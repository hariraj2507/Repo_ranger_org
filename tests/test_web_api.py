"""Local HTTP integration and boundary tests; no remote clones are performed."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from backend.web import create_server
from backend.web.service import (APIError, MAX_BODY_BYTES, ScanRequest, ScanStore,
                                 SourcePolicy, SubprocessScanRunner, hardened_environment)
from backend.web.worker import ConfinedWalker, scan_report
from backend.revisions import DETECTOR_REVISION, SCORING_REVISION


class WebAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory(prefix="reporanger-web-test-", dir=Path(__file__).resolve().parents[1])
        self.root = Path(self.workspace.name) / "allowed"
        self.root.mkdir()
        self.repo = self.root / "demo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("enabled = True\n", encoding="utf-8")
        self.server = create_server(self.root, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.host = f"127.0.0.1:{self.server.server_port}"
        self.origin = "http://" + self.host
        _, self.session, _ = self.request("GET", "/api/session")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server.store._thread.join(timeout=2)
        self.workspace.cleanup()

    def request(self, method: str, path: str, data: object = None, *, headers: dict[str, str] | None = None,
                raw: bytes | None = None, authorized: bool = True) -> tuple[int, object, dict[str, str]]:
        request_headers = {"Host": self.host}
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else b"")
        if method == "POST":
            request_headers.update({"Origin": self.origin, "Content-Type": "application/json",
                                    "Content-Length": str(len(body))})
            if authorized:
                request_headers["X-RepoRanger-Token"] = self.session["token"]
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            connection.putrequest(method, path, skip_host=True)
            for key, value in request_headers.items():
                if value:
                    connection.putheader(key, value)
            connection.endheaders(body)
            response = connection.getresponse()
            content = response.read()
            response_headers = dict(response.getheaders())
            if response_headers.get("Content-Type", "").startswith("application/json"):
                content = json.loads(content)
            return response.status, content, response_headers
        finally:
            connection.close()

    def wait_scan(self, identifier: str, *, timeout: float = 15) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, record, _ = self.request("GET", f"/api/scans/{identifier}")
            self.assertEqual(status, 200)
            if record["status"] in {"complete", "failed"}:
                return record
            time.sleep(0.02)
        self.fail("Local scan did not finish within the test deadline")

    def test_local_scan_report_download_and_default_guarded_ml(self) -> None:
        secret = "AKIA7N2P9Q4R6S8T1U3V"
        (self.repo / "app.py").write_text(f'access_key = "{secret}"\n', encoding="utf-8")
        status, created, _ = self.request("POST", "/api/scans", {"source": "demo"})
        self.assertEqual(status, 202)
        self.assertIn(created["status"], {"queued", "running"})
        self.assertNotIn("report", created)
        completed = self.wait_scan(created["id"])
        self.assertEqual(completed["status"], "complete", completed)
        report = completed["report"]
        self.assertGreater(report["summary"]["finding_count"], 0)
        self.assertEqual(report["scan"]["files_scanned"], 1)
        self.assertEqual(report["scan_profile"]["ml_policy"], "existing_alerts_only_v1")
        self.assertEqual(report["scan_profile"]["model_kind"], "trained_boosted_trees")
        self.assertEqual(report["scan_profile"]["detector_revision"], DETECTOR_REVISION)
        self.assertEqual(report["scan_profile"]["scoring_revision"], SCORING_REVISION)
        self.assertNotIn(secret, json.dumps(completed))
        status, download, headers = self.request("GET", f'/api/scans/{created["id"]}/report')
        self.assertEqual(status, 200)
        self.assertEqual(download, report)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertNotIn(secret, json.dumps(download))
        status, listing, _ = self.request("GET", "/api/scans")
        self.assertEqual(status, 200)
        self.assertEqual(listing["scans"][0]["summary"], report["summary"])
        self.assertNotIn("report", listing["scans"][0])

    def test_clean_scan_completes_without_findings(self) -> None:
        status, created, _ = self.request("POST", "/api/scans", {"source": str(self.repo)})
        self.assertEqual(status, 202)
        completed = self.wait_scan(created["id"])
        self.assertEqual(completed["status"], "complete", completed)
        self.assertEqual(completed["report"]["summary"]["finding_count"], 0)
        self.assertFalse(completed["report"]["scan"]["incomplete"])

    def test_loopback_binding_session_cache_and_browser_security_headers(self) -> None:
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, session, headers = self.request("GET", "/api/session", headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)
        self.assertEqual(session["token"], self.session["token"])
        self.assertEqual(session["allowed_root"], str(self.root.resolve()))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_foreign_origin_rebinding_host_and_fetch_metadata_are_denied(self) -> None:
        for headers in ({"Origin": "https://example.com"}, {"Origin": "null"},
                        {"Host": "attacker.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                status, result, _ = self.request("GET", "/api/session", headers=headers)
                self.assertEqual(status, 403)
                self.assertNotIn("token", result)
        status, _, _ = self.request("POST", "/api/scans", {"source": "demo"}, headers={"Origin": ""})
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/scans", {"source": "demo"}, headers={"Origin": "https://example.com"})
        self.assertEqual(status, 403)

    def test_missing_and_incorrect_csrf_token_are_denied(self) -> None:
        for token in (None, "wrong-token"):
            status, result, _ = self.request("POST", "/api/scans", {"source": "demo"},
                                             authorized=False, headers={} if token is None else {"X-RepoRanger-Token": token})
            self.assertEqual(status, 403)
            self.assertEqual(result["error"]["code"], "invalid_token")
        self.assertEqual(self.server.store.list(), [])

    def test_request_limit_bad_json_content_type_and_config_injection(self) -> None:
        status, result, _ = self.request("POST", "/api/scans", raw=b" " * (MAX_BODY_BYTES + 1))
        self.assertEqual(status, 413)
        self.assertEqual(result["error"]["code"], "body_too_large")
        for raw in (b"{", b"\xff", b"[]", b"null"):
            self.assertEqual(self.request("POST", "/api/scans", raw=raw)[0], 400)
        self.assertEqual(self.request("POST", "/api/scans", {"source": "demo"}, headers={"Content-Type": "text/plain"})[0], 415)
        for setting in ("config", "model", "exclude", "reflog"):
            self.assertEqual(self.request("POST", "/api/scans", {"source": "demo", setting: "untrusted"})[0], 400)

    def test_history_limit_types_and_bounds_are_enforced(self) -> None:
        for field, values in (("max_commits", (0, -1, 501, True, "1")),
                              ("max_blobs", (0, 10_001, False, 1.2)),
                              ("history", (1, "true", None))):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.request("POST", "/api/scans", {"source": "demo", field: value})[0], 400)

    def test_local_path_escape_missing_files_and_symlinks_are_denied(self) -> None:
        outside = Path(self.workspace.name) / "outside"
        outside.mkdir()
        for source in (str(outside), "../outside", "missing", str(self.repo / "app.py"), "\\\\server\\share"):
            with self.subTest(source=source):
                self.assertEqual(self.request("POST", "/api/scans", {"source": source})[0], 400)
        link = self.root / "link"
        try:
            link.symlink_to(self.repo, target_is_directory=True)
        except (OSError, NotImplementedError):
            # Test junction behavior on Windows without requiring symlink privileges.
            if os.name != "nt":
                self.skipTest("This host cannot create symbolic links")
            with patch("backend.web.service.is_link", side_effect=lambda path: path == self.repo):
                self.assertEqual(self.request("POST", "/api/scans", {"source": "demo"})[0], 400)
        else:
            self.assertEqual(self.request("POST", "/api/scans", {"source": "link"})[0], 400)

    def test_only_exact_public_github_urls_are_accepted(self) -> None:
        policy = self.server.store.policy
        for source in ("https://github.com/example/demo", "https://github.com/example/demo.git"):
            self.assertEqual(policy.validate(source), source)
        for source in ("http://github.com/a/b", "https://127.0.0.1/a/b", "https://localhost/a/b",
                       "https://github.com.evil.test/a/b", "https://user@github.com/a/b", "git@github.com:a/b",
                       "https://github.com:443/a/b", "https://github.com/a/b?token=secret",
                       "https://github.com/a/b#fragment", "https://github.com/a/../b", "https://github.com/a/%2e%2e",
                       "https://github.com/a/b/", "https://github.com/a/b\n--config"):
            with self.subTest(source=source):
                status, result, _ = self.request("POST", "/api/scans", {"source": source})
                self.assertEqual(status, 400)
                self.assertNotIn(source, json.dumps(result))

    def test_unknown_scan_static_path_traversal_and_wrong_methods(self) -> None:
        self.assertEqual(self.request("GET", "/api/scans/" + "0" * 32)[0], 404)
        for path in ("/../README.md", "/%2e%2e/README.md", "/api/session?token=sensitive", "/app.js/../README.md"):
            self.assertIn(self.request("GET", path)[0], {400, 404})
        self.assertEqual(self.request("DELETE", "/api/scans")[0], 405)

    def test_scan_errors_do_not_expose_exception_secrets(self) -> None:
        private_message = "secret-password-from-git-stderr"
        self.server.store._runner = lambda request: (_ for _ in ()).throw(RuntimeError(private_message))
        status, created, _ = self.request("POST", "/api/scans", {"source": "demo"})
        self.assertEqual(status, 202)
        completed = self.wait_scan(created["id"])
        self.assertEqual(completed["status"], "failed")
        self.assertNotIn(private_message, json.dumps(completed))
        self.assertEqual(self.request("GET", f'/api/scans/{created["id"]}/report')[0], 409)

    def test_queue_is_bounded_and_only_one_scan_runs_at_once(self) -> None:
        started, release = threading.Event(), threading.Event()
        active = 0
        maximum = 0

        def runner(request):
            nonlocal active, maximum
            active += 1
            maximum = max(active, maximum)
            started.set()
            release.wait(5)
            active -= 1
            return {"summary": {"finding_count": 0}}

        self.server.store._runner = runner
        first = self.request("POST", "/api/scans", {"source": "demo"})
        self.assertEqual(first[0], 202)
        self.assertTrue(started.wait(2))
        try:
            for _ in range(self.server.store.max_pending):
                self.assertEqual(self.request("POST", "/api/scans", {"source": "demo"})[0], 202)
            status, result, headers = self.request("POST", "/api/scans", {"source": "demo"})
            self.assertEqual(status, 429)
            self.assertEqual(result["error"]["code"], "queue_full")
            self.assertEqual(headers["Retry-After"], "5")
            self.assertEqual(maximum, 1)
        finally:
            release.set()
        self.wait_scan(first[1]["id"])

    def test_record_history_evicts_old_terminal_results(self) -> None:
        store = ScanStore(self.server.store.policy, lambda request: {"summary": {"finding_count": 0}}, max_records=2)
        identifiers = []
        try:
            for _ in range(3):
                created = store.submit({"source": "demo"})
                identifiers.append(created["id"])
                deadline = time.monotonic() + 2
                while store.get(created["id"])["status"] != "complete" and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(store.get(created["id"])["status"], "complete")
            self.assertEqual(len(store.list()), 2)
            with self.assertRaises(APIError) as error:
                store.get(identifiers[0])
            self.assertEqual(error.exception.status, 404)
            self.assertEqual(store.list()[0]["id"], identifiers[-1])
        finally:
            store.close()
            store._thread.join(timeout=2)

    def test_process_timeout_and_git_hardening_have_fixed_errors(self) -> None:
        runner = SubprocessScanRunner(self.root, timeout=1)
        with patch("backend.web.service.subprocess.Popen") as spawn, patch.object(runner, "_terminate") as terminate:
            spawn.return_value.communicate.side_effect = subprocess.TimeoutExpired("trusted-worker", 1)
            with self.assertRaises(APIError) as error:
                runner(ScanRequest(str(self.repo)))
            terminate.assert_called_once_with(spawn.return_value)
        self.assertEqual(error.exception.code, "scan_timeout")
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": "untrusted", "GIT_CONFIG_COUNT": "1", "GIT_ASKPASS": "untrusted"}):
            environment = hardened_environment()
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        settings = {environment[f"GIT_CONFIG_KEY_{index}"]: environment[f"GIT_CONFIG_VALUE_{index}"]
                    for index in range(int(environment["GIT_CONFIG_COUNT"]))}
        self.assertEqual(settings["credential.helper"], "")
        self.assertEqual(settings["http.followRedirects"], "false")
        self.assertEqual(settings["protocol.allow"], "never")

    def test_input_byte_budget_is_reported_as_incomplete(self) -> None:
        with patch("backend.web.worker.MAX_CURRENT_BYTES", 1):
            report = scan_report(ScanRequest(str(self.repo)), self.server.store.policy)
        self.assertTrue(report["scan"]["incomplete"])
        self.assertEqual(report["scan"]["files_scanned"], 0)
        self.assertTrue(any("budget" in warning for warning in report["scan"]["warnings"]))

    def test_nested_link_contents_are_not_followed(self) -> None:
        outside = Path(self.workspace.name) / "outside"
        outside.mkdir()
        (outside / "secret.py").write_text('access_key = "AKIA7N2P9Q4R6S8T1U3V"\n')
        link = self.repo / "external"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            # Exercise the same denial through a mocked junction marker when
            # Windows cannot create a real symlink without administrator rights.
            link.mkdir()
            (link / "secret.py").write_text('access_key = "AKIA7N2P9Q4R6S8T1U3V"\n')
            with patch("backend.web.worker.is_link", side_effect=lambda path: path == link):
                walker = ConfinedWalker()
                paths = list(walker.walk(self.repo))
            self.assertEqual([path.name for path in paths], ["app.py"])
            self.assertTrue(walker.warnings)
            return
        walker = ConfinedWalker()
        paths = list(walker.walk(self.repo))
        self.assertEqual([path.name for path in paths], ["app.py"])
        self.assertTrue(walker.warnings)

    def test_deleted_secret_in_git_history_is_scanned_with_bounded_profile(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is unavailable")
        secret = "AKIA7N2P9Q4R6S8T1U3V"
        def git(*arguments):
            subprocess.run(["git", "-C", str(self.repo), *arguments], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "RepoRanger test")
        (self.repo / "app.py").write_text(f'access_key = "{secret}"\n')
        git("add", "app.py")
        git("-c", "core.hooksPath=" + os.devnull, "commit", "-q", "-m", "Synthetic historical credential")
        (self.repo / "app.py").write_text("enabled = True\n")
        git("add", "app.py")
        git("-c", "core.hooksPath=" + os.devnull, "commit", "-q", "-m", "Remove synthetic credential")
        status, created, _ = self.request("POST", "/api/scans", {"source": "demo", "history": True, "max_commits": 1, "max_blobs": 1})
        self.assertEqual(status, 202)
        completed = self.wait_scan(created["id"])
        self.assertEqual(completed["status"], "complete", completed)
        self.assertTrue(completed["report"]["scan"]["incomplete"])
        status, created, _ = self.request("POST", "/api/scans", {"source": "demo", "history": True})
        self.assertEqual(status, 202)
        completed = self.wait_scan(created["id"])
        self.assertEqual(completed["status"], "complete", completed)
        report = completed["report"]
        self.assertEqual(report["scan"]["history"]["commit_history"]["commits_scanned"], 2)
        self.assertTrue(any("history" in finding for finding in report["findings"]))
        self.assertNotIn(secret, json.dumps(report))

    def test_linked_git_metadata_and_external_object_stores_are_denied(self) -> None:
        metadata = self.repo / ".git"
        metadata.write_text("gitdir: ../../outside-private-repo/.git\n")
        with self.assertRaises(ValueError):
            scan_report(ScanRequest(str(self.repo), history=True), self.server.store.policy)
        metadata.unlink()
        (metadata / "objects" / "info").mkdir(parents=True)
        alternates = metadata / "objects" / "info" / "alternates"
        alternates.write_text("../../../../outside-private-repo/.git/objects\n")
        with self.assertRaises(ValueError):
            scan_report(ScanRequest(str(self.repo), history=True), self.server.store.policy)
        alternates.unlink()
        with patch("backend.web.worker.is_link", side_effect=lambda path: path == metadata):
            with self.assertRaises(ValueError):
                scan_report(ScanRequest(str(self.repo), history=True), self.server.store.policy)


if __name__ == "__main__":
    unittest.main()
