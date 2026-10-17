"""Smoke-test an installed distribution, never the source checkout.

After installing the wheel or sdist, run this file by its absolute path from a
directory outside the checkout. Only synthetic credentials and local HTTP are
used; the dashboard scan runs its normal, separate worker process.
"""
from __future__ import annotations

import base64
import http.client
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


CHECKOUT = Path(__file__).resolve().parents[1]


def inside_checkout(path: Path) -> bool:
    try:
        path.resolve().relative_to(CHECKOUT)
    except ValueError:
        return False
    return True


def assert_installed_imports() -> None:
    for name, module in tuple(sys.modules.items()):
        if name == "backend" or name.startswith("backend."):
            location = getattr(module, "__file__", None)
            assert location and not inside_checkout(Path(location)), (
                f"{name} was imported from the checkout instead of the installed distribution"
            )


def write_fixture(directory: Path) -> tuple[tuple[str, ...], set[tuple[str, int, str]]]:
    """Cover the new auth formats with unique, entirely fabricated material."""
    basic_password, proxy_password = "riverstone", "duskwood"
    basic = base64.b64encode(f"admin:{basic_password}".encode()).decode()
    proxy = base64.b64encode(f"proxy:{proxy_password}".encode()).decode()
    bearer, proxy_bearer = "q7Lx9Aa2Vm3Kp8Nr", "t6Wp1Zy8Ns4Qv7Hm"
    attached, equal, quoted, proxy_user, configured = (
        "C8tK3uN4pR7v", "H5bR8mT3xV6p", "correct horse",
        "p4V9dN7k", "Z8mD2qF6nL5s",
    )
    ntlm_bytes = bytearray(64)
    ntlm_bytes[:8] = b"NTLMSSP\0"
    struct.pack_into("<I", ntlm_bytes, 8, 3)
    response = b"\x71" * 24
    struct.pack_into("<HHI", ntlm_bytes, 20, len(response), len(response), 64)
    struct.pack_into("<HHI", ntlm_bytes, 36, 4, 4, 64 + len(response))
    ntlm = base64.b64encode(ntlm_bytes + response + b"user").decode()
    lines = (
        f"Authorization: Basic {basic}",
        f"Proxy-Authorization: Basic {proxy}",
        f"Authorization: Bearer {bearer}",
        f"Proxy-Authorization: Bearer {proxy_bearer}",
        f"curl -uadmin:{attached} https://example.invalid",
        f"curl --user=admin:{equal} https://example.invalid",
        f'curl -U "admin:{quoted}" https://example.invalid',
        f"curl --proxy-user admin:{proxy_user} https://example.invalid",
        f"Authorization: NTLM {ntlm}",
    )
    directory.mkdir()
    (directory / "auth.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (directory / ".curlrc").write_text(f'user = "admin:{configured}"\n', encoding="utf-8")
    secrets = (basic_password, proxy_password, basic, proxy, bearer, proxy_bearer,
               attached, equal, quoted, proxy_user, configured, ntlm)
    expected = {("auth.txt", line, "authorization_literal") for line in range(1, 9)}
    expected.update({("auth.txt", 9, "ntlm_authenticate"), (".curlrc", 1, "authorization_literal")})
    return secrets, expected


def assert_redacted(content: str | bytes, secrets: tuple[str, ...], label: str) -> None:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    assert all(secret not in text for secret in secrets), f"{label} exposed synthetic credential material"


def assert_report(report: dict[str, Any], expected: set[tuple[str, int, str]]) -> None:
    from backend.revisions import DETECTOR_REVISION, SCORING_REVISION

    profile = report["scan_profile"]
    assert profile["model_kind"] == "trained_boosted_trees", "Bundled trained model was not used"
    assert profile["ml_policy"] == "existing_alerts_only_v1", "Default ML safeguard was not used"
    assert profile["detector_revision"] == DETECTOR_REVISION, "Detector revision differs from the installed backend"
    assert profile["scoring_revision"] == SCORING_REVISION, "Scoring revision differs from the installed backend"
    assert report["scan"]["files_scanned"] == 2, "Synthetic fixture files were not fully scanned"
    actual = {(finding["file_path"], finding["line_start"], finding["rule_id"])
              for finding in report["findings"]}
    missing = expected - actual
    assert not missing, f"Installed scan missed authentication formats: {sorted(missing)}"
    assert report["summary"]["finding_count"] >= len(expected), "Authentication findings were omitted"


class DashboardClient:
    def __init__(self, port: int) -> None:
        self.port = port
        self.host = f"127.0.0.1:{port}"
        self.origin = "http://" + self.host
        self.token: str | None = None

    def request(self, method: str, path: str, data: object = None, *,
                headers: dict[str, str | None] | None = None) -> tuple[int, Any, dict[str, str]]:
        body = json.dumps(data).encode("utf-8") if data is not None else b""
        request_headers: dict[str, str | None] = {"Host": self.host}
        if method == "POST":
            request_headers.update({"Origin": self.origin, "Content-Type": "application/json",
                                    "Content-Length": str(len(body)), "X-RepoRanger-Token": self.token})
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body=body,
                               headers={name: value for name, value in request_headers.items() if value is not None})
            response = connection.getresponse()
            content = response.read()
            response_headers = dict(response.getheaders())
            if response_headers.get("Content-Type", "").startswith("application/json"):
                content = json.loads(content)
            return response.status, content, response_headers
        finally:
            connection.close()

    def wait_scan(self, identifier: str) -> dict[str, Any]:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status, record, _ = self.request("GET", f"/api/scans/{identifier}")
            assert status == 200, "Scan status endpoint failed"
            if record["status"] in {"complete", "failed"}:
                assert record["status"] == "complete", f"Installed worker failed: {record.get('error', {}).get('code')}"
                return record
            time.sleep(0.05)
        raise AssertionError("Installed dashboard worker did not finish within 45 seconds")


def smoke_dashboard(root: Path, secrets: tuple[str, ...], expected: set[tuple[str, int, str]],
                    cli_report: dict[str, Any]) -> None:
    from backend.web import create_server

    server = create_server(root, port=0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    client = DashboardClient(server.server_port)
    try:
        for path, content_type in (("/", "text/html"), ("/app.js", "text/javascript"), ("/styles.css", "text/css")):
            status, asset, headers = client.request("GET", path)
            assert status == 200 and asset, f"Installed dashboard asset is unavailable: {path}"
            assert headers["Content-Type"].startswith(content_type), f"Incorrect dashboard asset type: {path}"
        status, session, headers = client.request("GET", "/api/session")
        assert status == 200 and session["token"], "Dashboard session endpoint failed"
        assert session["allowed_root"] == str(root.resolve()), "Dashboard allowed root is incorrect"
        assert headers["Cache-Control"] == "no-store", "Session token response must not be cached"
        client.token = session["token"]
        for override, code in (
            ({"X-RepoRanger-Token": None}, "invalid_token"),
            ({"X-RepoRanger-Token": "incorrect-smoke-token"}, "invalid_token"),
            ({"Origin": None}, "invalid_origin"),
            ({"Origin": "https://example.invalid"}, "invalid_origin"),
        ):
            status, denied, _ = client.request("POST", "/api/scans", {"source": "auth-fixture"}, headers=override)
            assert status == 403 and denied["error"]["code"] == code, "Unauthorized scan request was accepted"
        status, denied, _ = client.request("GET", "/api/session", headers={"Origin": "https://example.invalid"})
        assert status == 403 and "token" not in denied, "Foreign origin received a session token"
        status, listing, _ = client.request("GET", "/api/scans")
        assert status == 200 and listing["scans"] == [], "Denied requests started scan workers"

        status, created, _ = client.request("POST", "/api/scans", {"source": "auth-fixture"})
        assert status == 202 and created["status"] in {"queued", "running"}, "Authorized scan was not queued"
        assert "report" not in created, "Queued scan returned a premature report"
        completed = client.wait_scan(created["id"])
        assert_redacted(json.dumps(completed), secrets, "Dashboard scan response")
        report = completed["report"]
        assert_report(report, expected)
        assert not report["scan"]["incomplete"], "Synthetic scan has incomplete coverage"
        assert report["scan_profile"]["model_id"] == cli_report["scan_profile"]["model_id"], "CLI and dashboard loaded different models"
        status, download, headers = client.request("GET", f'/api/scans/{created["id"]}/report')
        assert status == 200 and download == report, "Report download differs from the completed scan"
        assert "attachment" in headers["Content-Disposition"], "Report download is not an attachment"
        assert_redacted(json.dumps(download), secrets, "Dashboard report download")
        status, listing, _ = client.request("GET", "/api/scans")
        assert status == 200 and len(listing["scans"]) == 1, "Completed scan is missing from the dashboard"
        assert "report" not in listing["scans"][0], "Scan listing returned the full report"
        assert_redacted(json.dumps(listing), secrets, "Dashboard scan listing")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        server.store._thread.join(timeout=5)
    assert not thread.is_alive() and not server.store._thread.is_alive(), "Dashboard threads did not stop"


def main() -> None:
    assert not inside_checkout(Path.cwd()), "Run installed_smoke.py from a directory outside the checkout"
    # Exclude the script's checkout even if the caller supplied it in PYTHONPATH.
    # Editable installs still resolve to source and are rejected by the assertion.
    sys.path[:] = [entry for entry in sys.path if not inside_checkout(Path(entry or Path.cwd()))]
    if "PYTHONPATH" in os.environ:
        os.environ["PYTHONPATH"] = os.pathsep.join(
            str(Path(entry).resolve()) for entry in os.environ["PYTHONPATH"].split(os.pathsep)
            if entry and not inside_checkout(Path(entry))
        )
    try:
        importlib.import_module("backend")
    except ImportError as error:
        raise AssertionError("Install the built wheel or sdist before running this smoke test") from error
    assert_installed_imports()
    from backend.ml.classifier import CandidateClassifier

    identity = CandidateClassifier.default().model_identity()
    assert isinstance(identity["trees"], list) and len(identity["trees"]) == 100, "Installed default model does not contain 100 learned trees"
    assert identity["existing_alerts_only"] is True, "Installed default model lacks the conservative ML policy"
    assert identity["promotion_threshold"] is not None, "Installed default model lacks its promotion guard"
    with tempfile.TemporaryDirectory(prefix="reporanger-installed-smoke-") as temporary:
        root = Path(temporary) / "allowed"
        root.mkdir()
        fixture = root / "auth-fixture"
        secrets, expected = write_fixture(fixture)
        cli = subprocess.run([sys.executable, "-m", "backend", str(fixture), "--format", "json"],
                             cwd=temporary, capture_output=True, text=True, encoding="utf-8", timeout=45)
        assert_redacted(cli.stdout + cli.stderr, secrets, "CLI output")
        assert cli.returncode == 0, f"Installed CLI failed with exit status {cli.returncode}"
        report = json.loads(cli.stdout)
        assert_report(report, expected)
        smoke_dashboard(root, secrets, expected, report)
    assert_installed_imports()
    print("Installed distribution smoke passed: trained model, auth detection, redaction, dashboard, and scan worker")


if __name__ == "__main__":
    main()
