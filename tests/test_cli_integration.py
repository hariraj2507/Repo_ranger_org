"""CLI integration tests against real, isolated Git repositories."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from backend.application.cli import main
from backend.application.scan_orchestrator import ScanOrchestrator
from backend.scanner.repo_cloner import RepositoryCloner


class CliIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="reporanger-test-", ignore_cleanup_errors=True)
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.git("init")
        self.git("config", "user.name", "RepoRanger Test")
        self.git("config", "user.email", "test@example.invalid")
        self.secret = "AKIA" + "IOSFODNN7EXAMPLE"
        (self.root / "config.py").write_text(f"access_key = '{self.secret}'\n")
        self.git("add", "config.py")
        self.git("commit", "-m", "Add synthetic credential")
        self.first = self.git("rev-parse", "HEAD").strip()
        (self.root / "config.py").write_text("enabled = True\n")
        self.git("add", "config.py")
        self.git("commit", "-m", "Remove synthetic credential")

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments], check=True,
                              capture_output=True, text=True, timeout=30).stdout

    def run_cli(self, *arguments):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main([str(self.root), *arguments])
        self.assertNotIn(self.secret, output.getvalue() + error.getvalue())
        return code, output.getvalue(), error.getvalue()

    def test_history_finds_deleted_secret_with_provenance(self):
        code, output, _ = self.run_cli("--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["summary"]["finding_count"], 0)
        code, output, _ = self.run_cli("--history", "--format", "json", "--fail-on", "high")
        report = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(report["findings"][0]["history"]["commit_id"], self.first)
        self.assertEqual(report["scan"]["history"]["commit_history"]["commits_scanned"], 2)

    def test_history_limit_is_reported_and_fails_closed_in_ci(self):
        code, output, error = self.run_cli("--history", "--max-commits", "1", "--format", "json", "--fail-on", "high")
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(output)["scan"]["history"]["commit_history"]["truncated"])
        self.assertIn("incomplete", error)

    def test_reflog_recovers_unreachable_commit_and_deduplicates(self):
        # Move the branch to a new root so the credential commit survives only in reflog.
        self.git("checkout", "--orphan", "clean")
        self.git("add", "config.py")
        self.git("commit", "-m", "Clean root")
        branches = self.git("for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines()
        for branch in branches:
            if branch != "clean":
                self.git("branch", "-D", branch)
        code, output, _ = self.run_cli("--history", "--reflog", "--format", "json")
        findings = json.loads(output)["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["history"]["source_kind"], "reflog")
        code, output, _ = self.run_cli("--reflog", "--max-commits", "1", "--format", "json")
        self.assertTrue(json.loads(output)["scan"]["history"]["reflog"]["truncated"])

    def test_markdown_and_github_include_historical_location(self):
        for format_name in ("markdown", "github"):
            code, output, _ = self.run_cli("--history", "--format", format_name)
            self.assertEqual(code, 0)
            self.assertIn(self.first[:12], output)
        self.assertNotIn("file=config.py", output)

    def test_clean_policy_and_scan_error_exit_codes(self):
        self.assertEqual(self.run_cli("--fail-on", "low")[0], 0)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root / "missing")]), 2)
            with self.assertRaises(SystemExit) as error:
                main([str(self.root), "--max-commits", "0"])
            self.assertEqual(error.exception.code, 2)

    def test_remote_history_uses_full_clone_and_preserves_source(self):
        url = "https://github.com/example/demo.git"
        with patch("backend.application.scan_orchestrator.RepositoryCloner") as cloner:
            cloner.return_value.clone.return_value = self.root
            result = ScanOrchestrator().scan(url, history=True)
            self.assertFalse(cloner.return_value.clone.call_args.kwargs["shallow"])
            self.assertEqual(result.source, url)
            self.assertGreater(result.finding_count, 0)
        with self.assertRaisesRegex(ValueError, "local"):
            ScanOrchestrator().scan(url, reflog=True)

    def test_clone_command_supports_full_history(self):
        def runner(command, **kwargs):
            self.assertNotIn("--depth", command)
            return subprocess.CompletedProcess(command, 0, "", "")
        RepositoryCloner(runner=runner).clone("https://github.com/example/demo.git", self.root / "clone", shallow=False)

    def test_expected_binary_skips_do_not_fail_ci(self):
        (self.root / "image.bin").write_bytes(b"\x00\x01\x02")
        (self.root / "empty.txt").write_text("")
        self.git("add", ".")
        self.git("commit", "-m", "Add non-text files")
        code, output, _ = self.run_cli("--history", "--format", "json", "--fail-on", "critical")
        stats = json.loads(output)["scan"]["history"]["commit_history"]
        self.assertGreaterEqual(stats["blobs_skipped"], 2)
        self.assertFalse(stats["incomplete"])
        self.assertNotEqual(code, 2)

    def test_oversized_history_blob_fails_ci_with_coverage_gap(self):
        (self.root / "large.txt").write_text("a" * 2_000_001)
        self.git("add", ".")
        self.git("commit", "-m", "Add oversized blob")
        code, output, _ = self.run_cli("--history", "--format", "json", "--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(output)["scan"]["history"]["commit_history"]["incomplete"])

    def test_policy_applies_to_history_and_reflog(self):
        code, output, _ = self.run_cli('--history', '--reflog', '--exclude', 'config.py', '--format', 'json', '--fail-on', 'low')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['summary']['finding_count'], 0)
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps({'disabled_rules': ['aws_access_key_id']}))
        code, output, error = self.run_cli('--history', '--reflog', '--config', str(policy), '--format', 'json', '--fail-on', 'low')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['scan']['suppressed_findings'], 1)
        self.assertIn('suppressed', error)

    def test_shallow_clone_is_reported_as_incomplete(self):
        clone = self.root / 'shallow-copy'
        subprocess.run(['git', 'clone', '--depth', '1', '--', self.root.as_uri(), str(clone)],
                       capture_output=True, check=True, timeout=30)
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main([str(clone), '--history', '--format', 'json', '--fail-on', 'high'])
        self.assertEqual(code, 2)
        stats = json.loads(output.getvalue())['scan']['history']['commit_history']
        self.assertTrue(stats['shallow'])
        self.assertTrue(stats['incomplete'])
        self.assertIn('git fetch --unshallow', error.getvalue())

    def test_historical_validation_and_context_are_reported(self):
        code, output, _ = self.run_cli('--history', '--format', 'json')
        finding = json.loads(output)['findings'][0]
        self.assertTrue(finding['validation']['format_valid'])
        self.assertFalse(finding['validation']['live_verified'])
        self.assertEqual(finding['context']['language'], 'python')
        self.assertEqual(finding['context']['symbol_kind'], 'assignment')
        self.assertEqual(finding['history']['commit_id'], self.first)

    def test_custom_rule_runs_on_deleted_historical_content(self):
        (self.root / 'company.py').write_text('key="acme_Ab3Def78"')
        self.git('add', 'company.py')
        self.git('commit', '-m', 'Add synthetic custom token')
        (self.root / 'company.py').write_text('enabled=True')
        self.git('add', 'company.py')
        self.git('commit', '-m', 'Remove custom token')
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps({'custom_rules':[{'rule_id':'company_key','prefix':'acme_','min_length':8,'max_length':16}]}))
        code, output, _ = self.run_cli('--history', '--config', str(policy), '--format', 'json')
        findings = [f for f in json.loads(output)['findings'] if f['rule_id']=='company_key']
        self.assertEqual(len(findings), 1)
        self.assertIn('history', findings[0])
        self.assertNotIn('acme_Ab3Def78', output)

    def test_historical_utf16_is_analyzed(self):
        (self.root / 'unicode.py').write_text(f'key="{self.secret}"\n', encoding='utf-16')
        self.git('add', 'unicode.py')
        self.git('commit', '-m', 'UTF16 synthetic credential')
        (self.root / 'unicode.py').write_text('enabled=True\n', encoding='utf-16')
        self.git('add', 'unicode.py')
        self.git('commit', '-m', 'Remove UTF16 credential')
        _, output, _ = self.run_cli('--history', '--format', 'json')
        findings=[f for f in json.loads(output)['findings'] if f['file_path']=='unicode.py']
        self.assertEqual(len(findings),1)
        self.assertTrue(findings[0]['validation']['format_valid'])
        self.assertEqual(findings[0]['context']['language'],'python')
