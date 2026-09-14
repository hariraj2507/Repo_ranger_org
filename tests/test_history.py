"""Unit tests for bounded Git history scanning without a real Git process."""
from pathlib import Path
import subprocess
import unittest

from backend.detectors.finding import Finding, Severity
from backend.history.blob_scanner import BlobScanResult
from backend.history.history_scanner import HistoryScanner
from backend.history.reflog_scanner import ReflogScanner


def completed(command, stdout=b"", stderr=b"", returncode=0):
    """Build a subprocess result suitable for injected Git runners."""
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class FakeBlobScanner:
    """Return a redacted finding from a fake blob without reading Git."""
    def scan(self, root, blob_id, path):
        finding = Finding.from_match(
            detector="regex", rule_id="test", category="test", severity=Severity.HIGH,
            file_path=path, line_start=1, line_end=1, matched_value="AKIAIOSFODNN7EXAMPLE",
        )
        return BlobScanResult((finding,))


class HistoryTests(unittest.TestCase):
    def test_history_scanner_deduplicates_blobs_and_preserves_provenance(self) -> None:
        def runner(command, **kwargs):
            if "--is-shallow-repository" in command:
                return completed(command, b"false\n")
            if "rev-parse" in command:
                return completed(command, b"true\n")
            if "rev-list" in command:
                return completed(command, b"commit-one\ncommit-two\n")
            if "ls-tree" in command:
                output = b"100644 blob blob-a\tconfig.py\0"
                return completed(command, output)
            raise AssertionError(command)
        result = HistoryScanner(FakeBlobScanner(), runner=runner).scan(Path.cwd())
        self.assertEqual(result.commits_scanned, 2)
        self.assertEqual(result.blobs_scanned, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source.commit_id, "commit-one")

    def test_reflog_scanner_passes_unique_commits_to_history_scanner(self) -> None:
        class FakeHistoryScanner:
            def scan(self, root, commits, source_kind):
                self.root, self.commits, self.source_kind = root, tuple(commits), source_kind
                return "result"
        fake = FakeHistoryScanner()
        def runner(command, **kwargs):
            return completed(command, b"a\na\nb\n")
        result = ReflogScanner(fake, runner=runner).scan(Path.cwd())
        self.assertEqual(result, "result")
        self.assertEqual(fake.commits, ("a", "b"))
        self.assertEqual(fake.source_kind, "reflog")

    def test_identical_blob_retains_distinct_paths_without_rescanning(self):
        from unittest.mock import Mock
        blob_scanner = Mock(wraps=FakeBlobScanner())
        def runner(command, **kwargs):
            if '--is-shallow-repository' in command:
                return completed(command, b'false\n')
            if 'rev-parse' in command:
                return completed(command, b'true\n')
            if 'rev-list' in command:
                return completed(command, b'new\nold\n')
            if 'ls-tree' in command:
                return completed(command, b'100644 blob same\tapp.py\0' if command[-1] == 'new'
                                 else b'100644 blob same\told.py\0')
            raise AssertionError(command)
        result = HistoryScanner(blob_scanner, runner=runner, max_blobs=1).scan(Path.cwd())
        self.assertEqual(blob_scanner.scan.call_count, 1)
        self.assertEqual(result.blobs_scanned, 1)
        self.assertFalse(result.truncated)
        self.assertEqual([(f.finding.file_path, f.source.path, f.source.commit_id) for f in result.findings],
                         [('app.py', 'app.py', 'new'), ('old.py', 'old.py', 'old')])
