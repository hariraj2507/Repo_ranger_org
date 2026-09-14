"""Report persistence and comparison behavior through the CLI."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from backend.application.cli import main
from backend.application.report_store import ReportStore


class ReportStoreTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.token = 'AKIA' + 'IOSFODNN7EXAMPLE'
        (self.repo / 'config.py').write_text(f"key='{self.token}'\n")

    def scan(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main([str(self.repo), '--format', 'json', *args])
        self.assertNotIn(self.token, output.getvalue() + error.getvalue())
        return code, output.getvalue(), error.getvalue()

    def test_save_compare_add_remove_and_line_shift(self):
        baseline = self.root / 'baseline.json'
        code, _, _ = self.scan('--save-report', str(baseline))
        self.assertEqual(code, 0)
        self.assertNotIn(self.token, baseline.read_text())
        (self.repo / 'config.py').write_text(f"# moved down\nkey='{self.token}'\n")
        code, output, _ = self.scan('--compare', str(baseline))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['comparison']['unchanged_count'], 1)
        (self.repo / 'config.py').write_text('enabled=True\n')
        (self.repo / 'new.py').write_text(f"key='{self.token}'\n")
        code, output, _ = self.scan('--compare', str(baseline))
        comparison = json.loads(output)['comparison']
        self.assertEqual(comparison['new_count'], 1)
        self.assertEqual(comparison['no_longer_detected_count'], 1)
        self.assertEqual(comparison['unchanged_count'], 0)

    def test_existing_snapshot_is_not_overwritten(self):
        baseline = self.root / 'baseline.json'
        self.scan('--save-report', str(baseline))
        original = baseline.read_bytes()
        code, _, error = self.scan('--save-report', str(baseline))
        self.assertEqual(code, 2)
        self.assertIn('new filename', error)
        self.assertEqual(baseline.read_bytes(), original)

    def test_incompatible_settings_are_rejected(self):
        baseline = self.root / 'baseline.json'
        self.scan('--save-report', str(baseline))
        code, _, error = self.scan('--compare', str(baseline), '--exclude', '*.py')
        self.assertEqual(code, 2)
        self.assertIn('settings differ', error)

    def test_repository_and_incomplete_history_are_rejected(self):
        _, output, _ = self.scan()
        report = json.loads(output)
        previous = copy.deepcopy(report)
        previous['repository_source'] = 'different'
        with self.assertRaisesRegex(ValueError, 'repository'):
            ReportStore.compare(report, previous)
        previous = copy.deepcopy(report)
        previous['scan']['history'] = {'commit_history': {'incomplete': True, 'truncated': False}}
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            ReportStore.compare(report, previous)

    def test_malformed_baseline_returns_controlled_error(self):
        baseline = self.root / 'baseline.json'
        for value in ('[]', '{broken', '{"schema_version": 99}'):
            baseline.write_text(value)
            code, _, _ = self.scan('--compare', str(baseline))
            self.assertEqual(code, 2)
        _, output, _ = self.scan()
        report = json.loads(output)
        report['findings'][0]['history'] = []
        baseline.write_text(json.dumps(report))
        code, _, error = self.scan('--compare', str(baseline))
        self.assertEqual(code, 2)
        self.assertIn('metadata', error)
