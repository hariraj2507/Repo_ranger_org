"""Focused policy and detector-order regression checks."""
from datetime import datetime, timezone
import hashlib
import io
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from backend.application.cli import main
from backend.application.scan_orchestrator import ScanOrchestrator
from backend.config import ScanConfig, excluded_path
from backend.detectors.detection_engine import DetectionEngine
from backend.detectors.entropy_detector import EntropyDetector
from backend.detectors.regex_detector import RegexDetector
from backend.scanner.file_filter import FileFilter
from backend.scanner.parser import RepositoryParser
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


class PolicyTests(unittest.TestCase):
    def test_globs_are_relative_case_sensitive_and_cover_directories(self):
        self.assertTrue(excluded_path('fixtures/a/b.py', ('fixtures/',)))
        self.assertTrue(excluded_path('a.lock', ('**/*.lock',)))
        self.assertTrue(excluded_path('nested/a.lock', ('**/*.lock',)))
        self.assertFalse(excluded_path('src/a.py', ('fixtures/',)))
        self.assertFalse(excluded_path('Fixtures/a.py', ('fixtures/',)))

    def test_invalid_policy_is_rejected(self):
        for values in ({'exclude': 'src'}, {'disabled_rules': ['typo']}, {'suppress_fingerprints': ['raw-token']}, {'exclude': [3]}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ScanConfig(**values)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text('{"unknown": []}')
            with self.assertRaises(ValueError):
                ScanConfig.load(str(path))

    def test_excluded_file_is_not_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'skip.txt').write_text('sensitive text')
            extractor = Mock()
            result = RepositoryParser(file_filter=FileFilter(excluded_patterns=('skip.txt',)), extractor=extractor).parse(root)
            extractor.extract.assert_not_called()
            self.assertEqual(result.file_count, 0)
            self.assertEqual(result.metadata.skipped_files['excluded'], 1)

    def test_both_pipelines_prefer_signature_even_when_entropy_runs_first(self):
        token = 'ghp_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
        text = f"token='{token}'\nother='{token}'\n"
        repo = ParsedRepository(RepositoryMetadata('demo', 'demo'), (
            NormalizedTextFile(FileMetadata('config.py', len(text), datetime.now(timezone.utc), 'utf-8'), text),))
        detectors = (EntropyDetector(), RegexDetector())
        findings = DetectionEngine(detectors).scan(repo).findings
        parser = Mock()
        parser.parse.return_value = repo
        scanner = ScanOrchestrator(parser=parser)
        scanner._candidate_detectors = detectors
        results = scanner.scan('demo')
        self.assertEqual(len(findings), 2)
        self.assertEqual([f.rule_id for f in findings], ['github_token'] * 2)
        self.assertEqual([a.finding.rule_id for a in results.assessments], ['github_token'] * 2)

    def test_suppression_changes_score_and_is_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = 'AKIA' + 'IOSFODNN7EXAMPLE'
            (root / 'config.py').write_text(f"key='{token}'")
            for config in (ScanConfig(disabled_rules=('aws_access_key_id',)),
                           ScanConfig(suppress_fingerprints=(hashlib.sha256(token.encode()).hexdigest(),))):
                result = ScanOrchestrator(config=config).scan(root)
                self.assertEqual(result.finding_count, 0)
                self.assertEqual(result.score.score, 0)
                self.assertEqual(result.suppressed_findings, 1)

    def test_cli_combines_config_and_explicit_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('one.py', 'two.py'):
                (root / name).write_text("key='AKIAIOSFODNN7EXAMPLE'")
            policy = root / 'policy.json'
            policy.write_text(json.dumps({'exclude': ['one.py']}))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), '--config', str(policy), '--exclude', 'two.py', '--format', 'json', '--fail-on', 'low'])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())['scan']['skipped_files']['excluded'], 2)
