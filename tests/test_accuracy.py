"""Labeled precision/recall regression fixtures, not a production benchmark."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import unittest

from backend.detectors.detection_engine import DetectionEngine
from backend.detectors.entropy_detector import EntropyDetector
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


def make_file(source, path='config.py'):
    return NormalizedTextFile(FileMetadata(path, len(source), datetime.now(timezone.utc), 'utf-8'), source)


class AccuracyTests(unittest.TestCase):
    def test_labeled_positive_and_negative_examples(self):
        cases = json.loads((Path(__file__).parent / 'fixtures' / 'accuracy_cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['name']):
                repository = ParsedRepository(RepositoryMetadata('fixture', 'fixture'), (make_file(case['source'], case['path']),))
                result = DetectionEngine().scan(repository)
                self.assertEqual(bool(result.findings), case['expected'])

    def test_value_is_whole_and_does_not_include_assignment_name(self):
        token = 'q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB=='
        findings = EntropyDetector().detect(make_file(f'TOKEN={token}'))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fingerprint, hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, str(findings))

    def test_dotted_token_is_not_split_into_multiple_candidates(self):
        token = 'q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB.otherSegment123456.signature123456789'
        findings = EntropyDetector().detect(make_file(f'TOKEN="{token}"'))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].fingerprint, hashlib.sha256(token.encode()).hexdigest())

    def test_multiline_assignment_reports_value_line(self):
        findings = EntropyDetector().detect(make_file('apiKey =\n "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"'))
        self.assertEqual(findings[0].line_start, 2)

    def test_unquoted_exclamation_mark_is_retained(self):
        token = 'q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB!'
        finding = EntropyDetector().detect(make_file(f'PASSWORD={token}'))[0]
        self.assertEqual(finding.fingerprint, hashlib.sha256(token.encode()).hexdigest())
