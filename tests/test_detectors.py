"""Unit tests for the Day 2 detection layer."""
from datetime import datetime, timezone
import unittest

from backend.detectors import DetectionEngine, Severity
from backend.detectors.entropy_detector import EntropyDetector
from backend.detectors.pattern_registry import PatternDefinition, PatternRegistry
from backend.detectors.regex_detector import RegexDetector
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


def repository_with(text: str, path: str = "settings.py") -> ParsedRepository:
    """Create a small parsed-repository fixture without filesystem I/O."""
    text_file = NormalizedTextFile(
        FileMetadata(path, len(text.encode()), datetime.now(timezone.utc), "utf-8"), text,
    )
    return ParsedRepository(RepositoryMetadata("test", "test"), (text_file,))


class DetectorTests(unittest.TestCase):
    def test_regex_detector_reports_redacted_aws_key_with_line_number(self) -> None:
        result = DetectionEngine(detectors=(RegexDetector(),)).scan(
            repository_with("name = 'demo'\nkey = 'AKIAIOSFODNN7EXAMPLE'\n")
        )
        self.assertEqual(result.finding_count, 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "aws_access_key_id")
        self.assertEqual(finding.line_start, 2)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertNotIn("IOSFODNN", finding.preview)
        self.assertEqual(len(finding.fingerprint), 64)

    def test_entropy_detector_flags_diverse_long_token(self) -> None:
        token = "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"
        result = DetectionEngine(detectors=(EntropyDetector(),)).scan(repository_with(f"token={token}"))
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].rule_id, "high_entropy_token")
        self.assertEqual(result.findings[0].severity, Severity.MEDIUM)

    def test_engine_suppresses_entropy_duplicate_of_regex_match(self) -> None:
        token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        result = DetectionEngine().scan(repository_with(f"token = '{token}'"))
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].rule_id, "github_token")

    def test_pattern_registry_rejects_duplicate_rule_ids(self) -> None:
        rule = PatternDefinition("test", "test", "x", Severity.LOW, "test")
        with self.assertRaises(ValueError):
            PatternRegistry((rule, rule))
