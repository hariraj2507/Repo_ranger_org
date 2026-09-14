"""End-to-end application-layer tests using a parsed in-memory repository."""
from datetime import datetime, timezone
from unittest.mock import Mock
import unittest

from backend.application.scan_orchestrator import ScanOrchestrator
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


class ApplicationTests(unittest.TestCase):
    def test_orchestrator_validates_then_returns_only_safe_result(self) -> None:
        text = "def configure():\n    access_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        repository = ParsedRepository(
            RepositoryMetadata("demo", "demo"),
            (NormalizedTextFile(FileMetadata("src/config.py", len(text), datetime.now(timezone.utc), "utf-8"), text),),
        )
        parser = Mock()
        parser.parse.return_value = repository
        result = ScanOrchestrator(parser=parser).scan("demo")
        self.assertEqual(result.finding_count, 1)
        self.assertGreater(result.score.score, 0)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(result))
        self.assertEqual(result.assessments[0].finding.rule_id, "aws_access_key_id")
