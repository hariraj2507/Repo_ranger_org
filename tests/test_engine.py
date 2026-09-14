"""Tests for Day 7 risk, report, and GitHub Actions output."""
import unittest

from backend.detectors.finding import Finding, Severity
from backend.engine import GitHubAction, ReportGenerator, RiskEngine, RiskLevel, ScoreEngine
from backend.ml.confidence_engine import ConfidenceLevel, ConfidenceResult


def assessment(severity: Severity = Severity.HIGH, confidence: float = 0.9):
    """Create a safe finding assessment fixture."""
    finding = Finding.from_match(
        detector="regex", rule_id="aws_access_key_id", category="cloud_credential", severity=severity,
        file_path="src/config.py", line_start=7, line_end=7, matched_value="AKIAIOSFODNN7EXAMPLE",
    )
    level = ConfidenceLevel.HIGH if confidence >= 0.8 else ConfidenceLevel.MEDIUM
    return RiskEngine().assess(finding, ConfidenceResult(confidence, level, ()))


class EngineTests(unittest.TestCase):
    def test_risk_engine_combines_high_severity_and_confidence(self) -> None:
        result = assessment()
        self.assertEqual(result.level, RiskLevel.HIGH)
        self.assertGreater(result.score, 0.65)

    def test_report_generator_excludes_raw_secret(self) -> None:
        item = assessment()
        score = ScoreEngine().calculate((item,))
        report = ReportGenerator().as_json("demo", score, (item,))
        self.assertIn("AKIA...MPLE", report)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", report)

    def test_github_action_fails_policy_and_escapes_file_path(self) -> None:
        item = assessment()
        unsafe_finding = Finding(
            item.finding.detector, item.finding.rule_id, item.finding.category, item.finding.severity,
            "src/a,b.py", item.finding.line_start, item.finding.line_end, item.finding.preview, item.finding.fingerprint,
        )
        unsafe_item = RiskEngine().assess(unsafe_finding, item.confidence)
        score = ScoreEngine().calculate((unsafe_item,))
        result = GitHubAction().render(score, (unsafe_item,))
        self.assertTrue(result.should_fail)
        self.assertIn("file=src/a%2Cb.py", result.annotations[0])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result.annotations[0])
