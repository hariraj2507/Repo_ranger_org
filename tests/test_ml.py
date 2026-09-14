"""Tests for transparent Day 5 candidate scoring."""
import unittest

from backend.ast.context_engine import CodeContext
from backend.detectors.finding import Finding, Severity
from backend.ml import CandidateClassifier, ClassificationLabel, ConfidenceEngine, ConfidenceLevel, FeatureExtractor
from backend.validators.validation_result import ValidationResult


def finding(path: str, detector: str = "regex", severity: Severity = Severity.HIGH) -> Finding:
    """Build a safe finding fixture."""
    return Finding.from_match(
        detector=detector, rule_id="aws_access_key_id", category="cloud_credential", severity=severity,
        file_path=path, line_start=4, line_end=4, matched_value="AKIAIOSFODNN7EXAMPLE",
    )


class MlTests(unittest.TestCase):
    def test_validated_signature_in_production_code_is_likely_secret(self) -> None:
        vector = FeatureExtractor().extract(
            finding("src/client.py"), ValidationResult("aws", True),
            CodeContext("python", "api_key", "assignment", 4, 4, ("Client",)),
        )
        classification = CandidateClassifier().classify(vector)
        confidence = ConfidenceEngine().assess(classification, vector)
        self.assertEqual(classification.label, ClassificationLabel.LIKELY_SECRET)
        self.assertEqual(confidence.level, ConfidenceLevel.HIGH)
        self.assertIn("provider-format validation passed", confidence.rationale)

    def test_test_fixture_receives_a_confidence_penalty(self) -> None:
        extractor = FeatureExtractor()
        production = extractor.extract(finding("src/client.py"), ValidationResult("aws", True))
        fixture = extractor.extract(finding("tests/fixtures/keys.py"), ValidationResult("aws", True))
        classifier = CandidateClassifier()
        production_score = ConfidenceEngine().assess(classifier.classify(production), production).score
        fixture_score = ConfidenceEngine().assess(classifier.classify(fixture), fixture).score
        self.assertLess(fixture_score, production_score)

    def test_feature_vector_contains_no_secret_value(self) -> None:
        vector = FeatureExtractor().extract(finding("app.py"))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(vector.values))
