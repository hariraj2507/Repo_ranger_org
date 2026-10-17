"""One analysis pipeline for working-tree text and historical blob text."""
from dataclasses import dataclass
from backend.detectors.authorization_detector import AuthorizationDetector
from backend.detectors.structured_detector import StructuredDetector
from backend.detectors.literal_password_detector import LiteralPasswordDetector

from backend.ast.context_engine import CodeContext, ContextEngine
from backend.detectors.deduplication import finding_identity, unique_detections
from backend.detectors.detection_engine import DetectionResult
from backend.detectors.finding import Finding
from backend.detectors.regex_detector import RegexDetector
from backend.detectors.entropy_detector import EntropyDetector
from backend.validators.router import ValidatorRouter
from backend.validators.validation_result import ValidationResult


@dataclass(frozen=True)
class AnalyzedFinding:
    finding: Finding
    validation: ValidationResult | None
    context: CodeContext


class FindingAnalyzer:
    def __init__(self, detectors=None, router=None, context_engine=None):
        self.detectors = detectors or (RegexDetector(), StructuredDetector(), AuthorizationDetector(), EntropyDetector(), LiteralPasswordDetector())
        self.router = router or ValidatorRouter()
        self.context_engine = context_engine or ContextEngine()

    def analyze(self, repository):
        findings, validations = [], {}
        for text_file in repository.files:
            candidates = unique_detections(
                (candidate for detector in self.detectors for candidate in detector.detect_candidates(text_file)),
                lambda candidate: candidate.to_finding())
            for candidate in candidates:
                finding = candidate.to_finding()
                findings.append(finding)
                validations[finding_identity(finding)] = self.router.validate(candidate)
        enriched = self.context_engine.enrich(DetectionResult(repository, tuple(findings)))
        return tuple(AnalyzedFinding(item.finding, validations[finding_identity(item.finding)], item.context)
                     for item in enriched.findings)
