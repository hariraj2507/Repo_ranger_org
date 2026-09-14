"""Convert confidence and severity signals into explainable finding risk."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from backend.ast.context_engine import CodeContext
from backend.validators.validation_result import ValidationResult

from backend.detectors.finding import Finding, Severity
from backend.history.models import HistoricalSource
from backend.ml.confidence_engine import ConfidenceResult


class RiskLevel(str, Enum):
    """Prioritization level for remediation decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """A safe risk decision for one finding and its optional Git provenance."""

    finding: Finding
    confidence: ConfidenceResult
    level: RiskLevel
    score: float
    rationale: tuple[str, ...]
    historical_source: HistoricalSource | None = None
    validation: ValidationResult | None = None
    context: CodeContext | None = None


class RiskEngine:
    """Apply a documented, deterministic risk policy to a finding."""

    _SEVERITY_WEIGHT = {
        Severity.LOW: 0.25,
        Severity.MEDIUM: 0.50,
        Severity.HIGH: 0.75,
        Severity.CRITICAL: 1.00,
    }

    def assess(
        self,
        finding: Finding,
        confidence: ConfidenceResult,
        historical_source: HistoricalSource | None = None,
    ) -> RiskAssessment:
        """Return a risk score using severity, confidence, and history exposure."""
        score = (0.45 * self._SEVERITY_WEIGHT[finding.severity]) + (0.55 * confidence.score)
        rationale = [f"detector severity is {finding.severity.value}", f"confidence is {confidence.level.value}"]
        if historical_source is not None:
            score += 0.08
            rationale.append(f"also exposed through {historical_source.source_kind}")
        score = min(1.0, score)
        if score >= 0.85 or (finding.severity is Severity.CRITICAL and confidence.score >= 0.65):
            level = RiskLevel.CRITICAL
        elif score >= 0.65:
            level = RiskLevel.HIGH
        elif score >= 0.40:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        return RiskAssessment(finding, confidence, level, score, tuple(rationale), historical_source)
