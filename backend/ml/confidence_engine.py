"""Confidence calibration over transparent classification signals."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .classifier import Classification
from .feature_extractor import FeatureVector


class ConfidenceLevel(str, Enum):
    """Human-readable confidence bands for review prioritization."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ConfidenceResult:
    """Calibrated confidence with explicit positive and negative evidence."""

    score: float
    level: ConfidenceLevel
    rationale: tuple[str, ...]


class ConfidenceEngine:
    """Calibrate classification confidence without claiming credential validity."""

    def assess(self, classification: Classification, features: FeatureVector) -> ConfidenceResult:
        """Return a bounded confidence score and concise evidence rationale."""
        score = classification.score
        rationale: list[str] = []
        if features.value("jwt_structure"):
            rationale.append("JWT structure decoded; signature and credential secrecy are not verified")
        for signal, reason in (('public_identifier_context', 'field name suggests a public identifier; review required'),
                               ('placeholder_context', 'value has an explicit placeholder marker'),
                               ('comment_context', 'candidate is on a comment line')):
            if features.value(signal):
                rationale.append(reason)
        if features.value("validator_valid") == 1.0:
            score += 0.10
            rationale.append("provider-format validation passed")
        if features.value("known_signature") == 1.0:
            score += 0.05
            rationale.append("known credential signature matched")
        if features.value("non_production_path") == 1.0:
            score -= 0.20
            rationale.append("candidate is located in a test, example, or documentation path")
        if features.value("entropy_signal") == 1.0 and features.value("known_signature") == 0.0:
            rationale.append("score is based partly on entropy heuristic")
        score = min(1.0, max(0.0, score))
        if score >= 0.80:
            level = ConfidenceLevel.HIGH
        elif score >= 0.50:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW
        return ConfidenceResult(score, level, tuple(rationale))
