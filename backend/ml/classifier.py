"""Explainable baseline classifier for secret-candidate triage."""
from __future__ import annotations

import math
import json
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .feature_extractor import FeatureVector


class ClassificationLabel(str, Enum):
    """Triage labels for a potential credential finding."""

    UNLIKELY_SECRET = "unlikely_secret"
    POSSIBLE_SECRET = "possible_secret"
    LIKELY_SECRET = "likely_secret"


@dataclass(frozen=True, slots=True)
class Classification:
    """A label, probability-like score, and safe scoring explanation."""

    label: ClassificationLabel
    score: float
    contributing_features: tuple[str, ...]


class CandidateClassifier:
    """A deterministic logistic baseline, ready to be replaced by a trained model.

    This is deliberately transparent rather than marketed as a trained ML model.
    The injected weights make calibrated training data an additive future step.
    """

    _DEFAULT_WEIGHTS: Mapping[str, float] = {
        "bias": -1.15,
        'public_identifier_context': -1.0,
        'placeholder_context': -1.2,
        'comment_context': -0.35,
        "severity": 1.10,
        "known_signature": 1.25,
        "custom_signature": 0.65,
        "validator_invalid": -1.0,
        "entropy_signal": 0.35,
        "validator_valid": 1.15,
        "assignment_context": 0.25,
        "parsed_context": 0.10,
        "source_code_file": 0.15,
        "non_production_path": -1.45,
    }

    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        self._weights = dict(self._DEFAULT_WEIGHTS if weights is None else weights)

    @classmethod
    def from_file(cls, path):
        try:
            with Path(path).open(encoding="utf-8") as source:
                text = source.read(1_000_001)
            if len(text) > 1_000_000:
                raise ValueError("Model file is too large")
            model = json.loads(text)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Cannot read JSON model") from exc
        if not isinstance(model, dict) or model.get("schema_version") != 1 or model.get("kind") != "logistic":
            raise ValueError("Unsupported model schema")
        from .training import FEATURES
        weights = model.get("weights")
        if not isinstance(weights, dict) or "bias" not in weights or set(weights) - (FEATURES | {"bias"}):
            raise ValueError("Invalid model feature weights")
        if any(type(v) not in (int,float) or not math.isfinite(v) or abs(v)>100 for v in weights.values()):
            raise ValueError("Model weights must be finite numbers between -100 and 100")
        return cls(weights)

    def classify(self, features: FeatureVector) -> Classification:
        """Classify an extracted feature vector using a stable logistic function."""
        raw_score = self._weights.get("bias", 0.0)
        contributors: list[str] = []
        for name, value in features.values.items():
            contribution = self._weights.get(name, 0.0) * value
            raw_score += contribution
            if abs(contribution) >= 0.10:
                contributors.append(name)
        if raw_score >= 0:
            score = 1.0 / (1.0 + math.exp(-raw_score))
        else:
            exp_score = math.exp(raw_score)
            score = exp_score / (1.0 + exp_score)
        if score >= 0.75:
            label = ClassificationLabel.LIKELY_SECRET
        elif score >= 0.45:
            label = ClassificationLabel.POSSIBLE_SECRET
        else:
            label = ClassificationLabel.UNLIKELY_SECRET
        return Classification(label, score, tuple(sorted(contributors)))
