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
    """Transparent heuristic or validated trained model for candidate triage.

    Direct construction preserves the heuristic used as the comparison baseline.
    Normal scans use default(), which loads the bundled guarded trained ensemble.
    """

    _GUARD_VETO_FEATURES = (
        'public_identifier_context', 'placeholder_context', 'reference_context',
        'test_context', 'test_value_context', 'non_production_path',
    )
    PROMOTION_POLICY = 'baseline_floor_and_context_veto_v1'

    _DEFAULT_WEIGHTS: Mapping[str, float] = {
        "bias": -1.15,
        "test_context": -1.0,
        "test_value_context": -0.7,
        "reference_context": -1.2,
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

    def __init__(self, weights: Mapping[str, float] | None = None, promotion_threshold: float | None = None, feature_transform: str | None = None, trees=None, existing_alerts_only=False) -> None:
        self._weights = dict(self._DEFAULT_WEIGHTS if weights is None else weights)
        if promotion_threshold is not None and (type(promotion_threshold) not in (int, float) or not .5 <= promotion_threshold <= 1):
            raise ValueError("Promotion threshold must be a finite number between .5 and 1")
        self._promotion_threshold = promotion_threshold
        if feature_transform not in (None, 'pairwise_v1'):
            raise ValueError('Unsupported feature transform')
        self._feature_transform = feature_transform
        self._trees = trees
        self._existing_alerts_only = existing_alerts_only
        if trees is not None:
            from .tree_model import validate_ensemble
            validate_ensemble(trees)

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
        if not isinstance(model, dict) or (model.get("schema_version"), model.get("kind")) not in ((1, "logistic"), (2, "guarded_logistic"), (3, "interaction_logistic"), (4, "boosted_trees")):
            raise ValueError("Unsupported model schema")
        from .training import FEATURES
        transform = model.get('feature_transform') if model['schema_version'] == 3 else None
        if model['schema_version'] == 3 and transform != 'pairwise_v1':
            raise ValueError('Unsupported feature transform')
        from .interactions import interaction_names
        allowed = FEATURES | interaction_names(FEATURES) if transform else FEATURES
        weights = model.get("weights")
        if not isinstance(weights, dict) or "bias" not in weights or set(weights) - (allowed | {"bias"}):
            raise ValueError("Invalid model feature weights")
        if any(type(v) not in (int,float) or not math.isfinite(v) or abs(v)>100 for v in weights.values()):
            raise ValueError("Model weights must be finite numbers between -100 and 100")
        threshold = model.get('promotion_threshold') if model['schema_version'] in (2,4) else None
        if model['schema_version'] == 2 and threshold is None:
            raise ValueError('Guarded model requires a promotion threshold')
        if model['schema_version'] == 2 and model.get('promotion_policy') != cls.PROMOTION_POLICY:
            raise ValueError('Unsupported guarded promotion policy')
        trees = model.get('trees') if model['schema_version'] == 4 else None
        if model['schema_version'] == 4:
            if set(weights) != {'bias'} or trees is None:
                raise ValueError('Invalid tree model weights')
            if threshold is not None and model.get('promotion_policy') != 'existing_alerts_only_v1':
                raise ValueError('Unsupported tree promotion policy')
            if model.get('promotion_policy') is not None and threshold is None:
                raise ValueError('Tree promotion policy requires a threshold')
        return cls(weights, promotion_threshold=threshold, feature_transform=transform, trees=trees,
                   existing_alerts_only=model.get('promotion_policy') == 'existing_alerts_only_v1')

    @classmethod
    def default(cls):
        """Use the bundled trained model with conservative baseline safeguards."""
        return cls.from_file(Path(__file__).with_name('data') / 'default.json')

    def model_identity(self):
        """Include runtime policy and trees when identifying comparable reports."""
        return {'weights': self._weights, 'trees': self._trees,
                'feature_transform': self._feature_transform,
                'promotion_threshold': self._promotion_threshold,
                'existing_alerts_only': self._existing_alerts_only}

    def classify(self, features: FeatureVector) -> Classification:
        """Classify an extracted feature vector using a stable logistic function."""
        raw_score = self._weights.get("bias", 0.0)
        contributors: list[str] = []
        values = features.values
        if self._trees is not None:
            from .tree_model import leaf_value
            raw_score += sum(leaf_value(tree, values) for tree in self._trees)
            contributors.append('ml_tree_evidence')
        if self._feature_transform:
            from .interactions import expand_features
            values = expand_features(values)
        for name, value in values.items():
            contribution = self._weights.get(name, 0.0) * value
            raw_score += contribution
            if abs(contribution) >= 0.10:
                contributors.append(name)
        if raw_score >= 0:
            score = 1.0 / (1.0 + math.exp(-raw_score))
        else:
            exp_score = math.exp(raw_score)
            score = exp_score / (1.0 + exp_score)
        if self._promotion_threshold is not None:
            baseline = CandidateClassifier().classify(features)
            if (self._promotion_threshold == 1.0 or score < self._promotion_threshold
                    or score <= baseline.score
                    or (self._existing_alerts_only and baseline.score < .5)
                    or any(features.values.get(name, 0) for name in self._GUARD_VETO_FEATURES)):
                return baseline
            if self._existing_alerts_only:
                # Refine ranking inside existing classifier and risk bands,
                # including the historical exposure increment used by RiskEngine.
                from .confidence_engine import ConfidenceEngine
                confidence = ConfidenceEngine().assess(baseline, features).score
                risk = .45 * features.value('severity') + .55 * confidence
                if confidence < 1:
                    margins = [bound - risk - exposure for exposure in (0., .08)
                               for bound in (.4, .65, .85) if bound > risk + exposure]
                    if features.value('severity') == 1 and confidence < .65:
                        margins.append(.55 * (.65 - confidence))
                    if margins:
                        score = min(score, baseline.score + max(0., min(margins) / .55 - 1e-10))
                if baseline.score < .75:
                    score = min(score, .75 - 1e-10)
                if score <= baseline.score:
                    return baseline
            contributors.append('ml_priority_promotion')
        if score >= 0.75:
            label = ClassificationLabel.LIKELY_SECRET
        elif score >= 0.45:
            label = ClassificationLabel.POSSIBLE_SECRET
        else:
            label = ClassificationLabel.UNLIKELY_SECRET
        return Classification(label, score, tuple(sorted(contributors)))
