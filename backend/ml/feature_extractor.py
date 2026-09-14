"""Convert safe scanner artifacts into model-ready numeric features."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from backend.ast.context_engine import CodeContext
from backend.detectors.finding import Finding, Severity
from backend.validators.validation_result import ValidationResult


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """Named, normalized features used by the scoring classifier.

    Features intentionally derive only from metadata, redacted findings, and
    validation outcomes. Raw credentials and source snippets never enter this
    layer.
    """

    values: Mapping[str, float]

    def value(self, name: str) -> float:
        """Return a feature value, defaulting to zero for unknown features."""
        return self.values.get(name, 0.0)


class FeatureExtractor:
    """Create deterministic features from one finding and optional enrichment."""

    _SEVERITY = {
        Severity.LOW: 0.25,
        Severity.MEDIUM: 0.5,
        Severity.HIGH: 0.75,
        Severity.CRITICAL: 1.0,
    }
    _NON_PRODUCTION_PARTS = frozenset({"test", "tests", "fixture", "fixtures", "example", "examples", "sample", "samples", "docs", "documentation"})

    def extract(
        self,
        finding: Finding,
        validation: ValidationResult | None = None,
        context: CodeContext | None = None,
    ) -> FeatureVector:
        """Return a normalized vector suitable for scoring or future training."""
        path_parts = {part.lower() for part in PurePosixPath(finding.file_path).parts}
        suffix = PurePosixPath(finding.file_path).suffix.lower()
        values = {
            "severity": self._SEVERITY[finding.severity],
            "known_signature": 1.0 if finding.detector == "regex" else 0.0,
            "custom_signature": 1.0 if finding.detector == "custom" else 0.0,
            "validator_invalid": 1.0 if validation is not None and not validation.is_valid else 0.0,
            "entropy_signal": 1.0 if finding.detector == "entropy" else 0.0,
            "validator_valid": 1.0 if validation is not None and validation.is_valid else 0.0,
            "validator_present": 1.0 if validation is not None else 0.0,
            "non_production_path": 1.0 if path_parts & self._NON_PRODUCTION_PARTS else 0.0,
            "source_code_file": 1.0 if suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".rs"} else 0.0,
            "assignment_context": 1.0 if context is not None and context.symbol_kind == "assignment" else 0.0,
            "parsed_context": 1.0 if context is not None and context.symbol_kind not in {"unknown", "unparsed", "line"} else 0.0,
        }
        return FeatureVector(values)
