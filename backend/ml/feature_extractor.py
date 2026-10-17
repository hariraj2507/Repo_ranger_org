"""Convert safe scanner artifacts into model-ready numeric features."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Mapping

from backend.ast.context_engine import CodeContext
from backend.detectors.finding import Finding, Severity, VALUE_SHAPE_FEATURES
from backend.validators.validation_result import ValidationResult


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """Named, normalized features used by the scoring classifier.

    Features derive from metadata, redacted findings, coarse token statistics,
    and validation outcomes. Raw credentials and source snippets never enter
    this layer.
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
        filename = PurePosixPath(finding.file_path).name.lower()
        non_production = bool(path_parts & self._NON_PRODUCTION_PARTS or re.search(
            r'(^test_|_test[.]|[.](?:test|spec)[.]|[.](?:example|sample)$|^readme(?:[.]|$))', filename)
            or suffix in {'.md', '.rst'})
        values = {
            **{name: float(context is not None and name in context.evidence) for name in (
                'credential_name_context', 'password_name_context', 'token_name_context',
                'public_metadata_context', 'quoted_literal_context', 'credential_usage_context', 'xml_value_context',
                'mapping_literal_context', 'translation_map_context')},
            'localization_resource_context': float(bool(path_parts & {'locale', 'locales', 'lang', 'languages', 'i18n', 'l10n', 'translation', 'translations', 'messages'})),
            'php_source_file': float(suffix == '.php'),
            'auth_response_structure': float(finding.rule_id == 'ntlm_authenticate'),
            'authorization_literal_signal': float(finding.rule_id == 'authorization_literal'),
            'password_literal_signal': float(finding.rule_id == 'hardcoded_password'),
            'private_key_structure': float(finding.rule_id == 'private_jwk' or finding.category == 'private_key'),
            'configuration_file': float(filename == '.env' or filename.startswith('.env.') or
                                        suffix in {'.env', '.ini', '.properties', '.yaml', '.yml', '.toml', '.json', '.conf', '.xml'}),
            'documentation_file': float(suffix in {'.md', '.rst', '.txt', '.html'} or filename.startswith('readme')),
            'reference_context': float(context is not None and 'reference_context' in context.evidence and finding.detector != 'regex'),
            'test_value_context': float(context is not None and 'test_value_context' in context.evidence and finding.detector != 'regex'),
            'test_context': float(context is not None and 'test_context' in context.evidence and not non_production),
            "jwt_structure": float(finding.rule_id == "jwt"),
            'public_identifier_context': float(context is not None and 'public_identifier_context' in context.evidence and finding.detector != 'regex'),
            'placeholder_context': float(context is not None and 'placeholder_context' in context.evidence and finding.detector != 'regex'),
            'comment_context': float(context is not None and 'comment_context' in context.evidence),
            "severity": self._SEVERITY[finding.severity],
            "known_signature": 1.0 if finding.detector == "regex" and finding.rule_id != "jwt" else 0.0,
            "custom_signature": 1.0 if finding.detector == "custom" else 0.0,
            "validator_invalid": 1.0 if validation is not None and not validation.is_valid else 0.0,
            "entropy_signal": 1.0 if finding.detector == "entropy" else 0.0,
            "validator_valid": 1.0 if validation is not None and validation.is_valid and finding.rule_id != "jwt" else 0.0,
            "validator_present": 1.0 if validation is not None else 0.0,
            "non_production_path": float(non_production),
            "source_code_file": 1.0 if suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".rs", '.php'} else 0.0,
            "assignment_context": 1.0 if context is not None and context.symbol_kind == "assignment" else 0.0,
            "parsed_context": 1.0 if context is not None and context.symbol_kind not in {"unknown", "unparsed", "line"} else 0.0,
        }
        shape = finding.value_shape or ()
        values.update((name, shape[index] if index < len(shape) else 0.0)
                      for index, name in enumerate(VALUE_SHAPE_FEATURES))
        return FeatureVector(values)
