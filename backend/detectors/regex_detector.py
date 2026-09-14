"""High-confidence, registry-driven regex secret detection."""
from __future__ import annotations

from .candidate import DetectionCandidate
from .finding import Finding
from .pattern_registry import PatternRegistry, default_pattern_registry
from backend.scanner.models import NormalizedTextFile


class RegexDetector:
    """Find known credential formats in one normalized text file."""

    def __init__(self, registry: PatternRegistry | None = None) -> None:
        self._registry = registry or default_pattern_registry()

    def detect(self, text_file: NormalizedTextFile) -> tuple[Finding, ...]:
        """Return redacted findings for every configured rule match."""
        return tuple(candidate.to_finding() for candidate in self.detect_candidates(text_file))

    def detect_candidates(self, text_file: NormalizedTextFile) -> tuple[DetectionCandidate, ...]:
        """Return ephemeral candidates for immediate in-process validation only."""
        candidates: list[DetectionCandidate] = []
        text = text_file.text
        for pattern in self._registry.patterns():
            compiled = pattern.compile()
            for match in compiled.finditer(text):
                line_start = text.count("\n", 0, match.start()) + 1
                line_end = text.count("\n", 0, match.end()) + 1
                candidates.append(DetectionCandidate(
                    detector="custom" if pattern.custom else "regex", rule_id=pattern.rule_id, category=pattern.category,
                    severity=pattern.severity, file_path=text_file.metadata.relative_path,
                    line_start=line_start, line_end=line_end, matched_value=match.group(0),
                ))
        return tuple(candidates)
