"""Ephemeral detector candidates used only during in-process validation."""
from __future__ import annotations

from dataclasses import dataclass

from .finding import Finding, Severity


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    """A short-lived raw match which must never be returned or serialized."""

    detector: str
    rule_id: str
    category: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    matched_value: str

    def to_finding(self) -> Finding:
        """Convert to the safe, redacted finding contract."""
        return Finding.from_match(
            detector=self.detector, rule_id=self.rule_id, category=self.category,
            severity=self.severity, file_path=self.file_path,
            line_start=self.line_start, line_end=self.line_end,
            matched_value=self.matched_value,
        )
