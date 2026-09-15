"""Safe, immutable models for detector output."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """A finding's triage priority."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    """A potential secret location without retaining the original secret.

    ``fingerprint`` supports stable deduplication and correlation. ``preview``
    keeps only a small redacted representation, so normal logs and future
    reports do not expose credential material.
    """

    detector: str
    rule_id: str
    category: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    preview: str
    fingerprint: str

    @classmethod
    def from_match(
        cls,
        *,
        detector: str,
        rule_id: str,
        category: str,
        severity: Severity,
        file_path: str,
        line_start: int,
        line_end: int,
        matched_value: str,
    ) -> "Finding":
        """Build a finding, hashing and redacting ``matched_value`` immediately."""
        digest = hashlib.sha256(matched_value.encode("utf-8")).hexdigest()
        return cls(
            detector=detector,
            rule_id=rule_id,
            category=category,
            severity=severity,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            preview=redact(matched_value),
            fingerprint=digest,
        )


def redact(value: str) -> str:
    """Return a non-reversible, human-useful preview of a matched value."""
    if len(value) <= 16:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
