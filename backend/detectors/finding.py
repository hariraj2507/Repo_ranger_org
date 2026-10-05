"""Safe, immutable models for detector output."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum


VALUE_SHAPE_FEATURES = (
    "value_length_bin", "value_entropy_bin", "value_digit_ratio_bin",
    "value_uppercase_ratio_bin", "value_symbol_ratio_bin", "value_uuid_like",
    "value_hex_like", "value_base64_like",
    "value_length_detail_bin", "value_entropy_detail_bin",
    "value_digit_ratio_detail_bin", "value_uppercase_ratio_detail_bin",
    "value_symbol_ratio_detail_bin", "value_url_like", "value_path_like",
    "value_repeated_pattern",
)

_LEGACY_VALUE_SHAPE_FEATURE_COUNT = 8


def _value_shape(value: str) -> tuple[float, ...]:
    """Reduce an ephemeral value to quantized statistics, never token fragments.

    Length uses capped powers-of-two bins, entropy uses whole-bit bins capped
    at eight bits, and character ratios use quarter-width bins. The additional
    detail bins use four-character lengths, half-bit entropy, and sixteenth-width
    ratios. Format flags describe syntax only; they do not assert that a token
    is a credential.
    """
    length = len(value)
    if not length:
        return (0.0,) * len(VALUE_SHAPE_FEATURES)
    counts = Counter(value)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    digit_count = sum(count for char, count in counts.items() if char.isdigit())
    uppercase_count = sum(count for char, count in counts.items() if char.isupper())
    symbol_count = sum(count for char, count in counts.items() if not char.isalnum())
    url_like = re.fullmatch(r"https?://[^\s/?#]+(?:[/?#][^\s]*)?", value, re.IGNORECASE) is not None
    path_like = not url_like and ("/" in value or "\\" in value)
    repeated_pattern = length >= 12 and any(
        length % size == 0 and length // size >= 3 and value == value[:size] * (length // size)
        for size in range(1, 9)
    )
    return (
        min(length.bit_length(), 12) / 12.0,
        min(int(entropy), 8) / 8.0,
        (4 * digit_count // length) / 4.0,
        (4 * uppercase_count // length) / 4.0,
        (4 * symbol_count // length) / 4.0,
        float(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value) is not None),
        float(length >= 16 and re.fullmatch(r"[0-9a-fA-F]+", value) is not None),
        float(length >= 16 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value) is not None),
        min(length // 4, 64) / 64.0,
        min(math.floor(entropy * 2), 16) / 16.0,
        (16 * digit_count // length) / 16.0,
        (16 * uppercase_count // length) / 16.0,
        (16 * symbol_count // length) / 16.0,
        float(url_like),
        float(path_like),
        float(repeated_pattern),
    )


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
    value_shape: tuple[float, ...] = ()

    def __post_init__(self) -> None:
        """Keep optional shape metadata immutable, numeric, and normalized."""
        if not isinstance(self.value_shape, tuple) or (
            self.value_shape and (
                len(self.value_shape) not in (_LEGACY_VALUE_SHAPE_FEATURE_COUNT, len(VALUE_SHAPE_FEATURES))
                or any(type(value) not in (int, float) or not 0 <= value <= 1 for value in self.value_shape)
            )
        ):
            raise ValueError(
                f"value_shape must be an empty tuple, eight legacy numbers, or "
                f"{len(VALUE_SHAPE_FEATURES)} numbers in [0, 1]"
            )

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
            value_shape=_value_shape(matched_value),
        )


def redact(value: str) -> str:
    """Return a non-reversible, human-useful preview of a matched value."""
    if len(value) <= 16:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
