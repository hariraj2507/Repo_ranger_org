"""Provider-neutral output for offline credential validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """The outcome of a local structural validation operation.

    ``is_valid`` only means the candidate meets documented format requirements.
    It never asserts that a token is active, authorized, or safe to use.
    ``details`` is deliberately limited to non-secret metadata.
    """

    provider: str
    is_valid: bool
    reasons: tuple[str, ...] = ()
    details: Mapping[str, str | int | bool] = field(default_factory=dict)
