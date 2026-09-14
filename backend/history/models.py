"""Safe domain models for findings discovered in Git history."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from backend.ast.context_engine import CodeContext
    from backend.validators.validation_result import ValidationResult

from backend.detectors.finding import Finding


@dataclass(frozen=True, slots=True)
class HistoricalSource:
    """The immutable Git object location from which a finding originated."""

    commit_id: str
    blob_id: str
    path: str
    source_kind: str


@dataclass(frozen=True, slots=True)
class HistoricalFinding:
    """A redacted finding together with its Git provenance."""

    finding: Finding
    source: HistoricalSource
    validation: ValidationResult | None = None
    context: CodeContext | None = None
