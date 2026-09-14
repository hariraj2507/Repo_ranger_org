"""Safe final output of a complete RepoRanger application scan."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from backend.engine.risk_engine import RiskAssessment
from backend.engine.score_engine import RepositoryScore


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Application-level scan result containing no source text or raw secrets."""

    source: str
    score: RepositoryScore
    assessments: tuple[RiskAssessment, ...]
    files_scanned: int
    skipped_files: Mapping[str, int]
    history: Mapping[str, Mapping[str, int | bool]] = field(default_factory=dict)

    suppressed_findings: int = 0

    @property
    def finding_count(self) -> int:
        """Return the number of assessed findings."""
        return len(self.assessments)
