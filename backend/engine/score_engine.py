"""Aggregate individual risk assessments into a repository-level score."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping

from .risk_engine import RiskAssessment, RiskLevel


@dataclass(frozen=True, slots=True)
class RepositoryScore:
    """Bounded repository risk score with transparent counts."""

    score: int
    level: RiskLevel
    finding_count: int
    risk_counts: Mapping[RiskLevel, int]


class ScoreEngine:
    """Score a repository from its most serious exposure without escalating severity through duplicate volume."""

    def calculate(self, assessments: Iterable[RiskAssessment]) -> RepositoryScore:
        """Return a 0-100 score; a zero finding count produces low risk."""
        items = tuple(assessments)
        counts: Counter[RiskLevel] = Counter(item.level for item in items)
        if not items:
            return RepositoryScore(0, RiskLevel.LOW, 0, dict(counts))
        # Repository risk reflects the most serious individual finding. Repeated
        # low-confidence candidates cannot alone promote the repository to high risk.
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        strongest = max(items, key=lambda item: (order[item.level], item.score))
        level = strongest.level
        lower, upper = {RiskLevel.LOW: (0, 39), RiskLevel.MEDIUM: (40, 64),
                        RiskLevel.HIGH: (65, 84), RiskLevel.CRITICAL: (85, 100)}[level]
        score = max(lower, min(upper, round(strongest.score * 100)))
        return RepositoryScore(score, level, len(items), dict(counts))
