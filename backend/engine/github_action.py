"""Render safe GitHub Actions annotations and policy outcomes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .risk_engine import RiskAssessment, RiskLevel
from .score_engine import RepositoryScore


@dataclass(frozen=True, slots=True)
class GitHubActionResult:
    """CI-ready annotations, summary, and policy-based failure status."""

    annotations: tuple[str, ...]
    summary: str
    should_fail: bool


class GitHubAction:
    """Adapt RepoRanger output to GitHub Actions workflow commands.

    This class only formats output; the workflow runner owns printing commands
    and setting the final process exit code.
    """

    _LEVEL_ORDER = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}

    def render(
        self,
        score: RepositoryScore,
        assessments: Iterable[RiskAssessment],
        fail_at_or_above: RiskLevel = RiskLevel.HIGH,
    ) -> GitHubActionResult:
        """Return annotations and whether configured policy should fail CI."""
        items = tuple(assessments)
        annotations = tuple(self._annotation(item) for item in items)
        should_fail = any(self._LEVEL_ORDER[item.level] >= self._LEVEL_ORDER[fail_at_or_above] for item in items)
        summary = f"RepoRanger: {score.finding_count} findings, risk score {score.score}/100 ({score.level.value})."
        return GitHubActionResult(annotations, summary, should_fail)

    @staticmethod
    def _annotation(assessment: RiskAssessment) -> str:
        """Format one escaped GitHub Actions command with no secret preview."""
        finding = assessment.finding
        command = "error" if assessment.level in {RiskLevel.HIGH, RiskLevel.CRITICAL} else "warning"
        if assessment.historical_source is not None:
            source = assessment.historical_source
            message = _escape(f"{finding.rule_id} detected in {source.source_kind} {source.commit_id} at {finding.file_path}:{finding.line_start}; confidence {assessment.confidence.level.value}.")
            return f"::{command} title=RepoRanger historical {assessment.level.value} risk::{message}"
        properties = f"file={_escape(finding.file_path)},line={finding.line_start},title=RepoRanger {assessment.level.value} risk"
        message = _escape(f"{finding.rule_id} detected; confidence {assessment.confidence.level.value}.")
        return f"::{command} {properties}::{message}"


def _escape(value: str) -> str:
    """Escape GitHub Actions command values to prevent command injection."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C")
