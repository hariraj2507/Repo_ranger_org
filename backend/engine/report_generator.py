"""Create safe JSON and Markdown reports from risk assessments."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from .risk_engine import RiskAssessment
from .score_engine import RepositoryScore


class ReportGenerator:
    """Produce serializable reports that contain redacted findings only."""

    def as_dict(self, repository_source: str, score: RepositoryScore, assessments: Iterable[RiskAssessment]) -> dict[str, object]:
        """Return a report dictionary suitable for an API or JSON export."""
        items = tuple(assessments)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repository_source": repository_source,
            "summary": {
                "score": score.score,
                "risk_level": score.level.value,
                "finding_count": score.finding_count,
                "risk_counts": {level.value: count for level, count in score.risk_counts.items()},
            },
            "findings": [self._finding_dict(item) for item in items],
        }

    def as_json(self, repository_source: str, score: RepositoryScore, assessments: Iterable[RiskAssessment]) -> str:
        """Return an indented JSON report without raw credential material."""
        return json.dumps(self.as_dict(repository_source, score, assessments), indent=2, sort_keys=True)

    def as_markdown(self, repository_source: str, score: RepositoryScore, assessments: Iterable[RiskAssessment]) -> str:
        """Return a concise human-readable Markdown report."""
        rows = [
            "# RepoRanger security report", "",
            f"Repository: `{repository_source}`", f"Risk score: **{score.score}/100 ({score.level.value})**", "",
            "| Risk | Finding | Location | Confidence |", "|---|---|---|---|",
        ]
        for item in assessments:
            finding = item.finding
            location = f"{finding.file_path}:{finding.line_start}"
            if item.historical_source is not None:
                location += f" ({item.historical_source.source_kind} {item.historical_source.commit_id[:12]})"
            location = location.replace("|", "&#124;").replace("\n", " ").replace("\r", " ").replace("`", "&#96;")
            rows.append(
                f"| {item.level.value} | {finding.rule_id} | `{location}` | {item.confidence.level.value} |"
            )
        return "\n".join(rows)

    @staticmethod
    def _finding_dict(assessment: RiskAssessment) -> dict[str, object]:
        """Serialize a single assessment while excluding source text and secrets."""
        finding = assessment.finding
        value: dict[str, object] = {
            "rule_id": finding.rule_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "risk_level": assessment.level.value,
            "risk_score": round(assessment.score, 3),
            "confidence": assessment.confidence.level.value,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "preview": finding.preview,
            "fingerprint": finding.fingerprint,
            "rationale": list(assessment.rationale),
        }
        if assessment.validation is not None:
            value["validation"] = {"provider": assessment.validation.provider, "format_valid": assessment.validation.is_valid,
                                   "reasons": list(assessment.validation.reasons), "live_verified": False}
        if assessment.context is not None:
            context = assessment.context
            value["context"] = {"language": context.language, "symbol_kind": context.symbol_kind,
                                "start_line": context.start_line, "end_line": context.end_line}
        if assessment.historical_source is not None:
            value["history"] = {
                "commit_id": assessment.historical_source.commit_id,
                "blob_id": assessment.historical_source.blob_id,
                "source_kind": assessment.historical_source.source_kind,
            }
        return value
