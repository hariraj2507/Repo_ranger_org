"""Scan commits reachable only through local Git reflogs."""
from __future__ import annotations

import subprocess
from dataclasses import replace
from collections.abc import Callable
from pathlib import Path

from backend.history.history_scanner import HistoryScanError, HistoryScanResult, HistoryScanner
from backend.scanner.repo_validator import RepositoryValidator

GitRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class ReflogScanner:
    """Find potentially deleted historical content preserved by local reflogs."""

    def __init__(
        self,
        history_scanner: HistoryScanner | None = None,
        validator: RepositoryValidator | None = None,
        runner: GitRunner = subprocess.run,
        max_entries: int = 500,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._history_scanner = history_scanner or HistoryScanner()
        self._validator = validator or RepositoryValidator()
        self._runner = runner
        self._max_entries = max_entries

    def scan(self, repository_path: str | Path) -> HistoryScanResult:
        """Scan unique reflog commit targets while respecting history limits."""
        root = self._validator.validate_local_path(repository_path)
        commits = self._reflog_commits(root)
        result = self._history_scanner.scan(root, commits[:self._max_entries], source_kind="reflog")
        return replace(result, truncated=True) if len(commits) > self._max_entries else result

    def _reflog_commits(self, root: Path) -> tuple[str, ...]:
        """Return unique reflog commit IDs, newest first, without reflog messages."""
        try:
            result = self._runner(
                ["git", "-C", str(root), "reflog", "show", "--all", "--format=%H"],
                capture_output=True, check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HistoryScanError("Unable to execute Git reflog operation") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise HistoryScanError(f"Git reflog operation failed: {detail or 'unknown error'}")
        unique: dict[str, None] = {}
        for commit_id in result.stdout.decode("ascii", errors="strict").splitlines():
            if commit_id:
                unique.setdefault(commit_id, None)
            if len(unique) > self._max_entries:
                break
        return tuple(unique)
