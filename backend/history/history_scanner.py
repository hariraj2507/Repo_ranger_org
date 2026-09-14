"""Scan historical Git commit trees without checking out old revisions."""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from backend.config import excluded_path
from backend.history.blob_scanner import BlobScanError, BlobScanner
from backend.history.models import HistoricalFinding, HistoricalSource
from backend.scanner.repo_validator import RepositoryValidator

GitRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class HistoryScanError(RuntimeError):
    """Raised when the target is not a usable Git repository or Git fails."""


@dataclass(frozen=True, slots=True)
class HistoryScanResult:
    """Redacted historical findings and scan counters for observability."""

    findings: tuple[HistoricalFinding, ...]
    commits_scanned: int
    blobs_scanned: int
    blobs_skipped: int
    truncated: bool
    incomplete: bool = False
    shallow: bool = False


class HistoryScanner:
    """Enumerate commit-tree blobs with bounded, deterministic resource use."""

    def __init__(
        self,
        blob_scanner: BlobScanner | None = None,
        validator: RepositoryValidator | None = None,
        runner: GitRunner = subprocess.run,
        max_commits: int = 500,
        max_blobs: int = 10_000,
        excluded_patterns: tuple[str, ...] = (),
    ) -> None:
        if max_commits <= 0 or max_blobs <= 0:
            raise ValueError("max_commits and max_blobs must be positive")
        self._blob_scanner = blob_scanner or BlobScanner()
        self._validator = validator or RepositoryValidator()
        self._runner = runner
        self._max_commits = max_commits
        self._max_blobs = max_blobs
        self._excluded_patterns = excluded_patterns
        self._logger = logging.getLogger(__name__)

    def scan(
        self,
        repository_path: str | Path,
        commits: Iterable[str] | None = None,
        source_kind: str = "commit_history",
    ) -> HistoryScanResult:
        """Scan every unique reachable blob in selected commits, within limits."""
        root = self._validator.validate_local_path(repository_path)
        self._ensure_git_repository(root)
        shallow = self._git(root, ["rev-parse", "--is-shallow-repository"]).stdout.strip() == b"true"
        selected = tuple(commits) if commits is not None else self._all_commits(root)
        truncated = len(selected) > self._max_commits
        selected = selected[:self._max_commits]
        findings: list[HistoricalFinding] = []
        blob_cache = {}
        seen_blobs = set()
        seen_locations: set[tuple[str, str]] = set()
        skipped = 0
        incomplete = shallow
        commits_scanned = 0
        for commit_id in selected:
            commits_scanned += 1
            for blob_id, path in self._tree_blobs(root, commit_id):
                if excluded_path(path, self._excluded_patterns):
                    continue
                location = (blob_id, path)
                if location in seen_locations:
                    continue
                seen_locations.add(location)
                cache_key = (blob_id, Path(path).suffix.lower())
                if cache_key not in blob_cache:
                    if blob_id not in seen_blobs and len(seen_blobs) >= self._max_blobs:
                        return HistoryScanResult(tuple(findings), commits_scanned, len(seen_blobs), skipped, True, incomplete, shallow)
                    # Cache only redacted findings. Reuse detection for identical bytes,
                    # but retain each distinct path, even after a rename or copy.
                    seen_blobs.add(blob_id)
                    blob_cache[cache_key] = None
                    try:
                        result = self._blob_scanner.scan(root, blob_id, path)
                    except BlobScanError as exc:
                        self._logger.warning("Skipping inaccessible historical blob %s: %s", blob_id, exc)
                        skipped += 1
                        incomplete = True
                        continue
                    if result.skipped_reason is not None:
                        incomplete |= result.skipped_reason not in {"empty", "binary"}
                        skipped += 1
                        continue
                    blob_cache[cache_key] = result
                source = HistoricalSource(commit_id, blob_id, path, source_kind)
                cached = blob_cache[cache_key]
                if cached is None:
                    continue
                if cached.analyses:
                    findings.extend(HistoricalFinding(replace(item.finding, file_path=path), source, item.validation, item.context)
                                    for item in cached.analyses)
                else:
                    findings.extend(HistoricalFinding(replace(finding, file_path=path), source)
                                    for finding in cached.findings)
        return HistoryScanResult(tuple(findings), commits_scanned, len(seen_blobs), skipped, truncated, incomplete, shallow)

    def _all_commits(self, root: Path) -> tuple[str, ...]:
        """Return all reachable commit IDs in Git's stable revision order."""
        output = self._git(root, ["rev-list", "--all", f"--max-count={self._max_commits + 1}"]).stdout.decode("ascii", errors="strict")
        return tuple(line for line in output.splitlines() if line)

    def _tree_blobs(self, root: Path, commit_id: str) -> tuple[tuple[str, str], ...]:
        """Read blob IDs and paths from a commit tree using NUL-safe parsing."""
        output = self._git(root, ["ls-tree", "-r", "-z", "--full-tree", commit_id]).stdout
        blobs: list[tuple[str, str]] = []
        for record in output.split(b"\0"):
            if not record or b"\t" not in record:
                continue
            header, raw_path = record.split(b"\t", 1)
            parts = header.split()
            if len(parts) != 3 or parts[1] != b"blob":
                continue
            blobs.append((parts[2].decode("ascii"), raw_path.decode("utf-8", errors="surrogateescape")))
        return tuple(blobs)

    def _ensure_git_repository(self, root: Path) -> None:
        """Fail early with a focused error for ordinary directories."""
        result = self._git(root, ["rev-parse", "--is-inside-work-tree"])
        if result.stdout.strip() != b"true":
            raise HistoryScanError(f"Not a Git working tree: {root}")

    def _git(self, root: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        """Run a bounded non-interactive Git command against ``root``."""
        try:
            result = self._runner(
                ["git", "-C", str(root), *arguments], capture_output=True,
                check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HistoryScanError("Unable to execute Git history operation") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise HistoryScanError(f"Git history operation failed: {detail or 'unknown error'}")
        return result
