"""Read one Git blob safely and pass its text through the detection engine."""
from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from backend.detectors.detection_engine import DetectionEngine
from backend.detectors.finding import Finding
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata

GitRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class BlobScanError(RuntimeError):
    """Raised when a required Git blob operation fails."""


@dataclass(frozen=True, slots=True)
class BlobScanResult:
    """Findings from one blob or the reason that it was safely skipped."""

    findings: tuple[Finding, ...]
    skipped_reason: str | None = None
    analyses: tuple = ()


class BlobScanner:
    """Scan a Git blob with strict byte limits and no working-tree checkout."""

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        runner: GitRunner = subprocess.run,
        max_blob_size_bytes: int = 2_000_000,
        analyzer=None,
    ) -> None:
        if max_blob_size_bytes <= 0:
            raise ValueError("max_blob_size_bytes must be positive")
        self._detection_engine = detection_engine
        if analyzer is None and detection_engine is None:
            from backend.analysis_pipeline import FindingAnalyzer
            analyzer = FindingAnalyzer()
        self._analyzer = analyzer
        self._runner = runner
        self._max_blob_size_bytes = max_blob_size_bytes

    def scan(self, repository_path: Path, blob_id: str, path: str) -> BlobScanResult:
        """Scan a blob by object ID, returning redacted detector findings only."""
        size = self._blob_size(repository_path, blob_id)
        if size > self._max_blob_size_bytes:
            return BlobScanResult((), "too_large")
        content = self._git(repository_path, ["cat-file", "blob", blob_id]).stdout
        if not content:
            return BlobScanResult((), "empty")
        if b"\x00" in content and not content.startswith((b"\xff\xfe", b"\xfe\xff")):
            return BlobScanResult((), "binary")
        text, encoding = self._decode(content)
        if text is None:
            return BlobScanResult((), "undecodable")
        text_file = NormalizedTextFile(
            FileMetadata(path, len(content), datetime.now(timezone.utc), encoding), text,
        )
        repository = ParsedRepository(RepositoryMetadata(str(repository_path), str(repository_path)), (text_file,))
        if self._analyzer is not None:
            analyses = self._analyzer.analyze(repository)
            return BlobScanResult(tuple(item.finding for item in analyses), analyses=analyses)
        return BlobScanResult(self._detection_engine.scan(repository).findings)

    def _blob_size(self, repository_path: Path, blob_id: str) -> int:
        """Return the Git-reported blob size before loading its content."""
        output = self._git(repository_path, ["cat-file", "-s", blob_id]).stdout.decode("ascii", errors="strict").strip()
        try:
            return int(output)
        except ValueError as exc:
            raise BlobScanError(f"Git returned an invalid blob size for {blob_id}") from exc

    def _git(self, repository_path: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        """Execute a non-interactive Git command scoped to the target repository."""
        try:
            result = self._runner(
                ["git", "-C", str(repository_path), *arguments], capture_output=True,
                check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BlobScanError("Unable to execute Git blob operation") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise BlobScanError(f"Git blob operation failed: {detail or 'unknown error'}")
        return result

    @staticmethod
    def _decode(content: bytes) -> tuple[str | None, str]:
        """Decode common repository text encodings without replacement characters."""
        for encoding in ("utf-8-sig", "utf-8", "utf-16"):
            try:
                return content.decode(encoding), encoding
            except UnicodeDecodeError:
                continue
        return None, "unknown"
