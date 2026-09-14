"""Orchestration layer for Phase 1 repository extraction and parsing."""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .content_normalizer import ContentNormalizer
from .directory_walker import DirectoryWalker
from .file_detector import FileDetector
from .file_filter import FileFilter
from .models import ExtractionError, FileKind, FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata
from .repo_validator import RepositoryValidator
from .repo_cloner import RepositoryCloner
from .text_extractor import TextExtractor
from .workspace_manager import WorkspaceManager


class RepositoryParser:
    """Produce a deterministic, normalized representation of a local repository.

    Remote cloning is intentionally a separate concern (``RepositoryCloner``),
    allowing callers to control credentials and temporary-workspace lifetime.
    """

    def __init__(
        self, validator: RepositoryValidator | None = None, walker: DirectoryWalker | None = None,
        file_filter: FileFilter | None = None, detector: FileDetector | None = None,
        extractor: TextExtractor | None = None, normalizer: ContentNormalizer | None = None,
    ) -> None:
        self._validator = validator or RepositoryValidator()
        self._walker = walker or DirectoryWalker()
        self._filter = file_filter or FileFilter()
        self._detector = detector or FileDetector()
        self._extractor = extractor or TextExtractor()
        self._normalizer = normalizer or ContentNormalizer()
        self._logger = logging.getLogger(__name__)

    def parse(self, source: str | Path) -> ParsedRepository:
        """Extract eligible normalized text files from a local repository path."""
        root = self._validator.validate_local_path(source)
        skipped: Counter[str] = Counter()
        files: list[NormalizedTextFile] = []
        seen = 0
        for path in self._walker.walk(root, self._filter.ignored_directories):
            seen += 1
            reason = self._filter.rejection_reason(path, path.relative_to(root).as_posix())
            if reason:
                skipped[reason] += 1
                continue
            kind = self._detector.detect(path)
            if kind is not FileKind.TEXT:
                skipped[kind.value] += 1
                continue
            try:
                text, encoding = self._extractor.extract(path)
                stat = path.stat()
            except (ExtractionError, OSError, UnicodeError) as exc:
                # An individual unreadable file must not abort a repository scan.
                self._logger.warning("Skipping unreadable file %s: %s", path, exc)
                skipped["extraction_error"] += 1
                continue
            relative_path = path.relative_to(root).as_posix()
            metadata = FileMetadata(
                relative_path=relative_path,
                size_bytes=stat.st_size,
                modified_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                encoding=encoding,
                kind=kind,
            )
            files.append(NormalizedTextFile(metadata, self._normalizer.normalize(text)))
        repository_metadata = RepositoryMetadata(str(source), str(root), total_files_seen=seen, skipped_files=dict(sorted(skipped.items())))
        return ParsedRepository(repository_metadata, tuple(files))

    def parse_remote(
        self,
        source: str,
        cloner: RepositoryCloner | None = None,
        workspace_manager: WorkspaceManager | None = None,
    ) -> ParsedRepository:
        """Clone and parse a remote repository, deleting the clone on return.

        For custom credential handling, callers may inject a configured cloner.
        ``workspace_manager`` is injectable to make lifecycle behavior testable.
        """
        active_cloner = cloner or RepositoryCloner(self._validator)
        manager = workspace_manager or WorkspaceManager()
        with manager as workspace:
            clone_path = active_cloner.clone(source, workspace / "repository")
            parsed = self.parse(clone_path)
        metadata = RepositoryMetadata(
            source=source,
            root_path=parsed.metadata.root_path,
            parsed_at=parsed.metadata.parsed_at,
            total_files_seen=parsed.metadata.total_files_seen,
            skipped_files=parsed.metadata.skipped_files,
        )
        return ParsedRepository(metadata, parsed.files)
