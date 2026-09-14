"""Domain models used by the repository extraction pipeline.

The models deliberately contain no detection results.  They are a stable handoff
contract for later scanner phases.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping


class FileKind(str, Enum):
    """The extraction-relevant kind of a filesystem entry."""

    TEXT = "text"
    BINARY = "binary"
    EMPTY = "empty"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Metadata gathered for a file without interpreting its content."""

    relative_path: str
    size_bytes: int
    modified_at: datetime
    encoding: str
    kind: FileKind = FileKind.TEXT


@dataclass(frozen=True, slots=True)
class NormalizedTextFile:
    """A decoded, normalized text file and its immutable metadata."""

    metadata: FileMetadata
    text: str


@dataclass(frozen=True, slots=True)
class RepositoryMetadata:
    """Repository-level information captured during extraction."""

    source: str
    root_path: str
    parsed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_files_seen: int = 0
    skipped_files: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParsedRepository:
    """The Phase 1 output supplied to future detection and reporting stages."""

    metadata: RepositoryMetadata
    files: tuple[NormalizedTextFile, ...]

    @property
    def file_count(self) -> int:
        """Return the number of extracted normalized text files."""
        return len(self.files)


class RepositoryError(Exception):
    """Base exception for errors that make repository extraction impossible."""


class RepositoryValidationError(RepositoryError):
    """Raised when a repository source is malformed or unsafe."""


class CloneError(RepositoryError):
    """Raised when cloning a remote repository fails."""


class ExtractionError(RepositoryError):
    """Raised when a selected text file cannot be extracted."""
