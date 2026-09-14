"""Content-based distinction between text and binary files."""
from __future__ import annotations

from pathlib import Path

from .models import FileKind


class FileDetector:
    """Classify a file from a bounded byte sample without decoding it."""

    def __init__(self, sample_size: int = 8192) -> None:
        self._sample_size = sample_size

    def detect(self, path: Path) -> FileKind:
        """Return ``TEXT``, ``BINARY``, ``EMPTY``, or ``UNREADABLE``."""
        try:
            with path.open("rb") as handle:
                sample = handle.read(self._sample_size)
        except OSError:
            return FileKind.UNREADABLE
        if not sample:
            return FileKind.EMPTY
        # A Unicode BOM is conclusive evidence of text even though UTF-16/32
        # naturally contains NUL bytes in its encoded representation.
        if sample.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            return FileKind.TEXT
        if b"\x00" in sample:
            return FileKind.BINARY
        controls = sum(byte < 32 and byte not in (9, 10, 12, 13) for byte in sample)
        return FileKind.BINARY if controls / len(sample) > 0.30 else FileKind.TEXT
