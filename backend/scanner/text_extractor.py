"""Byte-to-text extraction using an injected encoding detector."""
from __future__ import annotations

from pathlib import Path

from .encoding_detector import EncodingDetector
from .models import ExtractionError


class TextExtractor:
    """Read text files with strict decoding so data issues are never hidden."""

    def __init__(self, encoding_detector: EncodingDetector | None = None) -> None:
        self._encoding_detector = encoding_detector or EncodingDetector()

    def extract(self, path: Path) -> tuple[str, str]:
        """Return ``(text, encoding)`` or raise ``ExtractionError``."""
        try:
            encoding = self._encoding_detector.detect(path)
            with path.open("r", encoding=encoding, errors="strict", newline="") as handle:
                return handle.read(), encoding
        except (OSError, UnicodeError) as exc:
            raise ExtractionError(f"Could not extract text from {path}") from exc
