"""Non-semantic text normalization used at the parser boundary."""
from __future__ import annotations

import unicodedata


class ContentNormalizer:
    """Normalize Unicode and line endings while preserving all content otherwise."""

    def normalize(self, text: str) -> str:
        """Return NFC Unicode text with CRLF and CR converted to LF."""
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        return unicodedata.normalize("NFC", normalized)
