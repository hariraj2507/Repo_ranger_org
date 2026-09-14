"""Deterministic character encoding detection for repository text files."""
from __future__ import annotations

from pathlib import Path


class EncodingDetector:
    """Detect common Unicode encodings, falling back to UTF-8 then Latin-1."""

    def detect(self, path: Path) -> str:
        """Return an encoding that can decode the file without replacement."""
        with path.open("rb") as handle:
            data = handle.read()
        if data.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return "utf-16"
        for encoding in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
            try:
                data.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue
        return "latin-1"  # Kept for an explicit, defensive total return contract.
