"""Policy for deciding which repository files may be extracted."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from backend.config import excluded_path


@dataclass(frozen=True, slots=True)
class FileFilter:
    """Reject generated, oversized, and known binary files before reading them."""

    excluded_patterns: tuple[str, ...] = ()
    max_file_size_bytes: int = 2_000_000
    ignored_directories: frozenset[str] = field(default_factory=lambda: frozenset({
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox",
        "dist", "build", "vendor",
    }))
    binary_extensions: frozenset[str] = field(default_factory=lambda: frozenset({
        ".7z", ".bin", ".class", ".dll", ".dylib", ".exe", ".gif", ".gz", ".ico",
        ".jar", ".jpeg", ".jpg", ".mp3", ".mp4", ".pdf", ".png", ".so",
        ".tar", ".woff", ".woff2", ".zip",
    }))

    def rejection_reason(self, path: Path, relative_path: str | None = None) -> str | None:
        """Return a stable skip reason, or ``None`` when the file is eligible."""
        if relative_path is not None and excluded_path(relative_path, self.excluded_patterns):
            return "excluded"
        try:
            size = path.stat().st_size
        except OSError:
            return "unreadable"
        if size > self.max_file_size_bytes:
            return "too_large"
        if path.suffix.lower() in self.binary_extensions:
            return "binary_extension"
        return None
