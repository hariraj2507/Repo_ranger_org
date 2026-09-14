"""Validation of local paths and Git repository URLs."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .models import RepositoryValidationError


class RepositoryValidator:
    """Validate sources before any filesystem or subprocess operation.

    This class validates syntax and local-directory accessibility only; it does
    not make network requests, keeping validation deterministic and testable.
    """

    _REMOTE_SCHEMES = frozenset({"https", "http", "ssh", "git"})

    def validate_local_path(self, source: str | Path) -> Path:
        """Return an absolute directory path or raise ``RepositoryValidationError``."""
        path = Path(source).expanduser()
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryValidationError(f"Repository path does not exist: {path}") from exc
        if not resolved.is_dir():
            raise RepositoryValidationError(f"Repository path is not a directory: {resolved}")
        return resolved

    def validate_remote_url(self, source: str) -> str:
        """Validate a supported remote Git URL and return it unchanged."""
        candidate = source.strip()
        parsed = urlparse(candidate)
        is_scp_style = "@" in candidate and ":" in candidate and "://" not in candidate
        if is_scp_style:
            return candidate
        if parsed.scheme not in self._REMOTE_SCHEMES or not parsed.netloc:
            raise RepositoryValidationError("Repository URL must be a supported absolute Git URL")
        return candidate
