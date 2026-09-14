"""Small adapter around Git cloning."""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from pathlib import Path

from .models import CloneError
from .repo_validator import RepositoryValidator

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class RepositoryCloner:
    """Clone remote repositories with a shallow, non-interactive Git command."""

    def __init__(self, validator: RepositoryValidator | None = None, runner: CommandRunner = subprocess.run) -> None:
        self._validator = validator or RepositoryValidator()
        self._runner = runner
        self._logger = logging.getLogger(__name__)

    def clone(self, source: str, destination: Path, *, shallow: bool = True) -> Path:
        """Clone ``source`` into an empty ``destination`` and return that path."""
        url = self._validator.validate_remote_url(source)
        destination = destination.resolve()
        if destination.exists() and any(destination.iterdir()):
            raise CloneError(f"Clone destination is not empty: {destination}")
        self._logger.info("Cloning repository into temporary workspace")
        try:
            result = self._runner(
                ["git", "clone", *(["--depth", "1"] if shallow else []), "--", url, str(destination)],
                text=True, capture_output=True, check=False, timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CloneError("Unable to execute Git clone") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "unknown Git error").strip()
            raise CloneError(f"Git clone failed: {detail}")
        return destination
