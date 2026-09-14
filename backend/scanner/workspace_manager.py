"""Lifecycle management for temporary clone workspaces."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path


class WorkspaceManager:
    """Create isolated temporary directories and reliably remove them on exit."""

    def __init__(self, base_directory: Path | None = None) -> None:
        self._base_directory = base_directory
        self._workspace: Path | None = None

    def __enter__(self) -> Path:
        self._workspace = Path(tempfile.mkdtemp(prefix="reporanger-", dir=self._base_directory))
        return self._workspace

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._workspace is not None:
            shutil.rmtree(self._workspace, ignore_errors=True)
            self._workspace = None
