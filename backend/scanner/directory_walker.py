"""Safe, deterministic repository directory traversal."""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path


class DirectoryWalker:
    """Yield regular files while avoiding symlinks and ignored directories."""

    def walk(self, root: Path, ignored_directories: frozenset[str] = frozenset()) -> Iterator[Path]:
        """Yield files in lexical order, relative traversal rooted at ``root``."""
        for current, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
            directory_names[:] = sorted(
                name for name in directory_names
                if name not in ignored_directories and not (Path(current) / name).is_symlink()
            )
            for name in sorted(filenames):
                path = Path(current) / name
                if not path.is_symlink() and path.is_file():
                    yield path
