"""Support ``python -m backend`` as the RepoRanger command-line interface."""
from __future__ import annotations

from backend.application.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
