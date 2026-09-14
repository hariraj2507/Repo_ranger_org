"""Compatibility entry point; prefer reporanger or python -m backend."""
from backend.application.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
