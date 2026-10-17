"""Start RepoRanger's local dashboard: python -m backend.web."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .server import create_server


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reporanger-web", description="Run the RepoRanger dashboard on this computer.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Allowed local folder tree (default: current folder)")
    parser.add_argument("--port", type=int, default=8765, help="Local HTTP port (default: 8765)")
    args = parser.parse_args(arguments)
    if not 1 <= args.port <= 65535:
        parser.error("port must be from 1 to 65535")
    try:
        server = create_server(args.root, args.port)
    except (OSError, ValueError, RuntimeError):
        print("RepoRanger could not start. Check the allowed folder and whether the local port is available.", file=sys.stderr)
        return 2
    print(f"RepoRanger dashboard: http://127.0.0.1:{server.server_port}", flush=True)
    print(f"Allowed local folder: {server.store.policy.root}", flush=True)
    print("Press Ctrl+C to stop. Scan reports are kept in memory for this session.", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
