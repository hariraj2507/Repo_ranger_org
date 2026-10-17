"""Bounded scan jobs and source validation for the local dashboard."""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Any

MAX_BODY_BYTES = 16_384
MAX_COMMITS = 500
MAX_BLOBS = 10_000
MAX_RECORDS = 20
MAX_PENDING = 4
SCAN_TIMEOUT_SECONDS = 300
MAX_CURRENT_BYTES = 50 * 1024 * 1024
MAX_CURRENT_FILES = 10_000
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_REPORT_FINDINGS = 5_000


class APIError(Exception):
    """An error with a deliberately public, fixed message."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def is_link(path: Path) -> bool:
    """Recognize symlinks and Windows junctions, including on Python 3.10."""
    try:
        info = path.lstat()
        return path.is_symlink() or getattr(info, "st_reparse_tag", 0) in {
            0xA0000003,  # IO_REPARSE_TAG_MOUNT_POINT
            0xA000000C,  # IO_REPARSE_TAG_SYMLINK
        }
    except OSError:
        return True


class SourcePolicy:
    """Allow a configured local tree or an exact public GitHub HTTPS URL."""

    _GITHUB = re.compile(
        r"https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
        r"([A-Za-z0-9_][A-Za-z0-9_.-]{0,99})(?:\.git)?\Z"
    )

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("The allowed root must be an existing directory")

    @classmethod
    def is_remote(cls, source: str) -> bool:
        return bool(cls._GITHUB.fullmatch(source)) and not source.endswith(("/.", "/.."))

    def validate(self, source: object) -> str:
        error = APIError(400, "invalid_source", "Use a folder within the allowed root or a public GitHub HTTPS repository URL.")
        if not isinstance(source, str) or not source.strip() or len(source) > 4096:
            raise error
        source = source.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in source):
            raise error
        if self.is_remote(source):
            return source
        if "://" in source or source.startswith(("//", "\\\\")) or "@" in source:
            raise error
        try:
            path = Path(source).expanduser()
            if not path.is_absolute():
                path = self.root / path
            # Normalize lexical dot segments before checking each component.
            lexical = Path(os.path.abspath(path))
            relative = lexical.relative_to(self.root)
            current = self.root
            for part in relative.parts:
                current = current / part
                if is_link(current):
                    raise error
            resolved = lexical.resolve(strict=True)
            resolved.relative_to(self.root)
            if not resolved.is_dir():
                raise error
        except (OSError, ValueError, RuntimeError):
            raise error from None
        return str(resolved)


@dataclass(frozen=True)
class ScanRequest:
    source: str
    history: bool = False
    max_commits: int = MAX_COMMITS
    max_blobs: int = MAX_BLOBS

    @classmethod
    def parse(cls, data: object, policy: SourcePolicy) -> ScanRequest:
        if not isinstance(data, dict) or set(data) - {"source", "history", "max_commits", "max_blobs"}:
            raise APIError(400, "invalid_request", "Provide only source, history, max_commits, and max_blobs.")
        history = data.get("history", False)
        if type(history) is not bool:
            raise APIError(400, "invalid_request", "History must be true or false.")
        limits = {}
        for key, ceiling in (("max_commits", MAX_COMMITS), ("max_blobs", MAX_BLOBS)):
            value = data.get(key, ceiling)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise APIError(400, "invalid_limits", f"{key} must be an integer from 1 to {ceiling}.")
            limits[key] = value
        return cls(policy.validate(data.get("source")), history, **limits)

    def as_dict(self) -> dict[str, object]:
        return {"source": self.source, "history": self.history,
                "max_commits": self.max_commits, "max_blobs": self.max_blobs}


def hardened_environment() -> dict[str, str]:
    """Disable inherited Git config, hooks, prompts, and credential helpers."""
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""})
    settings = {"core.hooksPath": os.devnull, "credential.helper": "", "http.followRedirects": "false",
                "protocol.allow": "never", "protocol.https.allow": "always", "init.templateDir": "",
                "core.fsmonitor": "false", "core.pager": "cat"}
    environment["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (key, value) in enumerate(settings.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


class SubprocessScanRunner:
    """Run each job in a disposable process with an overall time deadline."""

    def __init__(self, root: Path, timeout: int = SCAN_TIMEOUT_SECONDS) -> None:
        self.root, self.timeout = root, timeout
        self._lock = threading.Lock()
        self._active: subprocess.Popen[str] | None = None
        self._closed = False

    def __call__(self, request: ScanRequest) -> dict[str, Any]:
        payload = {"root": str(self.root), "request": request.as_dict()}
        try:
            # A temporary output file keeps even a malformed worker from filling
            # the server's memory through stdout. The worker limits finding rows.
            with tempfile.TemporaryFile(mode="w+b") as output:
                with self._lock:
                    if self._closed:
                        raise APIError(503, "server_stopped", "The server stopped before this scan completed.")
                    process = subprocess.Popen(
                        [sys.executable, "-m", "backend.web.worker"],
                        stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                        text=True, encoding="utf-8", errors="replace", env=hardened_environment(),
                        cwd=Path(__file__).resolve().parents[2],
                        start_new_session=os.name != "nt",
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                    self._active = process
                try:
                    process.communicate(json.dumps(payload), timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    self._terminate(process)
                    raise
                finally:
                    if process.stdin is not None:
                        process.stdin.close()
                    with self._lock:
                        self._active = None
                output.seek(0)
                content = output.read(MAX_REPORT_BYTES + 1)
                if len(content) > MAX_REPORT_BYTES:
                    raise APIError(500, "report_too_large", "The report exceeded its size limit. Try a smaller repository.")
        except subprocess.TimeoutExpired:
            raise APIError(408, "scan_timeout", "The scan reached its time limit. Try a smaller repository or lower history limits.") from None
        except (OSError, subprocess.SubprocessError):
            raise APIError(500, "scan_failed", "The scan could not complete. Check the repository and Git installation.") from None
        try:
            result = json.loads(content)
            if process.returncode != 0 or not isinstance(result, dict) or "report" not in result:
                raise ValueError
            return result["report"]
        except (ValueError, TypeError):
            raise APIError(500, "scan_failed", "The scan could not complete. Check the repository and Git installation.") from None

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        """Stop the trusted worker and any Git child when a deadline expires."""
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                               creationflags=subprocess.CREATE_NO_WINDOW, check=False)
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (OSError, subprocess.SubprocessError):
            pass
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
            process = self._active
        if process is not None:
            self._terminate(process)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    """One worker, a bounded pending queue, and a bounded in-memory history."""

    def __init__(self, policy: SourcePolicy, scan_runner: Callable[[ScanRequest], dict[str, Any]] | None = None,
                 *, max_pending: int = MAX_PENDING, max_records: int = MAX_RECORDS) -> None:
        if not 1 <= max_pending <= MAX_PENDING or not 1 <= max_records <= MAX_RECORDS:
            raise ValueError("Invalid scan storage limits")
        self.policy = policy
        self.token = secrets.token_urlsafe(32)
        self.max_pending, self.max_records = max_pending, max_records
        self._runner = scan_runner or SubprocessScanRunner(policy.root)
        self._records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._queue: queue.Queue[tuple[str, ScanRequest] | None] = queue.Queue(max_pending)
        self._lock = threading.Lock()
        self._closing = False
        self._thread = threading.Thread(target=self._work, name="reporanger-scans", daemon=True)
        self._thread.start()

    def session(self) -> dict[str, Any]:
        return {"token": self.token, "allowed_root": str(self.policy.root),
                "limits": {"max_commits": MAX_COMMITS, "max_blobs": MAX_BLOBS,
                           "max_body_bytes": MAX_BODY_BYTES, "max_pending": self.max_pending,
                           "max_records": self.max_records, "scan_timeout_seconds": SCAN_TIMEOUT_SECONDS,
                           "max_current_files": MAX_CURRENT_FILES, "max_current_bytes": MAX_CURRENT_BYTES,
                           "max_report_findings": MAX_REPORT_FINDINGS},
                "capabilities": {"history": True, "public_github": True, "local_only": True}}

    @staticmethod
    def _public(record: dict[str, Any], include_report: bool = False) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != "report" or include_report}

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public(record) for record in reversed(self._records.values())]

    def get(self, identifier: str, *, include_report: bool = True) -> dict[str, Any]:
        with self._lock:
            if identifier not in self._records:
                raise APIError(404, "scan_not_found", "This scan is unavailable.")
            return self._public(self._records[identifier], include_report)

    def submit(self, data: object) -> dict[str, Any]:
        request = ScanRequest.parse(data, self.policy)
        with self._lock:
            if self._closing or self._queue.full():
                raise APIError(429, "queue_full", "The scan queue is full. Wait for a scan to finish and try again.")
            if len(self._records) >= self.max_records:
                expired = next((identifier for identifier, record in self._records.items()
                                if record["status"] in {"complete", "failed"}), None)
                if expired is None:
                    raise APIError(429, "queue_full", "The scan queue is full. Wait for a scan to finish and try again.")
                del self._records[expired]
            identifier = secrets.token_hex(16)
            record = {"id": identifier, "status": "queued", **request.as_dict(), "created_at": _now(),
                      "started_at": None, "completed_at": None}
            self._records[identifier] = record
            self._queue.put_nowait((identifier, request))
            return self._public(record)

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            identifier, request = item
            with self._lock:
                record = self._records[identifier]
                record.update(status="running", started_at=_now())
            try:
                report = self._runner(request)
                if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
                    raise ValueError("Invalid worker report")
            except Exception as error:
                public_error = error if isinstance(error, APIError) else APIError(
                    500, "scan_failed", "The scan could not complete. Check the repository and Git installation.")
                with self._lock:
                    record.update(status="failed", error=public_error.as_dict(), completed_at=_now())
            else:
                with self._lock:
                    record.update(status="complete", report=report, summary=report["summary"], completed_at=_now())
            self._queue.task_done()

    def close(self) -> None:
        """Cancel queued jobs and terminate the active scan process."""
        with self._lock:
            if self._closing:
                return
            self._closing = True
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    self._records[item[0]].update(status="failed", completed_at=_now(),
                                                 error={"code": "server_stopped", "message": "The server stopped before this scan started."})
                self._queue.task_done()
            self._queue.put_nowait(None)
        close_runner = getattr(self._runner, "close", None)
        if close_runner is not None:
            close_runner()
