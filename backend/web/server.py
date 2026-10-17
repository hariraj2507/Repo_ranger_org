"""Loopback HTTP API and packaged dashboard assets, using the standard library."""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import json
from pathlib import Path
import re
import socket
from typing import Any
from urllib.parse import urlsplit

from .service import APIError, MAX_BODY_BYTES, ScanStore, SourcePolicy

_SCAN_ROUTE = re.compile(r"/api/scans/([0-9a-f]{32})(/report)?\Z")
_ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
           "/index.html": ("index.html", "text/html; charset=utf-8"),
           "/app.js": ("app.js", "text/javascript; charset=utf-8"),
           "/styles.css": ("styles.css", "text/css; charset=utf-8")}


class LocalServer(ThreadingHTTPServer):
    """Only IPv4 loopback binding is available through this server."""

    daemon_threads = True
    request_queue_size = 16

    def __init__(self, port: int, store: ScanStore) -> None:
        self.store = store
        super().__init__(("127.0.0.1", port), RequestHandler)

    def server_close(self) -> None:
        self.store.close()
        super().server_close()


class RequestHandler(BaseHTTPRequestHandler):
    """Strict JSON routes; no CORS, arbitrary file serving, or raw exceptions."""

    server: LocalServer
    server_version = "RepoRanger"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format: str, *args: object) -> None:
        # HTTP request lines may contain sensitive user input. Do not log them.
        pass

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._error(APIError(405, "method_not_allowed", "Use GET or POST for this endpoint."))

    do_PUT = do_HEAD
    do_DELETE = do_HEAD
    do_PATCH = do_HEAD
    do_OPTIONS = do_HEAD

    def _dispatch(self, method: str) -> None:
        try:
            self._check_request_origin(method)
            target = urlsplit(self.path)
            if target.scheme or target.netloc or target.query or target.fragment:
                raise APIError(400, "invalid_request", "This request URL is unsupported.")
            path = target.path
            if method == "GET" and path in _ASSETS:
                name, content_type = _ASSETS[path]
                try:
                    content = resources.files("backend.web").joinpath("static", name).read_bytes()
                except (OSError, FileNotFoundError):
                    raise APIError(404, "asset_not_found", "The dashboard asset is unavailable.") from None
                self._send(200, content, content_type)
                return
            if path == "/api/session" and method == "GET":
                self._json(200, self.server.store.session())
                return
            if path == "/api/scans":
                if method == "GET":
                    self._json(200, {"scans": self.server.store.list()})
                else:
                    self._check_token()
                    self._json(202, self.server.store.submit(self._read_json()))
                return
            match = _SCAN_ROUTE.fullmatch(path)
            if match and method == "GET":
                record = self.server.store.get(match.group(1))
                if match.group(2):
                    if record["status"] != "complete":
                        raise APIError(409, "report_not_ready", "The report is available after this scan completes.")
                    content = json.dumps(record["report"], indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8")
                    self._send(200, content, "application/json; charset=utf-8",
                               {"Content-Disposition": f'attachment; filename="reporanger-{record["id"]}.json"'})
                else:
                    self._json(200, record)
                return
            raise APIError(404, "not_found", "This endpoint is unavailable.")
        except APIError as error:
            self._error(error)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True
        except Exception:
            self._error(APIError(500, "internal_error", "The request could not complete."))

    def _check_request_origin(self, method: str) -> None:
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if port == 80:
            hosts.update({"127.0.0.1", "localhost"})
        host_headers = self.headers.get_all("Host", [])
        if len(host_headers) != 1 or host_headers[0] not in hosts:
            raise APIError(403, "invalid_host", "Access this server using its local address.")
        origins = self.headers.get_all("Origin", [])
        expected = "http://" + host_headers[0]
        if len(origins) > 1 or (origins and origins[0] != expected) or (method == "POST" and origins != [expected]):
            raise APIError(403, "invalid_origin", "Only requests from this local dashboard are accepted.")
        sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(sites) > 1 or (sites and sites[0] not in {"same-origin", "none"}):
            raise APIError(403, "invalid_origin", "Only requests from this local dashboard are accepted.")

    def _check_token(self) -> None:
        tokens = self.headers.get_all("X-RepoRanger-Token", [])
        if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode("utf-8"), self.server.store.token.encode("utf-8")):
            raise APIError(403, "invalid_token", "Refresh the dashboard before starting a scan.")

    def _read_json(self) -> Any:
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            raise APIError(400, "invalid_body", "Provide a JSON body with a valid Content-Length.")
        if len(lengths[0]) > 5 or int(lengths[0]) > MAX_BODY_BYTES:
            raise APIError(413, "body_too_large", "The request body exceeds the 16 KB limit.")
        size = int(lengths[0])
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or not re.fullmatch(r"application/json(?:\s*;\s*charset=utf-8)?", types[0], re.IGNORECASE):
            raise APIError(415, "invalid_content_type", "Use application/json for this request.")
        try:
            content = self.rfile.read(size)
            if len(content) != size:
                raise ValueError
            return json.loads(content.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            raise APIError(400, "invalid_json", "The request body must be valid UTF-8 JSON.") from None

    def _error(self, error: APIError) -> None:
        self._json(error.status, {"error": error.as_dict()}, {"Retry-After": "5"} if error.status == 429 else None)

    def _json(self, status: int, data: object, headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(data, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8", headers)

    def _send(self, status: int, content: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(content)


def create_server(root: str | Path | None = None, port: int = 8765, *, store: ScanStore | None = None) -> LocalServer:
    """Create an IPv4 loopback server; port zero is useful for tests."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Port must be from 0 to 65535")
    active_store = store or ScanStore(SourcePolicy(Path.cwd() if root is None else root))
    try:
        return LocalServer(port, active_store)
    except Exception:
        active_store.close()
        raise
