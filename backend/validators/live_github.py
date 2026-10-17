"""Explicit, bounded GitHub authentication checks with no retained credentials.

Only the authenticated-user endpoint is contacted. Its response body is never
read: reports need an authentication result, not the account owner's identity.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from http.client import HTTPException
import math
import re
import ssl
from threading import Lock
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


_ENDPOINT = "https://api.github.com/user"
_HEADER_TOKEN = re.compile(r"[A-Za-z0-9_]{1,512}\Z", re.ASCII)
LiveStatus = Literal["active", "inactive", "inconclusive", "skipped"]


@dataclass(frozen=True, slots=True)
class LiveCheck:
    """A safe result with fixed status and reason; no credential or identity."""

    status: LiveStatus
    reason: str


class _NoRedirect(HTTPRedirectHandler):
    """Never forward an Authorization header to a redirected destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubLiveVerifier:
    """Check at most 20 distinct credentials when a caller explicitly opts in.

    ``opener`` exists for deterministic tests. Production callers should leave it
    unset so that HTTPS verification, disabled proxies, and blocked redirects are
    always applied. Results are cached in memory by SHA-256 digest only.
    """

    def __init__(self, max_checks: int = 20, timeout: float = 5, opener=None) -> None:
        if type(max_checks) is not int or not 0 <= max_checks <= 20:
            raise ValueError("GitHub live checks must be between 0 and 20")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("GitHub live-check timeout must be greater than 0 and at most 30 seconds")
        self._max_checks = max_checks
        self._timeout = float(timeout)
        self._opener = opener if opener is not None else build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect(),
        )
        self._cache: dict[str, LiveCheck] = {}
        self._lock = Lock()

    def verify(self, value: str) -> LiveCheck:
        """Return a safe outcome without storing or exposing the token value."""
        if not isinstance(value, str) or not _HEADER_TOKEN.fullmatch(value):
            return LiveCheck("skipped", "github_invalid_token_header")
        # Installation and refresh tokens cannot authenticate as a user at this
        # endpoint. A rejection here would not establish their real validity.
        if value.startswith(("ghs_", "ghr_")):
            return LiveCheck("skipped", "github_unsupported_token_family")
        fingerprint = hashlib.sha256(value.encode("ascii")).hexdigest()
        with self._lock:
            if fingerprint in self._cache:
                return self._cache[fingerprint]
            if len(self._cache) >= self._max_checks:
                return LiveCheck("skipped", "github_check_limit_reached")
            result = self._check(value)
            self._cache[fingerprint] = result
            return result

    def _check(self, value: str) -> LiveCheck:
        request = Request(_ENDPOINT, method="GET", headers={
            "Authorization": "Bearer " + value,
            "Accept": "application/vnd.github+json",
            "User-Agent": "RepoRanger-Optional-Verification",
        })
        response = None
        try:
            response = self._opener.open(request, timeout=self._timeout)
            if response.geturl() != _ENDPOINT:
                return LiveCheck("inconclusive", "github_redirect_not_followed")
            return self._status(response.getcode())
        except HTTPError as error:
            try:
                return self._status(error.code)
            finally:
                self._close(error)
        except (URLError, OSError, HTTPException, ValueError):
            # Exception text can include a token, response body, or network
            # details. Only fixed, public reasons cross this boundary.
            return LiveCheck("inconclusive", "github_network_unavailable")
        except Exception:
            return LiveCheck("inconclusive", "github_check_unavailable")
        finally:
            if response is not None:
                self._close(response)

    @staticmethod
    def _close(response) -> None:
        try:
            response.close()
        except Exception:
            # Cleanup errors are not useful report evidence and must not expose
            # provider response text or credential-bearing exception details.
            pass

    @staticmethod
    def _status(code: int) -> LiveCheck:
        if type(code) is not int:
            return LiveCheck("inconclusive", "github_unexpected_http_status")
        if code == 200:
            return LiveCheck("active", "github_authenticated")
        if code == 401:
            return LiveCheck("inactive", "github_authentication_rejected")
        if code == 403 or code == 429:
            return LiveCheck("inconclusive", "github_forbidden_or_rate_limited")
        if 300 <= code < 400:
            return LiveCheck("inconclusive", "github_redirect_not_followed")
        return LiveCheck("inconclusive", "github_unexpected_http_status")
