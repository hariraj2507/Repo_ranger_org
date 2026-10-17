"""Bounded live-verification behavior using fake HTTP; never real credentials."""
from __future__ import annotations

import hashlib
import io
import ssl
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request

from backend.validators.live_github import GitHubLiveVerifier, LiveCheck, _NoRedirect


TOKEN = "ghp_" + "A" * 36
ENDPOINT = "https://api.github.com/user"


class FakeResponse:
    def __init__(self, code=200, url=ENDPOINT):
        self.code = code
        self.url = url
        self.closed = False

    def getcode(self):
        return self.code

    def geturl(self):
        return self.url

    def read(self, *args):
        raise AssertionError("Provider identities and response bodies must not be read")

    def close(self):
        self.closed = True


class GitHubLiveVerifierTests(unittest.TestCase):
    def verifier(self, response=None, error=None, **kwargs):
        opener = Mock()
        if error is not None:
            opener.open.side_effect = error
        else:
            opener.open.return_value = response if response is not None else FakeResponse()
        return GitHubLiveVerifier(opener=opener, **kwargs), opener

    def test_success_uses_fixed_endpoint_headers_and_closes_without_body(self):
        response = FakeResponse()
        verifier, opener = self.verifier(response)
        self.assertEqual(verifier.verify(TOKEN), LiveCheck("active", "github_authenticated"))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, ENDPOINT)
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("User-agent"), "RepoRanger-Optional-Verification")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 5.0})
        self.assertTrue(response.closed)

    def test_http_401_rejects_authentication_and_closes_error_body(self):
        body = io.BytesIO(b'{"login":"private-provider-identity"}')
        error = HTTPError(ENDPOINT, 401, "Unauthorized", {}, body)
        verifier, _ = self.verifier(error=error)
        self.assertEqual(verifier.verify(TOKEN).status, "inactive")
        self.assertTrue(body.closed)

    def test_forbidden_rate_limits_and_other_statuses_are_inconclusive(self):
        for status in (403, 429, 404, 500, 503, 304, None, "200"):
            with self.subTest(status=status):
                response = FakeResponse(status)
                verifier, _ = self.verifier(response)
                self.assertEqual(verifier.verify(TOKEN).status, "inconclusive")
                self.assertTrue(response.closed)

    def test_http_error_forbidden_rate_limits_and_redirects_are_closed(self):
        for status in (403, 429, 301, 302, 307, 308):
            with self.subTest(status=status):
                body = io.BytesIO(b"Never read this body")
                error = HTTPError(ENDPOINT, status, "Unavailable", {"Location": "https://other.example/user"}, body)
                verifier, opener = self.verifier(error=error)
                self.assertEqual(verifier.verify(TOKEN).status, "inconclusive")
                self.assertTrue(body.closed)
                self.assertEqual(opener.open.call_count, 1)

    def test_changed_response_url_is_not_reported_as_active(self):
        response = FakeResponse(200, "https://other.example/user")
        verifier, _ = self.verifier(response)
        result = verifier.verify(TOKEN)
        self.assertEqual(result, LiveCheck("inconclusive", "github_redirect_not_followed"))
        self.assertTrue(response.closed)

    def test_network_timeout_and_header_errors_do_not_expose_exception_text(self):
        for error in (URLError("private-provider-identity " + TOKEN), TimeoutError(TOKEN), ssl.SSLError(TOKEN), ValueError(TOKEN)):
            with self.subTest(kind=type(error).__name__):
                verifier, _ = self.verifier(error=error)
                result = verifier.verify(TOKEN)
                self.assertEqual(result.status, "inconclusive")
                self.assertNotIn(TOKEN, repr(result))
                self.assertNotIn("private-provider-identity", repr(result))

    def test_duplicate_tokens_use_digest_cache_and_do_not_spend_check_limit(self):
        verifier, opener = self.verifier(max_checks=1)
        first = verifier.verify(TOKEN)
        self.assertIs(verifier.verify(TOKEN), first)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(tuple(verifier._cache), (hashlib.sha256(TOKEN.encode()).hexdigest(),))
        self.assertNotIn(TOKEN, repr(verifier._cache))
        self.assertEqual(verifier.verify("ghp_" + "B" * 36).status, "skipped")
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(len(verifier._cache), 1)

    def test_network_failure_is_cached_and_counts_toward_limit(self):
        verifier, opener = self.verifier(error=URLError("unavailable"), max_checks=1)
        self.assertEqual(verifier.verify(TOKEN).status, "inconclusive")
        self.assertEqual(verifier.verify(TOKEN).status, "inconclusive")
        self.assertEqual(verifier.verify("ghp_" + "B" * 36).status, "skipped")
        self.assertEqual(opener.open.call_count, 1)

    def test_default_cap_is_twenty_unique_requests(self):
        verifier, opener = self.verifier()
        for index in range(20):
            self.assertEqual(verifier.verify("ghp_" + f"{index:036d}").status, "active")
        self.assertEqual(verifier.verify("ghp_" + "B" * 36).status, "skipped")
        self.assertEqual(opener.open.call_count, 20)

    def test_zero_limit_makes_no_requests(self):
        verifier, opener = self.verifier(max_checks=0)
        self.assertEqual(verifier.verify(TOKEN).status, "skipped")
        opener.open.assert_not_called()

    def test_header_injection_malformed_and_oversized_values_never_make_requests(self):
        verifier, opener = self.verifier()
        for value in ("", None, b"token", TOKEN + "\r\nX-Evil: yes", TOKEN + "\n", TOKEN + "\t", "token with spaces", "ghp_ä", "A" * 513):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(verifier.verify(value), LiveCheck("skipped", "github_invalid_token_header"))
        opener.open.assert_not_called()
        self.assertEqual(verifier._cache, {})

    def test_installation_and_refresh_tokens_need_different_endpoints(self):
        verifier, opener = self.verifier()
        for prefix in ("ghs_", "ghr_"):
            self.assertEqual(verifier.verify(prefix + "A" * 36), LiveCheck("skipped", "github_unsupported_token_family"))
        opener.open.assert_not_called()

    def test_result_and_verifier_repr_do_not_hold_raw_secret_or_identity(self):
        verifier, _ = self.verifier()
        result = verifier.verify(TOKEN)
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn(TOKEN, repr(verifier))
        self.assertEqual(set(result.__slots__), {"status", "reason"})
        self.assertEqual(set(verifier.__dict__), {"_max_checks", "_timeout", "_opener", "_cache", "_lock"})

    def test_timeout_is_forwarded_without_retry(self):
        verifier, opener = self.verifier(error=TimeoutError(), timeout=2.5)
        self.assertEqual(verifier.verify(TOKEN).status, "inconclusive")
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 2.5)

    def test_unexpected_transport_and_cleanup_errors_do_not_leak(self):
        verifier, _ = self.verifier(error=RuntimeError(TOKEN))
        self.assertEqual(verifier.verify(TOKEN), LiveCheck("inconclusive", "github_check_unavailable"))
        response = FakeResponse()
        response.close = Mock(side_effect=RuntimeError(TOKEN))
        verifier, _ = self.verifier(response)
        result = verifier.verify(TOKEN)
        self.assertEqual(result.status, "active")
        self.assertNotIn(TOKEN, repr(result))

    def test_production_opener_disables_proxies_and_uses_default_tls(self):
        with patch("backend.validators.live_github.build_opener") as factory:
            GitHubLiveVerifier()
        handlers = factory.call_args.args
        proxy = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
        https = next(handler for handler in handlers if isinstance(handler, HTTPSHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertTrue(https._context.check_hostname)
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(any(isinstance(handler, _NoRedirect) for handler in handlers))

    def test_redirect_handler_never_creates_a_forwarded_request(self):
        handler = _NoRedirect()
        request = Request(ENDPOINT, headers={"Authorization": "Bearer " + TOKEN})
        for destination in ("https://other.example/user", "http://api.github.com/user", ENDPOINT + "?next=true"):
            self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, destination))

    def test_bounds_cannot_disable_safety_cap(self):
        for maximum in (-1, 21, 1.5, True):
            with self.assertRaises(ValueError):
                GitHubLiveVerifier(max_checks=maximum, opener=Mock())
        for timeout in (0, -1, 31, float("inf"), float("nan"), True, "5"):
            with self.assertRaises(ValueError):
                GitHubLiveVerifier(timeout=timeout, opener=Mock())


if __name__ == "__main__":
    unittest.main()
