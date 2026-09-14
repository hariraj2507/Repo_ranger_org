"""JWT structure and claim validation without signature verification."""
from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any

from .validation_result import ValidationResult


class JwtValidator:
    """Validate compact JWT syntax and safe, non-secret claim metadata.

    Signature verification requires a trusted issuer key and is deliberately
    outside this offline validator's responsibilities.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock

    def validate(self, token: str) -> ValidationResult:
        """Validate JWT encoding, header algorithm, and expiration if present."""
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            return ValidationResult("jwt", False, ("jwt_must_have_three_nonempty_segments",))
        try:
            header = self._decode_json_segment(parts[0])
            payload = self._decode_json_segment(parts[1])
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return ValidationResult("jwt", False, ("invalid_jwt_json_encoding",))
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm.lower() == "none":
            return ValidationResult("jwt", False, ("missing_or_unsafe_jwt_algorithm",))
        reasons: list[str] = ["signature_not_verified_offline"]
        is_expired = False
        expiration = payload.get("exp")
        if expiration is not None:
            if not isinstance(expiration, (int, float)):
                return ValidationResult("jwt", False, ("invalid_expiration_claim",))
            is_expired = expiration <= self._clock()
            if is_expired:
                reasons.append("jwt_expired")
        details: dict[str, str | int | bool] = {
            "algorithm": algorithm, "signature_verified": False, "expired": is_expired,
        }
        issuer = payload.get("iss")
        if isinstance(issuer, str):
            details["has_issuer"] = True
        return ValidationResult("jwt", not is_expired, tuple(reasons), details)

    @staticmethod
    def _decode_json_segment(segment: str) -> dict[str, Any]:
        """Decode one base64url JSON segment, rejecting non-object values."""
        padding = "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding)
        value = json.loads(decoded.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JWT segment must contain a JSON object")
        return value
