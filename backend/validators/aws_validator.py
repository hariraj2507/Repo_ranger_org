"""Offline validation for AWS access-key material."""
from __future__ import annotations

import re

from .validation_result import ValidationResult


class AwsValidator:
    """Validate AWS access-key identifier and optional secret-key syntax."""

    _ACCESS_KEY_ID = re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$")
    _SECRET_ACCESS_KEY = re.compile(r"^[A-Za-z0-9/+=]{40}$")

    def validate(self, access_key_id: str, secret_access_key: str | None = None) -> ValidationResult:
        """Validate an access key ID and optionally its paired secret access key.

        AWS does not expose enough information for an offline active-key check;
        this method verifies format only.
        """
        reasons: list[str] = []
        if not self._ACCESS_KEY_ID.fullmatch(access_key_id):
            reasons.append("invalid_access_key_id_format")
        if secret_access_key is not None and not self._SECRET_ACCESS_KEY.fullmatch(secret_access_key):
            reasons.append("invalid_secret_access_key_format")
        return ValidationResult(
            provider="aws", is_valid=not reasons, reasons=tuple(reasons),
            details={"access_key_prefix": access_key_id[:4], "secret_key_supplied": secret_access_key is not None},
        )
