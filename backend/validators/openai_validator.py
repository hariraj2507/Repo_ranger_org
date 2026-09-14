"""Conservative offline screening for OpenAI API-key candidates."""
from __future__ import annotations

from .validation_result import ValidationResult


class OpenAIValidator:
    """Screen OpenAI-shaped candidates without treating an opaque key as verified.

    API-key formats are intentionally not a public authentication contract, so
    this class only applies a minimal, future-tolerant local candidate check.
    """

    def validate(self, api_key: str) -> ValidationResult:
        """Return a candidate-format result without contacting OpenAI."""
        if not api_key.startswith("sk-") or len(api_key) < 20 or any(character.isspace() for character in api_key):
            return ValidationResult("openai", False, ("invalid_openai_api_key_candidate",))
        key_type = "project" if api_key.startswith("sk-proj-") else "service_account" if api_key.startswith("sk-svcacct-") else "standard"
        return ValidationResult("openai", True, ("active_key_not_verified_offline",), {"key_type": key_type})
