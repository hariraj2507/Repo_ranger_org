"""Offline validation for GitHub token formats."""
from __future__ import annotations

import re

from .validation_result import ValidationResult


class GitHubValidator:
    """Recognize current GitHub classic and fine-grained token families."""

    _CLASSIC = re.compile(r"^gh[pousr]_[A-Za-z0-9]{36,255}$")
    _FINE_GRAINED = re.compile(r"^github_pat_[A-Za-z0-9_]{50,255}$")

    def validate(self, token: str) -> ValidationResult:
        """Return a format-only result for a GitHub token candidate."""
        if self._CLASSIC.fullmatch(token):
            token_type = {
                "ghp_": "personal_access", "gho_": "oauth", "ghu_": "user_to_server",
                "ghs_": "server_to_server", "ghr_": "refresh",
            }[token[:4]]
            return ValidationResult("github", True, details={"token_type": token_type})
        if self._FINE_GRAINED.fullmatch(token):
            return ValidationResult("github", True, details={"token_type": "fine_grained_personal_access"})
        return ValidationResult("github", False, ("invalid_github_token_format",))
