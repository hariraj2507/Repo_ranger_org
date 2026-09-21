"""Definitions and validation for regex-based secret patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .finding import Severity


@dataclass(frozen=True, slots=True)
class PatternDefinition:
    """A named, reviewed regex rule used by ``RegexDetector``."""

    rule_id: str
    category: str
    expression: str
    severity: Severity
    description: str
    custom: bool = False
    paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    minimum_entropy: float = 0.0

    def compile(self) -> re.Pattern[str]:
        """Compile this rule with multiline support, failing early if invalid."""
        return re.compile(self.expression, re.MULTILINE)


class PatternRegistry:
    """An immutable-style registry that rejects duplicate or invalid rule IDs."""

    def __init__(self, patterns: Iterable[PatternDefinition] = ()) -> None:
        self._patterns: dict[str, PatternDefinition] = {}
        for pattern in patterns:
            self.register(pattern)

    def register(self, pattern: PatternDefinition) -> None:
        """Validate and add a rule. Duplicate IDs are a configuration error."""
        if not pattern.rule_id.strip():
            raise ValueError("Pattern rule_id must not be blank")
        if pattern.rule_id in self._patterns:
            raise ValueError(f"Duplicate pattern rule_id: {pattern.rule_id}")
        pattern.compile()
        self._patterns[pattern.rule_id] = pattern

    def patterns(self) -> tuple[PatternDefinition, ...]:
        """Return registered patterns in deterministic ID order."""
        return tuple(self._patterns[rule_id] for rule_id in sorted(self._patterns))


def default_pattern_registry() -> PatternRegistry:
    """Return conservative, high-confidence credential signatures.

    Generic ``password=`` assignments are intentionally excluded at this stage
    because their false-positive rate is too high without contextual analysis.
    """
    return PatternRegistry((
        PatternDefinition(
            "aws_access_key_id", "cloud_credential", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            Severity.HIGH, "AWS access key ID",
        ),
        PatternDefinition(
            "github_token", "api_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b",
            Severity.HIGH, "GitHub personal, OAuth, user-to-server, or refresh token",
        ),
        PatternDefinition(
            "gitlab_token", "api_token", r"\bglpat-[A-Za-z0-9_-]{20,}\b",
            Severity.HIGH, "GitLab personal access token",
        ),
        PatternDefinition(
            "private_key_block", "private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            Severity.CRITICAL, "Private key block header",
        ),
    ))
