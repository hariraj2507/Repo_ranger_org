"""Map detector rules to the appropriate offline candidate validator."""
from __future__ import annotations
from dataclasses import replace

from backend.detectors.candidate import DetectionCandidate
from backend.validators import AwsValidator, DatabaseValidator, GitHubValidator, JwtValidator, OpenAIValidator, ValidationResult


class ValidatorRouter:
    """Route an ephemeral candidate to a validator without retaining its value."""

    def __init__(
        self,
        aws: AwsValidator | None = None,
        github: GitHubValidator | None = None,
        jwt: JwtValidator | None = None,
        database: DatabaseValidator | None = None,
        openai: OpenAIValidator | None = None,
        live_github=None,
    ) -> None:
        self._aws = aws or AwsValidator()
        self._github = github or GitHubValidator()
        self._jwt = jwt or JwtValidator()
        self._database = database or DatabaseValidator()
        self._openai = openai or OpenAIValidator()
        self._live_github = live_github

    def validate(self, candidate: DetectionCandidate) -> ValidationResult | None:
        """Return a structural validation result for a known candidate type."""
        value = candidate.matched_value
        if candidate.rule_id == "aws_access_key_id":
            return self._aws.validate(value)
        if candidate.rule_id == "github_token":
            result = self._github.validate(value)
            if self._live_github is not None and result.is_valid:
                check = self._live_github.verify(value)
                result = replace(result, details={**result.details,
                    'live_check_status': check.status, 'live_check_reason': check.reason,
                    'live_verified': check.status == 'active'})
            return result
        if candidate.rule_id == "jwt":
            return self._jwt.validate(value)
        if candidate.rule_id == "database_connection_string":
            return self._database.validate(value)
        if candidate.rule_id == "openai_api_key":
            return self._openai.validate(value)
        return None
