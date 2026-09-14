"""Unit tests for Day 3 offline credential validators."""
import base64
import json
import unittest

from backend.validators import AwsValidator, DatabaseValidator, GitHubValidator, JwtValidator, OpenAIValidator


def jwt_segment(value: dict[str, object]) -> str:
    """Return an unpadded base64url JSON segment for a test JWT."""
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class ValidatorTests(unittest.TestCase):
    def test_aws_validator_accepts_access_key_and_secret(self) -> None:
        result = AwsValidator().validate("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertTrue(result.is_valid)
        self.assertNotIn("wJalr", str(result.details))

    def test_github_validator_recognizes_classic_token(self) -> None:
        result = GitHubValidator().validate("ghp_" + "A" * 36)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.details["token_type"], "personal_access")

    def test_jwt_validator_rejects_expired_token_but_reports_offline_limit(self) -> None:
        token = f"{jwt_segment({'alg': 'HS256'})}.{jwt_segment({'exp': 100})}.signature"
        result = JwtValidator(clock=lambda: 101).validate(token)
        self.assertFalse(result.is_valid)
        self.assertIn("jwt_expired", result.reasons)
        self.assertFalse(result.details["signature_verified"])

    def test_database_validator_does_not_leak_password(self) -> None:
        result = DatabaseValidator().validate("postgresql://user:private-password@example.com:5432/app")
        self.assertTrue(result.is_valid)
        self.assertTrue(result.details["password_supplied"])
        self.assertNotIn("private-password", str(result.details))

    def test_openai_validator_supports_project_key(self) -> None:
        result = OpenAIValidator().validate("sk-proj-" + "a" * 24)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.details["key_type"], "project")
        self.assertIn("active_key_not_verified_offline", result.reasons)

    def test_database_validator_rejects_invalid_port_without_raising(self) -> None:
        result = DatabaseValidator().validate("postgresql://user:pass@example.com:not-a-port/app")
        self.assertFalse(result.is_valid)
        self.assertIn("invalid_database_port", result.reasons)
