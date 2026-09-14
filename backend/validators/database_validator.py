"""Offline validation for common database connection URI formats."""
from __future__ import annotations

from urllib.parse import urlparse

from .validation_result import ValidationResult


class DatabaseValidator:
    """Check connection URI structure without attempting a database connection."""

    _SUPPORTED_SCHEMES = frozenset({"postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "mssql"})

    def validate(self, connection_string: str) -> ValidationResult:
        """Validate scheme, host, username, and database name where required."""
        parsed = urlparse(connection_string)
        reasons: list[str] = []
        if parsed.scheme.lower() not in self._SUPPORTED_SCHEMES:
            reasons.append("unsupported_database_scheme")
        if not parsed.hostname:
            reasons.append("missing_database_host")
        if not parsed.username:
            reasons.append("missing_database_username")
        if parsed.scheme.lower() != "mongodb+srv" and not parsed.path.strip("/"):
            reasons.append("missing_database_name")
        try:
            port_specified = parsed.port is not None
        except ValueError:
            port_specified = False
            reasons.append("invalid_database_port")
        return ValidationResult(
            provider="database", is_valid=not reasons, reasons=tuple(reasons),
            details={
                "scheme": parsed.scheme.lower(), "host": parsed.hostname or "",
                "port_specified": port_specified, "password_supplied": parsed.password is not None,
            },
        )
