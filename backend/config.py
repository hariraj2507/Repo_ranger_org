"""Explicit, validated scan policy shared by CLI and scanner layers."""
from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re



def excluded_path(path: str, patterns: tuple[str, ...]) -> bool:
    """Match case-sensitive, repository-relative paths; * may span directories."""
    path = path.replace("\\", "/")
    for pattern in patterns:
        pattern = pattern.replace("\\", "/")
        if pattern.endswith("/"):
            pattern += "*"
        if fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatchcase(path, pattern[3:])):
            return True
    return False


@dataclass(frozen=True)
class ScanConfig:
    exclude: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    suppress_fingerprints: tuple[str, ...] = ()
    custom_rules: tuple = ()

    def __post_init__(self):
        for name in ("exclude", "disabled_rules", "suppress_fingerprints"):
            values = getattr(self, name)
            if not isinstance(values, (list, tuple)) or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValueError(f"{name} must be an array of nonempty strings")
            object.__setattr__(self, name, tuple(values))
        from backend.detectors.pattern_registry import default_pattern_registry
        from backend.detectors.custom_rule import CustomRule
        if not isinstance(self.custom_rules, (tuple, list)) or len(self.custom_rules) > 100:
            raise ValueError('custom_rules must be an array of at most 100 rules')
        try:
            rules = tuple(rule if isinstance(rule, CustomRule) else CustomRule(**rule) for rule in self.custom_rules)
        except (TypeError, KeyError) as exc:
            raise ValueError('Invalid custom rule fields') from exc
        identifiers = [rule.rule_id for rule in rules]
        reserved = {p.rule_id for p in default_pattern_registry().patterns()} | {'high_entropy_token', 'jwt', 'private_jwk'}
        if len(set(identifiers)) != len(identifiers) or set(identifiers) & reserved:
            raise ValueError('Custom rule IDs must be unique and cannot replace built-in rules')
        object.__setattr__(self, 'custom_rules', rules)
        known = set(identifiers) | {p.rule_id for p in default_pattern_registry().patterns()} | {"high_entropy_token", "jwt", "private_jwk"}
        if set(self.disabled_rules) - known:
            raise ValueError("disabled_rules contains an unknown rule ID")
        if any(not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in self.suppress_fingerprints):
            raise ValueError("suppress_fingerprints must contain SHA-256 hashes")
        object.__setattr__(self, "suppress_fingerprints", tuple(v.lower() for v in self.suppress_fingerprints))

    @classmethod
    def load(cls, path: str):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Cannot read scan configuration as UTF-8 JSON") from exc
        if not isinstance(data, dict) or set(data) - {"exclude", "disabled_rules", "suppress_fingerprints", "custom_rules"}:
            raise ValueError("Configuration must be an object with supported policy keys only")
        return cls(**data)

    def suppresses(self, finding) -> bool:
        return finding.rule_id in self.disabled_rules or finding.fingerprint in self.suppress_fingerprints
