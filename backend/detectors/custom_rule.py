"""Bounded custom signatures built from an escaped prefix and alphabet."""
from dataclasses import dataclass
import re

from backend.detectors.finding import Severity
from backend.detectors.pattern_registry import PatternDefinition


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    prefix: str
    alphabet: str = 'alnum'
    min_length: int = 20
    max_length: int = 128
    severity: str = 'high'
    suffix: str = ''
    paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    minimum_entropy: float = 0.0

    def __post_init__(self):
        if not isinstance(self.rule_id, str) or not re.fullmatch(r'[a-z][a-z0-9_]{2,63}', self.rule_id):
            raise ValueError('Custom rule_id must be 3-64 lowercase letters, digits, or underscores')
        if not isinstance(self.prefix, str) or not 2 <= len(self.prefix) <= 64 or not self.prefix.isascii() or any(c.isspace() or ord(c)<32 or ord(c)>126 for c in self.prefix):
            raise ValueError('Custom prefix must be 2-64 printable ASCII characters without spaces')
        if self.alphabet not in ('alnum', 'hex', 'base64url', 'base64'):
            raise ValueError('Custom alphabet must be alnum, hex, base64url, or base64')
        if type(self.min_length) is not int or type(self.max_length) is not int or not 4 <= self.min_length <= self.max_length <= 2048:
            raise ValueError('Custom suffix length must satisfy 4 <= min_length <= max_length <= 2048')
        if self.severity not in {item.value for item in Severity}:
            raise ValueError('Invalid custom severity')
        if not isinstance(self.suffix, str) or len(self.suffix) > 64 or not self.suffix.isascii() or any(ord(c)<32 or ord(c)>126 for c in self.suffix):
            raise ValueError('Custom suffix must be at most 64 printable ASCII characters')
        for name in ('paths', 'exclude_paths', 'keywords'):
            values = getattr(self, name)
            if not isinstance(values, (list, tuple)) or len(values)>50 or any(not isinstance(v,str) or not 1<=len(v)<=256 for v in values):
                raise ValueError(f'{name} must contain at most 50 nonempty strings of at most 256 characters')
            object.__setattr__(self, name, tuple(values))
        if type(self.minimum_entropy) not in (float,int) or not 0 <= self.minimum_entropy <= 8:
            raise ValueError('minimum_entropy must be between 0 and 8')

    def pattern(self):
        alphabet = {'alnum':'A-Za-z0-9', 'hex':'A-Fa-f0-9', 'base64url':'A-Za-z0-9_-', 'base64':'A-Za-z0-9+/='}[self.alphabet]
        expression = rf'(?<![A-Za-z0-9_]){re.escape(self.prefix)}[{alphabet}]{{{self.min_length},{self.max_length}}}{re.escape(self.suffix)}(?![{alphabet}])'
        return PatternDefinition(self.rule_id, 'custom_credential', expression, Severity(self.severity), 'User-defined bounded signature', custom=True,
                                 paths=self.paths, exclude_paths=self.exclude_paths, keywords=self.keywords, minimum_entropy=self.minimum_entropy)
