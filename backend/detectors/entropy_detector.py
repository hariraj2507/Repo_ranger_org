"""Contextual entropy screening for credential-valued assignments."""
from __future__ import annotations

import math
import re
import base64
import binascii
from collections import Counter

from backend.scanner.models import NormalizedTextFile
from .candidate import DetectionCandidate
from .finding import Finding, Severity


class EntropyDetector:
    """Flag diverse literal values assigned to credential-related fields.

    Known signatures are handled independently by RegexDetector. Entropy alone
    cannot distinguish credentials from hashes, identifiers, or generated code.
    """

    _ASSIGNMENT = re.compile(
        r'''(?<![\w.-])["']?(?P<name>[A-Za-z_][\w.-]{0,127})["']?'''
        r'''(?:[ \t]*:[ \t]*(?:string|str)[ \t]*)?[ \t]*[:=][ \t\r\n]*'''
        r'''(?:"(?P<double>[^"\r\n]{1,2048})"|'(?P<single>[^'\r\n]{1,2048})'|'''
        r'''(?P<bare>[A-Za-z0-9_./+=:@%$!-]{1,2048})(?![A-Za-z0-9_./+=:@%$!-]))'''
    )
    _CREDENTIAL_WORDS = frozenset({
        'key', 'token', 'secret', 'password', 'passwd', 'pwd',
        'credential', 'credentials', 'authorization', 'jwt',
    })
    _VALUE = re.compile(r'[A-Za-z0-9_./+=:@%!-]+')
    _REFERENCES = ('process.env.', 'import.meta.env.', 'os.environ', 'os.getenv', 'env.')
    _AUTH_HEADER = re.compile(
        r'''(?i)(?<![\w.-])["']?authorization["']?\s*[:=]\s*["']?'''
        r'''(?P<scheme>Basic|Bearer)[ \t]+(?P<value>[A-Za-z0-9_./+=-]{8,2048})(?![\w./+=-])''')

    @classmethod
    def _password_literal(cls, name, value):
        words = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()
        if not set(re.split(r'[^a-z0-9]+', words)) & {'password', 'passwd', 'pwd'}:
            return False
        classes = sum(bool(re.search(pattern, value)) for pattern in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^\w\s]'))
        return (len(value) >= 12 and classes >= 3 and cls.shannon_entropy(value) >= 3.0
                and not re.search(r'(?i)example|placeholder|changeme|your[_-]|replace[_-]', value))

    def __init__(self, minimum_length: int = 20, minimum_entropy: float = 4.0) -> None:
        if minimum_length < 8:
            raise ValueError('minimum_length must be at least 8')
        if not 0.0 < minimum_entropy <= 8.0:
            raise ValueError('minimum_entropy must be between 0 and 8')
        self._minimum_length = minimum_length
        self._minimum_entropy = minimum_entropy

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())

    @classmethod
    def _credential_name(cls, name: str) -> bool:
        name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)
        return bool(set(re.split(r'[^a-z0-9]+', name.lower())) & cls._CREDENTIAL_WORDS)

    def detect(self, text_file: NormalizedTextFile) -> tuple[Finding, ...]:
        return tuple(candidate.to_finding() for candidate in self.detect_candidates(text_file))

    def detect_candidates(self, text_file: NormalizedTextFile) -> tuple[DetectionCandidate, ...]:
        candidates = []
        text = text_file.text
        for match in self._ASSIGNMENT.finditer(text):
            if not self._credential_name(match.group('name')):
                continue
            group = next(name for name in ('double', 'single', 'bare') if match.group(name) is not None)
            original = match.group(group)
            value = original.strip()
            if value.lower().startswith('bearer '):
                value = value[7:].strip()
            if (not self._VALUE.fullmatch(value) or '://' in value
                    or value.startswith(self._REFERENCES)):
                continue
            strong_password = group != 'bare' and self._password_literal(match.group('name'), value)
            if not strong_password and (len(value) < self._minimum_length
                    or self.shannon_entropy(value) < self._minimum_entropy):
                continue
            line = text.count('\n', 0, match.start(group)) + 1
            candidates.append(DetectionCandidate(
                detector='entropy', rule_id='high_entropy_token', category='possible_secret',
                severity=Severity.MEDIUM, file_path=text_file.metadata.relative_path,
                line_start=line, line_end=line, matched_value=value,
            ))
        for match in self._AUTH_HEADER.finditer(text):
            value = match.group('value')
            if value.startswith(self._REFERENCES):
                continue
            if match.group('scheme').lower() == 'basic':
                try:
                    decoded = base64.b64decode(value, validate=True).decode('utf-8')
                except (ValueError, UnicodeError, binascii.Error):
                    continue
                username, separator, password = decoded.partition(':')
                if not username or not separator or not self._password_literal('password', password):
                    continue
            elif len(value) < self._minimum_length or self.shannon_entropy(value) < self._minimum_entropy:
                continue
            line = text.count('\n', 0, match.start('value')) + 1
            candidates.append(DetectionCandidate(
                detector='entropy', rule_id='high_entropy_token', category='possible_secret',
                severity=Severity.MEDIUM, file_path=text_file.metadata.relative_path,
                line_start=line, line_end=line, matched_value=value))
        return tuple(candidates)
