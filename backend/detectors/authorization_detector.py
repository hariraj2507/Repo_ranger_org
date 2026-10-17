"""Bounded authorization literals and NTLM authenticate-response detection.

NTLM negotiate/challenge messages are intentionally excluded: they are not
password-derived authenticate responses. No message is replayed or verified.
"""
import base64
import re
import struct
from pathlib import PurePosixPath

from .candidate import DetectionCandidate
from .entropy_detector import EntropyDetector
from .finding import Severity
from .literal_password_detector import LiteralPasswordDetector

RULE_IDS = frozenset({'ntlm_authenticate', 'authorization_literal'})


def ntlm_authenticate(value):
    """Recognize a complete type-three message with bounded response buffers."""
    try:
        data = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
        if len(data) < 64 or data[:8] != b'NTLMSSP\0' or struct.unpack_from('<I', data, 8)[0] != 3:
            return False
        # Six security buffers: LM, NT, domain, user, workstation, session key.
        lengths = []
        for at in range(12, 60, 8):
            length, capacity, offset = struct.unpack_from('<HHI', data, at)
            if length > capacity or (length and (offset < 64 or offset + length > len(data))):
                return False
            lengths.append(length)
        nt_length, _, nt_offset = struct.unpack_from('<HHI', data, 20)
        return (nt_length >= 24 and bool(lengths[3])
                and any(data[nt_offset:nt_offset + nt_length]))
    except (ValueError, struct.error):
        return False


class AuthorizationDetector:
    _NTLM = re.compile(r'(?<![A-Za-z0-9+/])TlRMTVNTUA[A-Za-z0-9+/]{74,8192}={0,2}(?![A-Za-z0-9+/=])')
    _HEADER = re.compile(r'''(?i)(?<![\w.-])["']?(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?P<scheme>Basic|Bearer)[ \t]+(?P<value>[A-Za-z0-9_./+=-]{4,8192})(?![\w./+=-])''')
    _USER_OPTION = re.compile(r'''(?<![\w-])(?:--(?:proxy-)?user(?:=|[ \t]+)|-[uU][ \t]*)(?:"(?P<double>[^"\r\n]{3,2048})"|'(?P<single>[^'\r\n]{3,2048})'|(?P<bare>[^\s"'`;$|<>]{3,2048}))''')
    _CONFIG_USER = re.compile(r'''(?im)^\s*(?:proxy-)?user\s*=\s*(?:"(?P<double>[^"\r\n]{3,2048})"|'(?P<single>[^'\r\n]{3,2048})'|(?P<bare>[^\s"'`;$|<>]{3,2048}))''')

    def detect(self, text_file):
        return tuple(candidate.to_finding() for candidate in self.detect_candidates(text_file))

    def detect_candidates(self, text_file):
        text = text_file.text
        path = text_file.metadata.relative_path
        candidates = []
        def add(value, at, rule='authorization_literal', category='authorization_material'):
            line = text.count('\n', 0, at) + 1
            candidates.append(DetectionCandidate(detector='contextual', rule_id=rule,
                category=category, severity=Severity.MEDIUM, file_path=path,
                line_start=line, line_end=line, matched_value=value))
        for match in self._NTLM.finditer(text):
            if ntlm_authenticate(match.group()):
                add(match.group(), match.start(), 'ntlm_authenticate', 'authentication_response')
        for match in self._HEADER.finditer(text):
            value = match.group('value')
            if match.group('scheme').lower() == 'basic':
                try:
                    decoded = base64.b64decode(value + '=' * (-len(value) % 4), validate=True).decode('utf-8')
                except (ValueError, UnicodeError):
                    continue
                user, separator, password = decoded.partition(':')
                if not separator or not user or not LiteralPasswordDetector.literal(password):
                    continue
            elif (len(value) < 12 or EntropyDetector.shannon_entropy(value) < 3.5
                  or not LiteralPasswordDetector.literal(value)):
                continue
            add(value, match.start('value'))
        basename = PurePosixPath(path.replace('\\', '/')).name.lower()
        for pattern in (self._USER_OPTION, self._CONFIG_USER):
            for match in pattern.finditer(text):
                prefix = text[max(0, match.start() - 1024):match.start()]
                curl_config = basename in {'.curlrc', '_curlrc', 'curl.conf'}
                if pattern is self._CONFIG_USER:
                    if not curl_config:
                        continue
                elif not curl_config and not re.search(r'(?i)\b(?:curl|wget)\b[^\r\n]*$|<command>[^<]*$', prefix):
                    continue
                group = next(name for name in ('double', 'single', 'bare') if match.group(name) is not None)
                user, separator, password = match.group(group).partition(':')
                if user and separator and LiteralPasswordDetector.literal(password):
                    add(password, match.start(group) + len(user) + 1, category='password')
        return tuple(candidates)
