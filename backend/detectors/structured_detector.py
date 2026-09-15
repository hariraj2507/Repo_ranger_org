"""Bounded structural detection for signed JWTs and private JWK material.

RFC 7519 and RFC 7518. Parsing never verifies signatures or contacts issuers.
"""
import ast
import base64
import json
import re
from .candidate import DetectionCandidate
from .finding import Severity

RULE_IDS = frozenset({'jwt', 'private_jwk'})


def decode_segment(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def strict_object(value):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('Nonfinite JSON number')
    result = json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError('Object required')
    return result


def jwk_object(value):
    try:
        return strict_object(value)
    except ValueError:
        # Support flat JavaScript/Python literal objects without executing code.
        normalized = re.sub(r'([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:', lambda m:m[1]+json.dumps(m[2])+':', value)
        node = ast.parse(normalized, mode='eval').body
        if not isinstance(node, ast.Dict):
            raise ValueError('Literal object required')
        keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value,str)]
        if len(keys) != len(node.keys) or len(set(keys)) != len(keys):
            raise ValueError('Unique literal keys required')
        result = ast.literal_eval(node)
        if not isinstance(result,dict):
            raise ValueError('Object required')
        return result


class StructuredDetector:
    _JWT = re.compile(r'(?<![\w.-])[A-Za-z0-9_-]{4,2048}\.[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{16,2048}(?![\w.-])')
    _OBJECT = re.compile(r'\{[^{}]{1,16384}\}')
    _KEY_VALUE = re.compile(r'''[,{]\s*["']?(?P<field>d|k)["']?\s*:\s*["'](?P<value>[A-Za-z0-9_-]{16,8192})["']''')

    def detect(self, text_file):
        return tuple(c.to_finding() for c in self.detect_candidates(text_file))

    def detect_candidates(self, text_file):
        text = text_file.text
        candidates = []
        def add(value, position, rule, category, severity):
            line = text.count('\n', 0, position) + 1
            candidates.append(DetectionCandidate(detector='regex', rule_id=rule, category=category,
                severity=severity, file_path=text_file.metadata.relative_path,
                line_start=line, line_end=line, matched_value=value))
        for match in self._JWT.finditer(text):
            try:
                header, payload, signature = match.group().split('.')
                header = strict_object(decode_segment(header))
                strict_object(decode_segment(payload))
                algorithm = header.get('alg')
                if not isinstance(algorithm, str) or not algorithm or algorithm.lower() == 'none' or len(decode_segment(signature)) < 16:
                    continue
            except (ValueError, UnicodeError, RecursionError, SyntaxError, TypeError):
                continue
            add(match.group(), match.start(), 'jwt', 'signed_token', Severity.MEDIUM)
        for match in self._OBJECT.finditer(text):
            if 'kty' not in match.group():
                continue
            try:
                obj = jwk_object(match.group())
                kty = obj.get('kty')
                field = 'k' if kty == 'oct' else 'd' if kty in ('RSA','EC') else None
                value = obj.get(field) if field else None
                if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,8192}', value) or len(decode_segment(value)) < 16:
                    continue
                if kty == 'RSA' and not all(isinstance(obj.get(k), str) and obj[k] for k in ('n','e')):
                    continue
                if kty == 'EC' and not all(isinstance(obj.get(k), str) and obj[k] for k in ('crv','x','y')):
                    continue
            except (ValueError, UnicodeError, RecursionError, SyntaxError, TypeError):
                continue
            for part in self._KEY_VALUE.finditer(match.group()):
                if part.group('field') == field and part.group('value') == value:
                    add(value, match.start()+part.start('value'), 'private_jwk', 'private_key', Severity.HIGH)
                    break
        return tuple(candidates)
