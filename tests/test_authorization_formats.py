import base64
import struct
import unittest

from backend.analysis_pipeline import FindingAnalyzer
from backend.config import ScanConfig
from backend.detectors.authorization_detector import AuthorizationDetector, ntlm_authenticate
from backend.detectors.detection_engine import DetectionEngine
from tests.test_improvements import repo


def message(kind=3, response=b'\x71' * 24):
    data = bytearray(64)
    data[:8] = b'NTLMSSP\0'
    struct.pack_into('<I', data, 8, kind)
    struct.pack_into('<HHI', data, 20, len(response), len(response), 64)
    struct.pack_into('<HHI', data, 36, 4, 4, 64 + len(response))
    return base64.b64encode(data + response + b'user').decode()


class AuthorizationFormatTests(unittest.TestCase):
    def scan(self, text, path='auth.txt'):
        return DetectionEngine().scan(repo(text, path)).findings

    def test_authenticate_material_is_detected_and_redacted(self):
        value = message()
        result = self.scan('Authorization: NTLM ' + value)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].rule_id, 'ntlm_authenticate')
        self.assertNotIn(value, repr(result))
        analyzed = FindingAnalyzer().analyze(repo('"' + value + '"'))
        self.assertEqual(len(analyzed), 1)

    def test_public_negotiate_and_challenge_are_excluded(self):
        for kind in (1, 2, 4):
            self.assertFalse(self.scan('Authorization: NTLM ' + message(kind)))

    def test_truncated_out_of_bounds_and_zero_responses_are_excluded(self):
        value = base64.b64decode(message())
        bad = bytearray(value)
        struct.pack_into('<I', bad, 24, 65535)
        for data in (value[:63], bad):
            self.assertFalse(ntlm_authenticate(base64.b64encode(data).decode()))
        self.assertFalse(self.scan(message(response=b'\0' * 24)))

    def test_proxy_basic_short_password_and_bearer_literals(self):
        value = base64.b64encode(b'u:pw').decode()
        for header in ('Authorization', 'Proxy-Authorization'):
            self.assertEqual(len(self.scan(header + ': Basic ' + value)), 1)
        token = 'q7Lx9Aa2Vm3Kp8Nr'
        self.assertEqual(len(self.scan('Proxy-Authorization: Bearer ' + token)), 1)
        self.assertFalse(self.scan('Proxy-Authorization: Bearer process.env.TOKEN'))

    def test_curl_attached_equal_proxy_and_fixture_command_options(self):
        for source in ('curl -uadmin:abc https://example.invalid',
                       'curl --user=admin:abc https://example.invalid',
                       'curl -U "admin:correct horse" https://example.invalid',
                       '<command>\n--proxy-user admin:abc\n</command>'):
            with self.subTest(source=source):
                findings = self.scan(source)
                self.assertEqual(len(findings), 1)
                self.assertNotIn('correct horse', repr(findings))

    def test_curl_config_and_dynamic_or_unrelated_arguments(self):
        self.assertEqual(len(self.scan('user = "admin:abc"', '.curlrc')), 1)
        self.assertFalse(self.scan('user = "admin:abc"', 'app.ini'))
        self.assertFalse(self.scan('node -u admin:abc'))
        self.assertFalse(self.scan('curl --user=admin:${PASSWORD}'))
        self.assertFalse(self.scan('curl --user=admin'))

    def test_rule_ids_can_be_disabled_but_not_replaced(self):
        ScanConfig(disabled_rules=('ntlm_authenticate', 'authorization_literal'))
        with self.assertRaises(ValueError):
            ScanConfig(custom_rules=({'rule_id': 'ntlm_authenticate', 'prefix': 'demo_',
                                    'alphabet': 'alnum', 'min_length': 16, 'max_length': 32},))
