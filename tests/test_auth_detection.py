import base64
import unittest
from tests.test_accuracy import make_file
from backend.detectors.detection_engine import DetectionEngine
from backend.detectors.entropy_detector import EntropyDetector
from backend.scanner.models import ParsedRepository, RepositoryMetadata


class AuthenticationDetectionTests(unittest.TestCase):
    def scan(self, source):
        return DetectionEngine().scan(ParsedRepository(RepositoryMetadata('test', 'test'), (make_file(source),))).findings

    def test_short_complex_quoted_password(self):
        self.assertEqual(len(self.scan('dbPassword = "n8V!q2Lz5xRa"')), 1)

    def test_references_and_placeholders(self):
        for value in ('getPasswordValue', 'process.env.DB_PASSWORD', 'ExamplePassword123!', 'your_password_123', 'password'):
            with self.subTest(value=value):
                self.assertFalse(self.scan('password = ' + value))
        self.assertFalse(self.scan('password = "Example123!"'))

    def test_basic_header_and_redaction(self):
        value = base64.b64encode(b'admin:n8V!q2Lz5xRa').decode()
        findings = self.scan('Authorization: Basic ' + value)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(value, repr(findings))
        self.assertNotIn('n8V!q2Lz5xRa', repr(findings))

    def test_basic_requires_credentials_and_complex_password(self):
        for value in (b'not-a-credential', b'admin:password', b':n8V!q2Lz5xRa'):
            self.assertFalse(self.scan('Authorization: Basic ' + base64.b64encode(value).decode()))
        self.assertFalse(self.scan('Authorization: Basic invalid===='))

    def test_bearer_yaml_and_quoted_header_deduplicate(self):
        token = 'q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB'
        for source in ('Authorization: Bearer ' + token, '"Authorization": "Bearer ' + token + '"'):
            with self.subTest(source=source):
                findings = self.scan(source)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].line_start, 1)

    def test_bearer_environment_reference(self):
        self.assertFalse(self.scan('Authorization: Bearer process.env.MY_COMPLEX_APPLICATION_API_TOKEN'))
