import base64,unittest
from tests.test_improvements import repo
from backend.detectors.detection_engine import DetectionEngine

class PasswordLiteralTests(unittest.TestCase):
    def scan(self,source,path='config.py'):
        return DetectionEngine().scan(repo(source,path)).findings
    def test_weak_passwords_are_still_literals(self):
        for value in ('password','password123','hunter2','abc','correct horse battery staple'):
            with self.subTest(value=value):self.assertEqual(len(self.scan('password="'+value+'"')),1)
    def test_reference_and_template_exclusions(self):
        for source in ('password=get_password()', 'password="${PASSWORD}"','password="your-password-here"','password="token" + suffix','password="process.env.PASSWORD"','password=""','password_hint="some text"'):
            with self.subTest(source=source):self.assertFalse(self.scan(source))
    def test_config_literals_and_code_identifiers(self):
        self.assertTrue(self.scan('password=hunter2','.env.local'))
        self.assertFalse(self.scan('password=otherPassword','config.py'))
    def test_basic_password_need_not_be_random(self):
        value=base64.b64encode(b'admin:password').decode()
        self.assertEqual(len(self.scan('Authorization: Basic '+value)),1)
    def test_strong_candidates_remain_deduplicated(self):
        self.assertEqual(len(self.scan('password="q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"')),1)

    def test_literal_password_syntax_does_not_require_entropy(self):
        for source in ('<password>abc</password>','setPassword("abc")','postgresql://user:abc@localhost/db', "CREATE USER person IDENTIFIED BY 'abc'", "ALTER ROLE person WITH PASSWORD 'abc'", "config['password'] = 'abc'", "'password' => 'abc'",'curl --user admin:abc https://example.invalid'):
            with self.subTest(source=source):self.assertEqual(len(self.scan(source)),1)
    def test_masked_values_and_dynamic_commands(self):
        self.assertFalse(self.scan('password="****************"'))
        self.assertFalse(self.scan('curl --user admin:$PASSWORD https://example.invalid'))

    def test_private_key_header_variants(self):
        for kind in ('DSA', 'ENCRYPTED'):
            findings=self.scan('-----BEGIN '+kind+' PRIVATE KEY-----')
            self.assertEqual([f.rule_id for f in findings], ['private_key_block'])

    def test_analysis_pipeline_keeps_literal_redacted(self):
        from backend.analysis_pipeline import FindingAnalyzer
        finding=FindingAnalyzer().analyze(repo('password="hunter2"','config.py'))[0].finding
        self.assertEqual(finding.rule_id,'hardcoded_password')
        self.assertNotIn('hunter2',repr(finding))

    def test_config_and_format_expressions_are_not_passwords(self):
        for source in ('password: -', 'password: >', 'password: |', 'password: {{ vault.password }}', 'password: "#{settings.password}"', 'password: "%s"', 'password: "%02d"'):
            with self.subTest(source=source):
                self.assertFalse(self.scan(source,'settings.yaml'))
