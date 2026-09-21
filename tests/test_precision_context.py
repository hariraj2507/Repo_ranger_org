import unittest
from tests.test_improvements import repo
from backend.analysis_pipeline import FindingAnalyzer
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.classifier import CandidateClassifier
from backend.ml.confidence_engine import ConfidenceEngine
from backend.detectors.detection_engine import DetectionEngine

class PrecisionContextTests(unittest.TestCase):
    def score(self,source,path):
        items=FindingAnalyzer().analyze(repo(source,path))
        self.assertEqual(len(items),1)
        item=items[0];features=FeatureExtractor().extract(item.finding,item.validation,item.context)
        return item,ConfidenceEngine().assess(CandidateClassifier().classify(features),features)

    def test_test_scope_retains_candidate_with_lower_confidence(self):
        source='password="hunter2"'
        production,normal=self.score(source,'app.py')
        test,reduced=self.score('def test_login():\n    '+source,'app.py')
        self.assertEqual(test.finding.fingerprint,production.finding.fingerprint)
        self.assertIn('test_context',test.context.evidence)
        self.assertLess(reduced.score,normal.score)
        self.assertTrue(any('test function' in r for r in reduced.rationale))

    def test_test_and_documentation_filenames_retain_candidates(self):
        source='password="hunter2"'
        _,normal=self.score(source,'app.py')
        for path in ('test_login.py','login_test.go','login.spec.ts','login.test.tsx','README.md','.env.example'):
            with self.subTest(path=path):
                _,reduced=self.score(source,path)
                self.assertLess(reduced.score,normal.score)

    def test_unquoted_code_reference_is_not_an_entropy_literal(self):
        value='StrongApplicationPasswordProvider123456'
        item,reference=self.score('password='+value,'app.py')
        self.assertIn('reference_context',item.context.evidence)
        _,literal=self.score('password="'+value+'"','app.py')
        self.assertLess(reference.score,literal.score)
        self.assertTrue(DetectionEngine().scan(repo('password='+value,'app.env')).findings)
        self.assertTrue(DetectionEngine().scan(repo('password="'+value+'"','app.py')).findings)

    def test_similarly_named_production_function_is_not_a_test(self):
        item,_=self.score('def latest_password():\n    password="hunter2"','app.py')
        self.assertNotIn('test_context',item.context.evidence)

    def test_powershell_weak_password_requires_explicit_plaintext(self):
        for source in ('ConvertTo-SecureString "abc" -AsPlainText -Force', "ConvertTo-SecureString -String 'abc' -AsPlainText"):
            self.assertEqual(len(DetectionEngine().scan(repo(source,'setup.ps1')).findings),1)
        self.assertFalse(DetectionEngine().scan(repo('ConvertTo-SecureString "abc"','setup.ps1')).findings)

    def test_public_and_mock_context_match_the_actual_candidate(self):
        item,_=self.score('expected_password="hunter2"','app.py')
        self.assertIn('test_value_context',item.context.evidence)
        item,_=self.score('const publicKey = "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"','app.ts')
        self.assertIn('public_identifier_context',item.context.evidence)

    def test_public_field_does_not_penalize_other_value_on_same_line(self):
        items=FindingAnalyzer().analyze(repo('public_key="q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"; password="hunter2"','app.py'))
        self.assertEqual(len(items),2)
        literal=next(item for item in items if item.finding.rule_id=='hardcoded_password')
        self.assertNotIn('public_identifier_context',literal.context.evidence)
        public=next(item for item in items if item.finding.rule_id=='high_entropy_token')
        self.assertIn('public_identifier_context',public.context.evidence)
