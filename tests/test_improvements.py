from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from backend.scanner.models import FileMetadata,NormalizedTextFile,ParsedRepository,RepositoryMetadata
from backend.detectors.detection_engine import DetectionEngine
from backend.detectors.custom_rule import CustomRule
from backend.detectors.pattern_registry import PatternRegistry
from backend.detectors.regex_detector import RegexDetector
from backend.analysis_pipeline import FindingAnalyzer
from backend.ml.feature_extractor import FeatureExtractor

def file(source,path='settings.env'):
    return NormalizedTextFile(FileMetadata(path,len(source.encode()),datetime.now(timezone.utc),'utf-8'),source)

def repo(source,path='settings.env'):
    return ParsedRepository(RepositoryMetadata('fixture','fixture'),(file(source,path),))

class ImprovementTests(unittest.TestCase):
    def test_supported_password_syntax(self):
        for source in ('password=h7Rk92za','<password>h7Rk92za</password>', 'setPassword("h7Rk92za")', 'postgresql://app:h7Rk92za@localhost/db'):
            with self.subTest(source=source):
                findings=DetectionEngine().scan(repo(source)).findings
                self.assertEqual(len(findings),1)
                self.assertNotIn('h7Rk92za',repr(findings))

    def test_password_references_and_placeholders(self):
        for source in ('password=process.env.DB_PASSWORD','password="password123"','<password>changeme123</password>', 'setPassword(getPassword())','postgresql://app:${DB_PASSWORD}@localhost/db'):
            self.assertFalse(DetectionEngine().scan(repo(source)).findings)
        self.assertFalse(DetectionEngine().scan(repo('password=otherPassword42','settings.py')).findings)

    def test_custom_rule_scope_suffix_keywords_entropy(self):
        rule=CustomRule('company_token','co_',min_length=8,max_length=8,suffix='!',paths=['config/*'],exclude_paths=['config/example*'],keywords=['token'],minimum_entropy=2)
        detector=RegexDetector(PatternRegistry([rule.pattern()]))
        self.assertEqual(len(detector.detect(file('token=co_aB3dE6gH!','config/prod.env'))),1)
        for source,path in [('token=co_aB3dE6gH!','config/example.env'),('token=co_aB3dE6gH!','src/app.py'),('value=co_aB3dE6gH!','config/prod.env'),('token=co_aaaaaaaa!','config/prod.env'),('token=co_aB3dE6gH','config/prod.env')]:
            self.assertFalse(detector.detect(file(source,path)))

    def test_custom_rule_invalid_configuration(self):
        for options in ({'minimum_entropy':float('nan')},{'paths':'config/*'},{'keywords':['']},{'suffix':'\n'}):
            with self.assertRaises(ValueError):
                CustomRule('company_token','co_',**options)

    def test_context_public_identifier_is_evidence_not_suppression(self):
        source='VITE_PUBLISHABLE_KEY="q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"'
        result=FindingAnalyzer().analyze(repo(source))
        self.assertEqual(len(result),1)
        item=result[0]
        self.assertIn('public_identifier_context',item.context.evidence)
        self.assertEqual(item.context.symbol_kind,'assignment')
        self.assertEqual(FeatureExtractor().extract(item.finding,item.validation,item.context).value('public_identifier_context'),1)
        signed=FindingAnalyzer().analyze(repo('PUBLIC_KEY="ghp_'+'A1b2C3d4'*5+'"'))[0]
        self.assertEqual(FeatureExtractor().extract(signed.finding,signed.validation,signed.context).value('public_identifier_context'),0)

    def test_comment_context_does_not_drop_signature(self):
        result=FindingAnalyzer().analyze(repo('# ghp_'+'A1b2C3d4'*5))
        self.assertEqual(len(result),1)
        self.assertIn('comment_context',result[0].context.evidence)
