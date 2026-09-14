"""Custom signature validation and calibrated repository scoring."""
from datetime import datetime, timezone
import unittest
from backend.config import ScanConfig
from backend.analysis_pipeline import FindingAnalyzer
from backend.detectors.pattern_registry import PatternRegistry
from backend.detectors.regex_detector import RegexDetector
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata
from backend.engine.risk_engine import RiskEngine, RiskLevel
from backend.engine.score_engine import ScoreEngine
from backend.ml.confidence_engine import ConfidenceResult, ConfidenceLevel
from backend.detectors.finding import Finding, Severity


class CustomAndScoreTests(unittest.TestCase):
    def test_custom_signature_matches_whole_value_and_redacts(self):
        config = ScanConfig(custom_rules=[dict(rule_id='company_key', prefix='acme_', min_length=8, max_length=16)])
        registry = PatternRegistry([config.custom_rules[0].pattern()])
        value = 'acme_Ab3Def78'
        source = f'api_key="{value}"'
        repository = ParsedRepository(RepositoryMetadata('test', 'test'), (
            NormalizedTextFile(FileMetadata('app.py', len(source), datetime.now(timezone.utc), 'utf-8'), source),))
        analyzed = FindingAnalyzer(detectors=(RegexDetector(registry),)).analyze(repository)
        self.assertEqual(analyzed[0].finding.detector, 'custom')
        self.assertEqual(analyzed[0].finding.rule_id, 'company_key')
        self.assertNotIn(value, str(analyzed))
        self.assertIsNone(analyzed[0].validation)
        self.assertEqual(analyzed[0].context.symbol_kind, 'assignment')

    def test_invalid_or_unbounded_rules_are_rejected(self):
        invalid = [dict(rule_id='company_key', prefix='acme_', max_length=5000),
                   dict(rule_id='aws_access_key_id', prefix='x_'),
                   dict(rule_id='company_key', prefix='acme_', pattern='(a+)+$'),
                   dict(rule_id='company_key', prefix='acme_', alphabet='regex'),
                   dict(rule_id='company_key', prefix='acme_', min_length=True)]
        for rule in invalid:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                ScanConfig(custom_rules=[rule])

    def test_candidate_volume_cannot_promote_medium_risk(self):
        finding = Finding.from_match(detector='entropy', rule_id='high_entropy_token', category='possible_secret',
            severity=Severity.MEDIUM, file_path='config.py', line_start=1, line_end=1, matched_value='synthetic')
        item = RiskEngine().assess(finding, ConfidenceResult(.4, ConfidenceLevel.LOW, ()))
        self.assertEqual(item.level, RiskLevel.MEDIUM)
        single = ScoreEngine().calculate([item])
        many = ScoreEngine().calculate([item] * 10000)
        self.assertEqual(single.score, many.score)
        self.assertEqual(many.level, RiskLevel.MEDIUM)
