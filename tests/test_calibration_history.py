import json
import unittest
from backend.ml.training import calibrate,metrics,split_sources
from backend.history.blob_scanner import BlobScanner
from pathlib import Path
import subprocess

class CalibrationAndHistoryTests(unittest.TestCase):
    def test_source_splits_disjoint_and_order_independent(self):
        rows=[{'group':f'repo{i}','label':i%2,'features':{'severity':.5}} for i in range(20)]
        splits=split_sources(rows)
        groups=[{r['group'] for r in s} for s in splits]
        self.assertFalse(groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2])
        self.assertEqual(groups,[{r['group'] for r in s} for s in split_sources(list(reversed(rows)))])

    def test_calibration_preserves_ranking_and_produces_bins(self):
        rows=[{'group':'fixture','label':i%2,'features':{'severity':i%2}} for i in range(20)]
        weights,calibration=calibrate(rows,{'bias':-.1,'severity':.2})
        self.assertGreater(calibration['scale'],0)
        self.assertGreater(weights['severity'],0)
        result=metrics(rows,weights)
        self.assertEqual(sum(b['samples'] for b in result['reliability_bins']),20)
        self.assertLess(result['brier'],metrics(rows,{'bias':-.1,'severity':.2})['brier'])

    def test_single_label_calibration_rejected(self):
        with self.assertRaises(ValueError):
            calibrate([{'group':'fixture','label':1,'features':{}}],{'bias':0})

    def test_new_password_detection_in_historical_blob(self):
        value=b'password=h7Rk92za'
        def run(command,**kwargs):
            return subprocess.CompletedProcess(command,0,str(len(value)).encode() if '-s' in command else value,b'')
        result=BlobScanner(runner=run).scan(Path('.'),'fixture-blob','settings.env')
        self.assertEqual(len(result.findings),1)
        self.assertEqual(result.analyses[0].context.symbol_kind,'assignment')
        self.assertNotIn('h7Rk92za',repr(result))

    def test_custom_scope_applies_to_historical_blobs(self):
        from backend.analysis_pipeline import FindingAnalyzer
        from backend.detectors.custom_rule import CustomRule
        from backend.detectors.regex_detector import RegexDetector
        from backend.detectors.pattern_registry import PatternRegistry
        value=b'token=co_aB3dE6gH!'
        def run(command,**kwargs):
            return subprocess.CompletedProcess(command,0,str(len(value)).encode() if '-s' in command else value,b'')
        rule=CustomRule('company_token','co_',min_length=8,max_length=8,suffix='!',paths=['config/*'],keywords=['token'])
        analyzer=FindingAnalyzer(detectors=(RegexDetector(PatternRegistry([rule.pattern()])),))
        scanner=BlobScanner(runner=run,analyzer=analyzer)
        self.assertEqual(len(scanner.scan(Path('.'),'blob','config/app.env').findings),1)
        self.assertFalse(scanner.scan(Path('.'),'blob','src/app.env').findings)

    def test_independent_model_evaluation_rejects_overlap(self):
        from benchmarks.evaluate_model import evaluate
        root=Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(ValueError,'overlap'):
            evaluate(root/'benchmarks/external-triage.jsonl',root/'models/creddata-experimental.json')
