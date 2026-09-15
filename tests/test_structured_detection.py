import base64,json,unittest
from tests.test_improvements import repo
from backend.detectors.detection_engine import DetectionEngine
from backend.config import ScanConfig

def segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')

class StructuralTests(unittest.TestCase):
    def scan(self,source):return DetectionEngine().scan(repo(source)).findings
    def test_signed_jwt_and_duplicate_suppression(self):
        value=segment({'alg':'HS256'})+'.'+segment({'sub':'fixture','exp':1})+'.'+segment('synthetic-signature-material')
        result=self.scan('TOKEN="'+value+'"')
        self.assertEqual(len(result),1)
        self.assertEqual(result[0].rule_id,'jwt')
        self.assertNotIn(value,repr(result))
    def test_unstructured_and_unsigned_values_rejected(self):
        self.assertFalse(self.scan('aaaabbbb.ccccdddd.eeeeffffgggghhhh'))
        self.assertFalse(self.scan(segment({'alg':'none'})+'.'+segment({'sub':'fixture'})+'.'+segment('not-a-signature')))
    def test_private_and_public_jwk(self):
        key=segment('synthetic-private-key-bytes-123')
        private={'kty':'RSA','n':key,'e':'AQAB','d':key}
        self.assertEqual(self.scan(json.dumps(private))[0].rule_id,'private_jwk')
        del private['d']
        self.assertFalse(self.scan(json.dumps(private)))
        self.assertEqual(len(self.scan(json.dumps({'kty':'oct','k':key}))),1)
    def test_duplicate_jwk_members_rejected(self):
        key=segment('synthetic-private-key-bytes-123')
        self.assertFalse(self.scan('{"kty":"oct","k":"'+key+'","k":"other"}'))
    def test_command_literals(self):
        for source in ('curl --user admin:h7Rk92za https://example.invalid', 'mysql --password="h7Rk92za"', 'ConvertTo-SecureString "h7Rk92za" -AsPlainText -Force', 'ConvertTo-SecureString -String "h7Rk92za" -AsPlainText'):
            with self.subTest(source=source):self.assertEqual(len(self.scan(source)),1)
    def test_command_references_and_encrypted_powershell(self):
        for source in ('curl --user admin:$PASSWORD https://example.invalid', 'ConvertTo-SecureString "h7Rk92za"', 'ConvertTo-SecureString $PASSWORD -AsPlainText'):
            self.assertFalse(self.scan(source))
    def test_structural_rules_are_configurable_and_reserved(self):
        self.assertEqual(ScanConfig(disabled_rules=['jwt','private_jwk']).disabled_rules,('jwt','private_jwk'))
        with self.assertRaises(ValueError):ScanConfig(custom_rules=[{'rule_id':'jwt','prefix':'xy_'}])

    def test_username_without_password_not_a_secret(self):
        self.assertFalse(self.scan('curl --user VeryLongUser123 https://example.invalid'))

    def test_jwt_does_not_gain_credential_validity_confidence(self):
        from backend.analysis_pipeline import FindingAnalyzer
        from backend.ml.feature_extractor import FeatureExtractor
        value=segment({'alg':'HS256'})+'.'+segment({'sub':'fixture'})+'.'+segment('synthetic-signature-material')
        item=FindingAnalyzer().analyze(repo(value))[0]
        features=FeatureExtractor().extract(item.finding,item.validation,item.context)
        self.assertEqual(features.value('validator_valid'),0)
        self.assertEqual(features.value('known_signature'),0)
        self.assertEqual(features.value('jwt_structure'),1)

    def test_all_positive_model_fails_gate_even_with_good_brier(self):
        from backend.ml.training import metrics,quality_gate
        rows=[{'features':{},'label':int(i<90),'group':'fixture'} for i in range(100)]
        baseline=metrics(rows,{'bias':-1})
        learned=metrics(rows,{'bias':2})
        self.assertLess(learned['brier'],baseline['brier'])
        gate=quality_gate(baseline,learned)
        self.assertFalse(gate['passed'])
        self.assertIn('classifier_predicts_only_one_class',gate['reasons'])

    def test_javascript_and_python_jwk_literals(self):
        key=segment('synthetic-private-key-bytes-123')
        for source in ('{kty: "oct", k: "'+key+'"}', "{'kty': 'oct', 'k': '"+key+"'}"):
            self.assertEqual(self.scan(source)[0].rule_id,'private_jwk')
        self.assertFalse(self.scan('{kty:"oct", k: makeSecret()}'))
        self.assertFalse(self.scan('{kty:"oct", k:"'+key+'", k:"other"}'))

    def test_structural_rules_flow_through_cli_and_can_be_disabled(self):
        import tempfile,contextlib,io
        from pathlib import Path
        from backend.application.cli import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'key.json').write_text(json.dumps({'kty':'oct','k':segment('synthetic-private-key-bytes-123')}))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(main([str(root),'--format','json']),0)
            report=json.loads(output.getvalue())
            self.assertEqual(report['findings'][0]['rule_id'],'private_jwk')
            (root/'policy.json').write_text(json.dumps({'disabled_rules':['private_jwk']}))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(main([str(root),'--format','json','--config',str(root/'policy.json')]),0)
            self.assertEqual(json.loads(output.getvalue())['summary']['finding_count'],0)

    def test_readiness_does_not_confuse_test_success_with_accuracy(self):
        from benchmarks.readiness import assess
        result=assess({'counts':{'annotations_T':200,'annotations_F':200},'selected_repositories':10,'positive_annotation_recall':.38,'labeled_alert_precision':.91})
        self.assertFalse(result['passed'])
        self.assertIn('positive_annotation_recall_below_80_percent',result['reasons'])
