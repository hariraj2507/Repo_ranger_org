"""Verify actual training, runtime integration, policy bounds and model identity."""
import json,tempfile,unittest
from pathlib import Path
from backend.ml.classifier import CandidateClassifier
from backend.ml.feature_extractor import FeatureVector
from backend.ml.confidence_engine import ConfidenceEngine
from backend.ml.training import load_rows
from backend.ml.tree_training import fit_trees
from backend.application.scan_orchestrator import ScanOrchestrator

class TrainedDefaultTests(unittest.TestCase):
    def test_training_learns_from_labels_deterministically(self):
        rows=[{'group':str(i),'label':int(i>=10),'features':{'severity':i/19}} for i in range(20)]
        trees=fit_trees(rows,2,rounds=30)
        self.assertEqual(trees,fit_trees(rows,2,rounds=30))
        model=CandidateClassifier({'bias':0},trees=trees)
        self.assertLess(model.classify(FeatureVector({'severity':0})).score,.5)
        self.assertGreater(model.classify(FeatureVector({'severity':1})).score,.5)

    def test_normal_scans_load_bundled_trained_trees(self):
        classifier=ScanOrchestrator()._classifier
        self.assertEqual(len(classifier._trees),100)
        self.assertTrue(classifier._existing_alerts_only)

    def test_guarded_default_preserves_class_and_risk_bands(self):
        root=Path(__file__).resolve().parents[1]
        rows=load_rows(root/'benchmarks/ml-v4/development.jsonl')
        model=CandidateClassifier.default();baseline=CandidateClassifier();engine=ConfidenceEngine()
        changed=0
        def band(confidence,severity,exposure):
            risk=min(1,.45*severity+.55*confidence+exposure)
            return 'critical' if risk>=.85 or (severity==1 and confidence>=.65) else 'high' if risk>=.65 else 'medium' if risk>=.4 else 'low'
        for row in rows:
            features=FeatureVector(row['features']);a=baseline.classify(features);b=model.classify(features)
            self.assertEqual(a.label,b.label)
            self.assertEqual(a.score>=.5,b.score>=.5)
            self.assertGreaterEqual(b.score,a.score)
            changed+=b.score>a.score
            ca=engine.assess(a,features).score;cb=engine.assess(b,features).score
            for exposure in (0,.08):self.assertEqual(band(ca,features.value('severity'),exposure),band(cb,features.value('severity'),exposure))
        self.assertGreater(changed,0,'Default must actually apply learned ranking scores')

    def test_model_identity_includes_tree_values_and_policy(self):
        a=CandidateClassifier({'bias':0},trees=[{'value':.1}])
        b=CandidateClassifier({'bias':0},trees=[{'value':.2}])
        c=CandidateClassifier({'bias':0},trees=[{'value':.1}],promotion_threshold=.8,existing_alerts_only=True)
        self.assertNotEqual(a.model_identity(),b.model_identity())
        self.assertNotEqual(a.model_identity(),c.model_identity())

    def test_loader_rejects_malformed_trees_and_policies(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'model.json'
            for tree in ({'value':float('nan')},{'value':True},{'value':21},
                         {'feature':[],'threshold':.5,'left':{'value':0},'right':{'value':0}}):
                path.write_text(json.dumps({'schema_version':4,'kind':'boosted_trees','weights':{'bias':0},'trees':[tree]}),encoding='utf8')
                with self.assertRaises(ValueError):CandidateClassifier.from_file(path)
            path.write_text(json.dumps({'schema_version':4,'kind':'boosted_trees','weights':{'bias':0},'trees':[{'value':0}],'promotion_policy':'unknown','promotion_threshold':.8}),encoding='utf8')
            with self.assertRaises(ValueError):CandidateClassifier.from_file(path)
