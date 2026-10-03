import json, tempfile, unittest
from pathlib import Path
from backend.ml.classifier import CandidateClassifier
from backend.ml.feature_extractor import FeatureVector
from backend.ml.confidence_engine import ConfidenceEngine
from backend.ml.training import metrics

class GuardedModelTests(unittest.TestCase):
    def test_below_threshold_returns_exact_baseline(self):
        features=FeatureVector({'entropy_signal':1,'severity':.5})
        baseline=CandidateClassifier().classify(features)
        self.assertEqual(CandidateClassifier({'bias':1},promotion_threshold=.8).classify(features),baseline)

    def test_promotion_explained_and_never_lowers_baseline(self):
        model=CandidateClassifier({'bias':2},promotion_threshold=.8)
        for features in ({},{'severity':1,'known_signature':1,'validator_valid':1},{'non_production_path':1,'entropy_signal':1}):
            vector=FeatureVector(features)
            self.assertGreaterEqual(model.classify(vector).score,CandidateClassifier().classify(vector).score)
        vector=FeatureVector({}); result=model.classify(vector)
        self.assertIn('ml_priority_promotion',result.contributing_features)
        self.assertTrue(any('promotion threshold' in x for x in ConfidenceEngine().assess(result,vector).rationale))

    def test_evaluation_uses_runtime_guard(self):
        rows=[{'features':{'severity':.5},'label':label,'group':'repo'} for label in (0,1)]
        expected=metrics(rows,dict(CandidateClassifier._DEFAULT_WEIGHTS))
        actual=metrics(rows,{'bias':1},promotion_threshold=.9)
        self.assertEqual(actual,expected)

    def test_guarded_model_schema_and_invalid_thresholds(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'model.json'
            for threshold in (None,True,float('nan'),.4,1.1,'0.8'):
                path.write_text(json.dumps({'schema_version':2,'kind':'guarded_logistic','promotion_policy':CandidateClassifier.PROMOTION_POLICY,'weights':{'bias':0},'promotion_threshold':threshold}))
                with self.subTest(threshold=threshold),self.assertRaises(ValueError):CandidateClassifier.from_file(path)
            path.write_text(json.dumps({'schema_version':2,'kind':'guarded_logistic','promotion_policy':CandidateClassifier.PROMOTION_POLICY,'weights':{'bias':0},'promotion_threshold':.8}))
            self.assertEqual(CandidateClassifier.from_file(path)._promotion_threshold,.8)

    def test_frozen_model_never_demotes_development_candidates(self):
        from backend.ml.training import load_rows
        root=Path(__file__).resolve().parents[1]
        model=CandidateClassifier.from_file(root/'models/creddata-v3-guarded.json')
        baseline=CandidateClassifier()
        for row in load_rows(root/'benchmarks/ml-v2/development.jsonl'):
            vector=FeatureVector(row['features'])
            self.assertGreaterEqual(model.classify(vector).score,baseline.classify(vector).score)

    def test_no_passing_validation_candidate_disables_promotion(self):
        vector=FeatureVector({})
        self.assertEqual(CandidateClassifier({'bias':100},promotion_threshold=1).classify(vector),CandidateClassifier().classify(vector))

    def test_negative_context_prevents_even_saturated_promotion(self):
        model=CandidateClassifier({'bias':100},promotion_threshold=.8)
        for name in CandidateClassifier._GUARD_VETO_FEATURES:
            vector=FeatureVector({name:1})
            with self.subTest(feature=name):
                self.assertEqual(model.classify(vector),CandidateClassifier().classify(vector))

    def test_unknown_or_missing_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'model.json'
            for policy in (None, 'future_policy'):
                path.write_text(json.dumps({'schema_version':2,'kind':'guarded_logistic',
                    'weights':{'bias':0},'promotion_threshold':.8,'promotion_policy':policy}),encoding='utf8')
                with self.subTest(policy=policy),self.assertRaises(ValueError):
                    CandidateClassifier.from_file(path)
