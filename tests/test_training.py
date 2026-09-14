"""Model validation, partition isolation, and reproducible evaluation tests."""
import json
from pathlib import Path
import tempfile
import unittest

from backend.ml.classifier import CandidateClassifier
from backend.ml.feature_extractor import FeatureVector
from backend.ml.training import load_rows, split_groups
from benchmarks.evaluate import evaluate


class TrainingTests(unittest.TestCase):
    def test_group_partitions_are_disjoint(self):
        base=Path(__file__).resolve().parents[1]
        splits=split_groups(load_rows(base/'benchmarks/triage.jsonl'))
        groups=[{row['group'] for row in split} for split in splits]
        self.assertFalse(groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2])
        self.assertEqual(sum(map(len,splits)),200)

    def test_experimental_model_loads_and_baseline_stays_default(self):
        path=Path(__file__).resolve().parents[1]/'models/experimental.json'
        trained=CandidateClassifier.from_file(path)
        self.assertNotEqual(trained._weights,CandidateClassifier()._weights)
        self.assertTrue(0 <= trained.classify(FeatureVector({'known_signature':1})).score <= 1)

    def test_invalid_model_weights_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'model.json'
            for weights in ({'bias':float('nan')},{'bias':0,'unrecognized':1},{'bias':1000},{'bias':'text'}):
                path.write_text(json.dumps({'schema_version':1,'kind':'logistic','weights':weights}))
                with self.assertRaises(ValueError):
                    CandidateClassifier.from_file(path)

    def test_expanded_detection_benchmark(self):
        result=evaluate()
        self.assertEqual(result['samples'],52)
        self.assertEqual(result['failures'],[])
