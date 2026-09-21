"""Ranking metrics and independent evaluation diagnostics."""
import unittest

from backend.detectors.finding import VALUE_SHAPE_FEATURES
from backend.ml.training import FEATURES, metrics, ranking_metrics
from benchmarks.evaluate_model import feature_label_diagnostic, repository_metrics


def row(label, severity, group='a'):
    return {'label': label, 'features': {'severity': severity}, 'group': group}


class ModelMetricsTests(unittest.TestCase):
    def test_perfect_and_reversed_ranking(self):
        self.assertEqual(ranking_metrics([0, 0, 1, 1], [.1, .2, .8, .9]),
                         {'auroc': 1.0, 'average_precision': 1.0})
        reversed_scores = ranking_metrics([1, 1, 0, 0], [.1, .2, .8, .9])
        self.assertEqual(reversed_scores['auroc'], 0.0)
        self.assertAlmostEqual(reversed_scores['average_precision'], (1 / 3 + 2 / 4) / 2)

    def test_ties_are_grouped_and_order_independent(self):
        labels = [0, 1, 0, 1]
        scores = [.2, .2, .8, .8]
        result = ranking_metrics(labels, scores)
        self.assertEqual(result, {'auroc': .5, 'average_precision': .5})
        self.assertEqual(result, ranking_metrics(labels[::-1], scores[::-1]))
        self.assertEqual(ranking_metrics([1, 0, 0], [.5, .5, .5]),
                         {'auroc': .5, 'average_precision': 1 / 3})

    def test_single_class_ranking(self):
        self.assertEqual(ranking_metrics([1, 1], [.2, .8]),
                         {'auroc': None, 'average_precision': 1.0})
        self.assertEqual(ranking_metrics([0, 0], [.2, .8]),
                         {'auroc': None, 'average_precision': None})

    def test_balanced_accuracy_preserves_threshold_and_existing_fields(self):
        result = metrics([row(0, 0), row(1, 1), row(0, 1), row(1, .5)],
                         {'bias': -1, 'severity': 2})
        self.assertEqual(result['true_positive'], 2)  # Score .5 remains positive.
        self.assertEqual(result['false_positive'], 1)
        self.assertEqual(result['recall'], 1.0)
        self.assertEqual(result['specificity'], .5)
        self.assertEqual(result['balanced_accuracy'], .75)
        self.assertEqual(len(result['reliability_bins']), 10)
        self.assertIsNone(metrics([row(0, 0)], {})['balanced_accuracy'])
        self.assertIsNone(metrics([row(1, 0)], {})['balanced_accuracy'])
        self.assertTrue(set(VALUE_SHAPE_FEATURES) <= FEATURES)

    def test_repository_macro_excludes_undefined_rates(self):
        rows = [row(0, 0), row(1, 1), row(0, 0, 'b'), row(0, 0, 'b'), row(1, 1, 'c')]
        result = repository_metrics(rows, {'bias': -1, 'severity': 2})
        self.assertEqual(result['macro'], {'precision': 1.0, 'recall': 1.0,
                                           'specificity': 1.0, 'auroc': 1.0})
        self.assertEqual(result['macro_defined_repositories'],
                         {'precision': 2, 'recall': 2, 'specificity': 2, 'auroc': 1})
        self.assertIsNone(result['per_repository']['b']['recall'])
        self.assertIsNone(result['per_repository']['b']['precision'])

    def test_macro_is_unweighted_over_repositories(self):
        rows = [row(1, 1)] * 9 + [row(0, 1, 'b')]
        self.assertEqual(repository_metrics(rows, {'bias': 1})['macro']['precision'], .5)

    def test_conflicting_labels_normalize_missing_zero_features(self):
        rows = [row(1, 0), {'label': 0, 'features': {}, 'group': 'b'}, row(1, 1)]
        result = feature_label_diagnostic(rows)
        self.assertEqual(result['unique_feature_vectors'], 2)
        self.assertEqual(result['conflicting_label_vectors'], 1)
        self.assertEqual(result['rows_in_conflicting_vectors'], 2)
        self.assertEqual(result['minority_label_rows_in_conflicting_vectors'], 1)
        self.assertIn('metadata ambiguity', result['interpretation'])
        self.assertTrue(all(isinstance(value, int) for key, value in result.items() if key != 'interpretation'))
