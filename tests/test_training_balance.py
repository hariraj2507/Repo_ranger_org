"""Independent checks of repository splitting and weighted training objectives."""
from collections import defaultdict
import math
import unittest

from backend.ml.training import (
    FEATURES, calibrate, fit, sample_weights, sigmoid, split_sources, weighted_log_loss,
)


def row(group, label, value=.5):
    return {'group': group, 'label': label, 'features': {'severity': value}}


def reference_fit(rows, importance, regularization, steps):
    """Uncompressed per-row gradient descent for equivalence checking."""
    weights = {name: 0.0 for name in FEATURES | {'bias'}}
    for _ in range(steps):
        gradient = dict.fromkeys(weights, 0.0)
        for sample, mass in zip(rows, importance):
            values = {'bias': 1.0, **sample['features']}
            error = (sigmoid(sum(weights[name] * value for name, value in values.items()))
                     - sample['label']) * mass
            for name, value in values.items():
                gradient[name] += error * value
        for name in weights:
            penalty = 0 if name == 'bias' else regularization * weights[name]
            weights[name] -= .2 * (gradient[name] / len(rows) + penalty)
    return weights


class TrainingBalanceTests(unittest.TestCase):
    def test_split_is_deterministic_disjoint_and_label_independent(self):
        rows = [row(f'repo-{group}', index % 2) for group in range(30)
                for index in range(10 if group else 90)]
        parts = split_sources(rows)
        assignments = [{sample['group'] for sample in part} for part in parts]
        self.assertEqual(assignments, [{sample['group'] for sample in part}
                                      for part in split_sources(rows[::-1])])
        relabeled = [{**sample, 'label': 1 - sample['label']} for sample in rows]
        self.assertEqual(assignments, [{sample['group'] for sample in part}
                                      for part in split_sources(relabeled)])
        self.assertEqual(sum(map(len, parts)), len(rows))
        self.assertEqual(len(set.union(*assignments)), 30)
        for left, right in ((0, 1), (0, 2), (1, 2)):
            self.assertFalse(assignments[left] & assignments[right])
        for part, fraction in zip(parts, (.6, .2, .2)):
            self.assertLessEqual(abs(len(part) - fraction * len(rows)), 10)

    def test_dominant_repository_stays_whole_even_when_target_is_impossible(self):
        rows = [row('dominant', index % 2) for index in range(900)]
        rows += [row(f'small-{group}', 0) for group in range(19) for _ in range(5)]
        parts = split_sources(rows)
        self.assertEqual([sum(r['group'] == 'dominant' for r in part) for part in parts], [900, 0, 0])
        self.assertTrue(all(parts))
        self.assertEqual(sum(map(len, parts)), len(rows))
        self.assertLessEqual(abs(len(parts[1]) - len(parts[2])), 5)

    def test_weights_normalize_and_class_mass_is_equal(self):
        rows = [row('large', 1)] * 8 + [row('large', 0)] * 2 + [row('small', 0)]
        weights = sample_weights(rows, balance_groups=True)
        by_group = defaultdict(float)
        for sample, weight in zip(rows, weights):
            by_group[sample['group']] += weight
        self.assertAlmostEqual(by_group['large'], by_group['small'])
        for group_balance in (False, True):
            balanced = sample_weights(rows, group_balance, True)
            self.assertAlmostEqual(sum(balanced), len(rows))
            for label in (0, 1):
                self.assertAlmostEqual(sum(w for r, w in zip(rows, balanced) if r['label'] == label), len(rows) / 2)
        self.assertEqual(sample_weights(rows), [1.0] * len(rows))
        with self.assertRaises(ValueError):
            sample_weights([row('a', 1)], balance_classes=True)

    def test_compressed_fit_matches_per_row_reference(self):
        rows = [row('a', 1, .8)] * 7 + [row('a', 0, .8)] * 2
        rows += [row('b', 0, .2)] * 3 + [row('c', 1, .8)]
        for group_balance in (False, True):
            for class_balance in (False, True):
                with self.subTest(groups=group_balance, classes=class_balance):
                    expected = reference_fit(rows, sample_weights(rows, group_balance, class_balance), .01, 30)
                    actual = fit(rows, .01, steps=30, balance_groups=group_balance, balance_classes=class_balance)
                    for name in expected:
                        self.assertAlmostEqual(actual[name], expected[name], places=13)

    def test_loss_and_calibration_follow_class_balanced_objective(self):
        rows = [row('a', 1)] * 9 + [row('b', 0)]
        loss = weighted_log_loss(rows, {'bias': math.log(4)}, True, True)
        self.assertAlmostEqual(loss, -(math.log(.8) + math.log(.2)) / 2)
        balanced, details = calibrate(rows, {'bias': 0.0}, balance_classes=True)
        self.assertAlmostEqual(balanced['bias'], 0.0, places=12)
        self.assertAlmostEqual(details['scale'], 1.0)
        unbalanced, _ = calibrate(rows, {'bias': 0.0})
        self.assertGreater(unbalanced['bias'], 1.0)
