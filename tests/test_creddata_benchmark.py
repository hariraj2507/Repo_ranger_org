"""Matching must not turn ambiguous or unlabeled alerts into false positives."""
import unittest
from benchmarks.creddata import classify_alert


def row(label, start, end):
    return {'GroundTruth': label, 'LineStart': str(start), 'LineEnd': str(end)}


class CredDataMatchingTests(unittest.TestCase):
    def test_multiline_overlap_and_boundaries(self):
        rows = [row('T', 3, 8)]
        self.assertEqual(classify_alert(1, 3, rows), 'true_positive')
        self.assertEqual(classify_alert(8, 8, rows), 'true_positive')
        self.assertEqual(classify_alert(9, 9, rows), 'unlabeled')

    def test_conflicting_labels_are_ambiguous(self):
        self.assertEqual(classify_alert(4, 4, [row('T', 3, 5), row('F', 4, 4)]), 'ambiguous')

    def test_unknown_and_unlabeled_are_separate_from_negative(self):
        rows = [row('X', 1, 1), row('F', 2, 2)]
        self.assertEqual(classify_alert(1, 1, rows), 'unknown')
        self.assertEqual(classify_alert(2, 2, rows), 'false_positive')
        self.assertEqual(classify_alert(3, 3, rows), 'unlabeled')
