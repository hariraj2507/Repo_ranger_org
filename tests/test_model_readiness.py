"""Acceptance rejects incomplete, too-small, or repository-skewed evidence."""
from copy import deepcopy
import unittest

from benchmarks.model_readiness import assess
from backend.ml.tree_training import fit_trees, select_threshold, TRAINING_CANDIDATES
from types import SimpleNamespace


def fixture():
    per_repository = {f'repo-{i}': {'samples': 10, 'positive_labels': 5,
        'true_positive': 5, 'false_negative': 0, 'true_negative': 5, 'false_positive': 0}
        for i in range(20)}
    candidate = {
        'repositories': list(per_repository),
        'trained': {'samples': 200, 'positive_labels': 100, 'true_positive': 100,
                    'false_negative': 0, 'true_negative': 100, 'false_positive': 0},
        'repository_metrics': {'trained': {'per_repository': per_repository}},
    }
    coverage = {'selected_repositories': 20, 'counts': {'expected_files': 20,
        'scanned_files': 20, 'annotations_T': 100, 'annotations_F': 100},
        'repositories': [{'id': name, 'counts': {'expected_files': 1, 'scanned_files': 1}}
                         for name in per_repository],
        'positive_annotation_recall': .3, 'labeled_alert_precision': 1.0}
    return candidate, coverage


class ModelReadinessTests(unittest.TestCase):
    def test_candidate_acceptance_keeps_scanner_recall_separate(self):
        candidate, coverage = fixture()
        result = assess(candidate, coverage, independence='independent')
        self.assertTrue(result['passed'])
        self.assertFalse(result['full_scanner_readiness_established'])
        self.assertIn('positive_annotation_recall_below_80_percent', result['full_scanner_gate']['reasons'])

    def test_previously_inspected_sample_cannot_claim_independence(self):
        candidate, coverage = fixture()
        for declaration in ('unverified', 'diagnostic'):
            result = assess(candidate, coverage, independence=declaration)
            self.assertIn('independent_evaluation_not_established', result['reasons'])

    def test_changed_model_or_dataset_cannot_reuse_favorable_evaluation(self):
        candidate, coverage = fixture()
        candidate.update(model_sha256='old-model', dataset_sha256='old-dataset')
        hashes = {'model_sha256': 'changed-model', 'dataset_sha256': 'changed-dataset'}
        result = assess(candidate, coverage, independence='independent', artifact_hashes=hashes)
        self.assertIn('model_identity_does_not_match_evaluation', result['reasons'])
        self.assertIn('dataset_identity_does_not_match_evaluation', result['reasons'])
        self.assertEqual(result['evidence_sha256'], hashes)

    def test_selected_repository_overlap_is_checked_beyond_candidate_groups(self):
        candidate, coverage = fixture()
        metadata = {'training': {'split_groups': {'validation': ['repo-19']}}}
        candidate['repositories'].remove('repo-19')
        del candidate['repository_metrics']['trained']['per_repository']['repo-19']
        result = assess(candidate, coverage, independence='independent', model_metadata=metadata)
        self.assertIn('selected_repositories_overlap_model_development', result['reasons'])

    def test_missing_and_unreported_coverage_fail(self):
        candidate, coverage = fixture()
        for change in ('missing', 'scanned', 'absent', 'aggregate'):
            report = deepcopy(coverage)
            if change == 'missing':
                report['repositories'][0]['counts']['missing_files'] = 1
            elif change == 'scanned':
                report['repositories'][0]['counts']['scanned_files'] = 0
            elif change == 'absent':
                del report['repositories'][0]['counts']['expected_files']
            else:
                report['counts']['scanned_files'] = 19
            self.assertFalse(assess(candidate, report, independence='independent')['passed'])

    def test_few_candidate_negatives_fail_despite_many_negative_annotations(self):
        candidate, coverage = fixture()
        for summary in candidate['repository_metrics']['trained']['per_repository'].values():
            summary['samples'] = 6
            summary['true_negative'] = 1
        candidate['trained'].update(samples=120, true_negative=20)
        coverage['counts']['annotations_F'] = 2000
        result = assess(candidate, coverage, independence='independent')
        self.assertIn('need_at_least_100_negative_candidate_labels', result['reasons'])

    def test_macro_rejects_pooled_specificity_hidden_by_one_repository(self):
        candidate, coverage = fixture()
        for summary in candidate['repository_metrics']['trained']['per_repository'].values():
            summary.update(samples=11, positive_labels=10, true_positive=10,
                           true_negative=0, false_positive=1)
        dominant = candidate['repository_metrics']['trained']['per_repository']['repo-0']
        dominant.update(samples=1011, true_negative=1000)
        candidate['trained'].update(samples=1220, positive_labels=200, true_positive=200,
                                    true_negative=1000, false_positive=20)
        result = assess(candidate, coverage, independence='independent')
        self.assertGreater(result['candidate_metrics']['specificity'], .97)
        self.assertGreater(result['candidate_metrics']['precision'], .9)
        self.assertEqual(result['macro_specificity'], (1000 / 1001) / 20)
        self.assertEqual(result['reasons'], ['macro_specificity_below_50_percent'])

    def test_rates_recomputed_from_counts_and_inconsistent_counts_fail(self):
        candidate, coverage = fixture()
        candidate['trained']['precision'] = .1
        result = assess(candidate, coverage, independence='independent')
        self.assertEqual(result['candidate_metrics']['precision'], 1.0)
        candidate['trained']['true_negative'] = 99
        self.assertIn('invalid_candidate_confusion_counts',
                      assess(candidate, coverage, independence='independent')['reasons'])

    def test_omitted_or_fabricated_repository_metrics_fail(self):
        candidate, coverage = fixture()
        del candidate['repository_metrics']['trained']['per_repository']['repo-0']
        result = assess(candidate, coverage, independence='independent')
        self.assertIn('missing_or_invalid_candidate_repository_metrics', result['reasons'])
        self.assertIn('repository_metrics_do_not_match_pooled_counts', result['reasons'])

    def test_malformed_nested_repository_metrics_fail_without_raising(self):
        for metrics in (None, [], {'trained': None}, {'trained': []}):
            candidate, coverage = fixture()
            candidate['repository_metrics'] = metrics
            result = assess(candidate, coverage, independence='independent')
            self.assertFalse(result['passed'])
            self.assertIn('missing_or_invalid_candidate_repository_metrics', result['reasons'])

    def test_nonfinite_or_invalid_scanner_evidence_cannot_claim_scanner_readiness(self):
        for name, values in (
            ('positive_annotation_recall', (float('nan'), float('inf'), 1.1, '1.0', None)),
            ('labeled_alert_precision', (float('nan'), float('inf'), -1., '1.0', None)),
            ('annotations_T', (float('nan'), '100', True, None)),
            ('annotations_F', (float('inf'), '100', True, None)),
        ):
            for value in values:
                candidate, coverage = fixture()
                coverage['positive_annotation_recall'] = 1.
                if name.startswith('annotations_'):
                    coverage['counts'][name] = value
                else:
                    coverage[name] = value
                result = assess(candidate, coverage, independence='independent')
                self.assertTrue(result['passed'])
                self.assertFalse(result['full_scanner_readiness_established'])
                self.assertIn('invalid_scanner_evidence', result['full_scanner_gate']['reasons'])

    def test_negative_evidence_from_one_repository_is_insufficient(self):
        candidate, coverage = fixture()
        for index, summary in enumerate(candidate['repository_metrics']['trained']['per_repository'].values()):
            summary.update(samples=100 if index == 0 else 10,
                           positive_labels=0 if index == 0 else 10,
                           true_positive=0 if index == 0 else 10,
                           true_negative=100 if index == 0 else 0)
        candidate['trained'].update(samples=290, positive_labels=190, true_positive=190, true_negative=100)
        result = assess(candidate, coverage, independence='independent')
        self.assertEqual(result['candidate_metrics']['specificity'], 1.0)
        self.assertEqual(result['reasons'], ['need_at_least_5_negative_bearing_repositories'])

    def test_precision_and_recall_floors_are_independent(self):
        for metric, update, pooled in (
            ('precision', {'false_positive': 2, 'true_negative': 3},
             {'false_positive': 40, 'true_negative': 60}),
            ('recall', {'true_positive': 3, 'false_negative': 2},
             {'true_positive': 60, 'false_negative': 40}),
        ):
            candidate, coverage = fixture()
            for summary in candidate['repository_metrics']['trained']['per_repository'].values():
                summary.update(update)
            candidate['trained'].update(pooled)
            result = assess(candidate, coverage, independence='independent')
            self.assertEqual(result['reasons'], [f'pooled_{metric}_below_' + ('90' if metric == 'precision' else '80') + '_percent'])


class TreeTrainingPolicyTests(unittest.TestCase):
    def test_single_repository_cannot_supply_a_supported_leaf(self):
        rows = [{'group': 'negative' if i < 3 else 'positive', 'label': int(i >= 3),
                 'features': {'severity': i / 5}} for i in range(6)]
        supported = fit_trees(rows, 2, rounds=2, min_leaf_sources=2)
        self.assertTrue(all(set(tree) == {'value'} for tree in supported))
        unrestricted = fit_trees(rows, 2, rounds=2)
        self.assertTrue(any('feature' in tree for tree in unrestricted))

    def test_repeated_rows_do_not_create_distinct_leaf_support(self):
        rows = [{'group': 'a', 'label': 0, 'features': {'severity': 0}}] * 50
        rows += [{'group': 'b', 'label': 1, 'features': {'severity': 1}}] * 50
        trees = fit_trees(rows, 2, rounds=2, min_leaf_vectors=2)
        self.assertTrue(all(set(tree) == {'value'} for tree in trees))

    def test_threshold_policy_selects_precision_on_validation_only(self):
        rows = [{'group': str(i), 'label': label, 'features': {'severity': score}}
                for i in range(20) for label, score in ((0, .60), (1, .90))]
        class FixtureScorer:
            def classify(self, features):
                return SimpleNamespace(score=features.value('severity'))
        selection = select_threshold(rows, FixtureScorer())
        self.assertTrue(selection['passed'])
        self.assertEqual(selection['selected_threshold'], .65)
        self.assertEqual(selection['partition'], 'validation only')
        self.assertEqual(selection['selected_metrics']['macro_specificity'], 1.0)
        for row in rows:
            if row['label']:
                row['features']['severity'] = .55
        failed = select_threshold(rows, FixtureScorer())
        self.assertFalse(failed['passed'])
        self.assertIsNotNone(failed['fallback'])

    def test_fixed_candidates_require_stronger_regularization_and_source_support(self):
        self.assertEqual(len(TRAINING_CANDIDATES), 6)
        for settings in TRAINING_CANDIDATES:
            self.assertGreater(settings['regularization'], 1.)
            self.assertGreaterEqual(settings['min_leaf_vectors'], 8)
            self.assertGreaterEqual(settings['min_leaf_sources'], 2)


if __name__ == '__main__':
    unittest.main()
