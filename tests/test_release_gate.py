"""Release evidence must be current, complete, and distinct from readiness."""
from collections import Counter
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend.revisions import DETECTOR_REVISION, SCORING_REVISION
from benchmarks import release_gate


def fixture():
    counts = {'expected_files': 2, 'scanned_files': 2, 'expected_annotations': 10,
              'annotations_T': 5, 'annotations_F': 5, 'alerts': 6,
              'alerts_true_positive': 5, 'alerts_false_positive': 1,
              'positive_annotations_detected': 5, 'positive_annotations_missed': 0,
              'missing_files': 0}
    repositories = [{'id': f'repo-{index}', 'counts': deepcopy(counts)} for index in range(20)]
    totals = Counter()
    for repository in repositories:
        totals.update(repository['counts'])
    return {'detector_revision': DETECTOR_REVISION, 'scoring_revision': SCORING_REVISION,
            'selected_repositories': 20, 'repositories': repositories, 'counts': dict(totals),
            'labeled_alert_precision': 5 / 6, 'positive_annotation_recall': 1.0}


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.root = Path(self.workspace.name)
        for name in ('backend/detectors/check.py', 'backend/ast/check.py',
                     'backend/validators/check.py', 'backend/analysis_pipeline.py',
                     'backend/ml/feature_extractor.py', 'backend/web/server.py'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('VALUE = 1\n', encoding='utf-8')
        self.report_path = self.root / 'benchmarks/revision9/independent.json'
        self.manifest_path = self.root / 'benchmarks/revision9/release-evidence.json'
        self.report = fixture()
        self.record()

    def tearDown(self):
        self.workspace.cleanup()

    def record(self, *, independence='independent'):
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(json.dumps(self.report, indent=2) + '\n', encoding='utf-8')
        return release_gate.make_manifest(self.report_path, self.manifest_path,
                                          root=self.root, independence=independence)

    def check(self):
        return release_gate.verify(self.manifest_path, root=self.root)

    def save_manifest(self, manifest):
        self.manifest_path.write_text(json.dumps(manifest), encoding='utf-8')

    def test_valid_alpha_does_not_relax_stable_thresholds(self):
        result = self.check()
        self.assertTrue(result['valid'], result)
        self.assertFalse(result['ready'])
        self.assertEqual(result['readiness']['reasons'], ['labeled_alert_precision_below_90_percent'])
        with patch.object(release_gate, 'verify', return_value=result), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_gate.main(['verify', str(self.manifest_path)]), 0)
            self.assertEqual(release_gate.main(['verify', str(self.manifest_path), '--require-ready']), 1)

    def test_ready_requires_both_precision_and_annotation_recall(self):
        for repository in self.report['repositories']:
            repository['counts'].update(alerts=5, alerts_false_positive=0)
        self.report['counts'].update(alerts=100, alerts_false_positive=0)
        self.report['labeled_alert_precision'] = 1.0
        self.record()
        self.assertTrue(self.check()['ready'])
        for repository in self.report['repositories']:
            repository['counts'].update(positive_annotations_detected=3, positive_annotations_missed=2)
        self.report['counts'].update(positive_annotations_detected=60, positive_annotations_missed=40)
        self.report['positive_annotation_recall'] = .6
        self.record()
        result = self.check()
        self.assertTrue(result['valid'])
        self.assertFalse(result['ready'])
        self.assertIn('positive_annotation_recall_below_80_percent', result['readiness']['reasons'])

    def test_report_tampering_fails_even_if_metrics_still_pass(self):
        self.report_path.write_text(self.report_path.read_text() + ' ', encoding='utf-8')
        result = self.check()
        self.assertFalse(result['valid'])
        self.assertIn('report_sha256_does_not_match_evidence', result['validity_reasons'])

    def test_manifest_and_report_revisions_must_match_current_revisions(self):
        for key in ('detector_revision', 'scoring_revision'):
            with self.subTest(key=key):
                manifest = self.record()
                manifest[key] -= 1
                self.save_manifest(manifest)
                self.assertIn('manifest_revisions_are_not_current', self.check()['validity_reasons'])
                self.report[key] -= 1
                self.record()
                self.assertIn('report_revisions_are_not_current', self.check()['validity_reasons'])
                self.report = fixture()
        self.record()
        with patch.object(release_gate, 'DETECTOR_REVISION', DETECTOR_REVISION + 1):
            self.assertFalse(self.check()['valid'])

    def test_source_edits_and_added_detector_modules_invalidate_evidence(self):
        path = self.root / 'backend/detectors/check.py'
        path.write_text('VALUE = 2\n', encoding='utf-8')
        self.assertIn('detector_code_does_not_match_evidence', self.check()['validity_reasons'])
        self.record()
        (path.parent / 'new.py').write_text('VALUE = 3\n', encoding='utf-8')
        self.assertFalse(self.check()['valid'])

    def test_raw_report_has_explicit_null_scorer_but_triage_requires_current_scorer(self):
        self.report['scoring_revision'] = None
        self.report['triage'] = None
        self.record()
        self.assertTrue(self.check()['valid'])
        self.report['triage'] = {'minimum_risk': 50}
        self.record()
        self.assertIn('report_revisions_are_not_current', self.check()['validity_reasons'])
        self.report['triage'] = None
        del self.report['scoring_revision']
        self.record()
        self.assertIn('report_revisions_are_not_current', self.check()['validity_reasons'])

    def test_dashboard_edits_do_not_invalidate_detector_evidence(self):
        (self.root / 'backend/web/server.py').write_text('VALUE = 2\n', encoding='utf-8')
        self.assertTrue(self.check()['valid'])

    def test_utf8_lf_hashes_work_on_both_checkout_line_endings(self):
        for path in (self.report_path, self.root / 'backend/detectors/check.py'):
            content = path.read_text(encoding='utf-8').replace('\n', '\r\n')
            path.write_bytes(content.encode('utf-8'))
        self.assertTrue(self.check()['valid'])

    def test_external_and_traversal_report_paths_are_rejected(self):
        manifest = self.record()
        for path in ('../../../outside.json', str(self.report_path.resolve())):
            manifest['report_path'] = path
            self.save_manifest(manifest)
            self.assertIn('unreadable_invalid_or_unconfined_evidence', self.check()['validity_reasons'])
        with self.assertRaises(ValueError):
            release_gate.make_manifest(self.report_path, self.root.parent / 'outside.json', root=self.root)

    def test_complete_coverage_is_checked_per_repository_and_in_aggregate(self):
        for change in ('missing_files', 'scanned_files', 'expected_files', 'absent_counts', 'error'):
            with self.subTest(change=change):
                self.report = fixture()
                repository = self.report['repositories'][0]
                if change == 'missing_files':
                    repository['counts']['missing_files'] = 1
                elif change == 'scanned_files':
                    repository['counts']['scanned_files'] = 1
                elif change == 'expected_files':
                    del repository['counts']['expected_files']
                elif change == 'absent_counts':
                    del repository['counts']
                else:
                    repository['error'] = 'evaluation failed'
                self.record()
                self.assertFalse(self.check()['valid'])

    def test_all_repository_counts_must_equal_aggregate_and_rates(self):
        for key in ('scanned_files', 'annotations_T', 'alerts_true_positive', 'positive_annotations_detected'):
            with self.subTest(key=key):
                self.report = fixture()
                self.report['counts'][key] -= 1
                self.record()
                self.assertIn('repository_counts_do_not_match_aggregates', self.check()['validity_reasons'])
        self.report = fixture()
        self.report['labeled_alert_precision'] = 1.0
        self.record()
        self.assertIn('reported_metrics_do_not_match_counts', self.check()['validity_reasons'])

    def test_small_duplicate_and_undeclared_samples_are_invalid(self):
        self.report['selected_repositories'] = 19
        self.report['repositories'].pop()
        self.record()
        self.assertFalse(self.check()['valid'])
        self.report = fixture()
        self.report['repositories'][0]['id'] = self.report['repositories'][1]['id']
        self.record()
        self.assertFalse(self.check()['valid'])
        self.report = fixture()
        for declaration in ('diagnostic', 'unverified'):
            self.record(independence=declaration)
            self.assertIn('independent_evaluation_not_established', self.check()['validity_reasons'])

    def test_malformed_json_and_negative_counts_fail_closed(self):
        self.manifest_path.write_text('{}', encoding='utf-8')
        self.assertFalse(self.check()['valid'])
        self.report['repositories'][0]['counts']['alerts'] = -1
        self.record()
        self.assertFalse(self.check()['valid'])


if __name__ == '__main__':
    unittest.main()
