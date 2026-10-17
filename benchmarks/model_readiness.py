"""Fail-closed acceptance for independent, line-labeled candidate evaluation.

Candidate labels cover findings the detector emitted. They cannot establish
recall over all annotated source lines, which is reported as a separate gate.
An explicit independence declaration is required: a previously inspected
sample must be declared diagnostic, even if it has no training-group overlap.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from .readiness import assess as assess_scanner


POLICY = {
    'minimum_selected_repositories': 20,
    'minimum_positive_candidates': 100,
    'minimum_negative_candidates': 100,
    'minimum_negative_bearing_repositories': 5,
    'minimum_precision': .90,
    'minimum_recall': .80,
    'minimum_specificity': .50,
    'minimum_macro_specificity': .50,
    'complete_file_coverage_required': True,
}
ERROR_COUNTS = ('missing_files', 'oversized_files', 'undecodable_files',
                'invalid_label_files', 'repository_errors')
CONFUSION_COUNTS = ('true_positive', 'false_positive', 'false_negative', 'true_negative')


def _count(value):
    return type(value) is int and value >= 0


def _confusion(summary):
    if (not isinstance(summary, dict)
            or any(not _count(summary.get(k)) for k in CONFUSION_COUNTS + ('samples', 'positive_labels'))):
        return None
    tp, fp, fn, tn = (summary[k] for k in CONFUSION_COUNTS)
    if summary.get('samples') != tp + fp + fn + tn or summary.get('positive_labels') != tp + fn:
        return None
    return {
        'samples': tp + fp + fn + tn, 'positive_labels': tp + fn,
        'negative_labels': fp + tn, 'true_positive': tp, 'false_positive': fp,
        'false_negative': fn, 'true_negative': tn,
        'precision': tp / (tp + fp) if tp + fp else None,
        'recall': tp / (tp + fn) if tp + fn else None,
        'specificity': tn / (tn + fp) if tn + fp else None,
    }


def _coverage(report):
    """Check aggregate and every selected repository; absent evidence fails."""
    reasons = []
    counts = report.get('counts', {})
    counts = counts if isinstance(counts, dict) else {}
    repositories = report.get('repositories', [])
    selected = report.get('selected_repositories')
    if not _count(selected) or selected < POLICY['minimum_selected_repositories']:
        reasons.append('need_at_least_20_selected_independent_repositories')
    if (not isinstance(repositories, list) or not repositories
            or selected != len(repositories)):
        reasons.append('missing_or_inconsistent_repository_coverage')
        repositories = repositories if isinstance(repositories, list) else []
    ids = [r.get('id') for r in repositories if isinstance(r, dict)]
    if (len(ids) != len(repositories) or any(not isinstance(name, str) or not name for name in ids)
            or len(set(ids)) != len(ids)):
        reasons.append('invalid_or_duplicate_repository_identifiers')
    summaries = [counts] + [r.get('counts', {}) for r in repositories if isinstance(r, dict)]
    for summary in summaries:
        summary = summary if isinstance(summary, dict) else {}
        expected, scanned = summary.get('expected_files'), summary.get('scanned_files')
        if (not _count(expected) or not _count(scanned) or expected == 0 or expected != scanned
                or any(not _count(summary.get(k, 0)) or summary.get(k, 0) for k in ERROR_COUNTS)):
            reasons.append('incomplete_file_coverage')
            break
    if repositories and all(isinstance(r, dict) and isinstance(r.get('counts'), dict) for r in repositories):
        for key in ('expected_files', 'scanned_files'):
            entries = [r['counts'].get(key) for r in repositories]
            if all(_count(value) for value in entries) and counts.get(key) != sum(entries):
                reasons.append('inconsistent_aggregate_file_coverage')
                break
    return reasons, set(name for name in ids if isinstance(name, str))


def assess(candidate_report, coverage_report, *, independence='unverified', model_metadata=None,
           artifact_hashes=None):
    """Assess a frozen model; selection and tuning never occur in this function.

    ``independence`` records provenance supplied by the evaluator, not an
    inference from high scores. Optional model metadata checks repository
    separation again; the evaluator also performs this check when scoring.
    """
    reasons, selected = _coverage(coverage_report)
    if independence != 'independent':
        reasons.append('independent_evaluation_not_established')
    if artifact_hashes is not None:
        for key in ('dataset_sha256', 'model_sha256'):
            if not artifact_hashes.get(key) or candidate_report.get(key) != artifact_hashes[key]:
                reasons.append(key.replace('_sha256', '') + '_identity_does_not_match_evaluation')
    evaluated = candidate_report.get('repositories', [])
    if (not isinstance(evaluated, list) or any(not isinstance(g, str) for g in evaluated)
            or len(set(evaluated)) != len(evaluated)):
        reasons.append('invalid_candidate_repository_identifiers')
        evaluated = []
    if not set(evaluated) <= selected:
        reasons.append('candidate_repositories_absent_from_coverage')
    if model_metadata is not None:
        development = {group for groups in model_metadata.get('training', {}).get('split_groups', {}).values()
                       for group in groups}
        if selected & development:
            reasons.append('selected_repositories_overlap_model_development')
    pooled = _confusion(candidate_report.get('trained'))
    if pooled is None:
        reasons.append('invalid_candidate_confusion_counts')
        pooled = {}
    else:
        if pooled['positive_labels'] < POLICY['minimum_positive_candidates']:
            reasons.append('need_at_least_100_positive_candidate_labels')
        if pooled['negative_labels'] < POLICY['minimum_negative_candidates']:
            reasons.append('need_at_least_100_negative_candidate_labels')
        for name, floor in (('precision', .90), ('recall', .80), ('specificity', .50)):
            if pooled[name] is None or pooled[name] < floor:
                reasons.append('pooled_' + name + '_below_' + str(int(floor * 100)) + '_percent')
    repository_metrics = candidate_report.get('repository_metrics', {})
    repository_metrics = repository_metrics if isinstance(repository_metrics, dict) else {}
    trained_metrics = repository_metrics.get('trained', {})
    trained_metrics = trained_metrics if isinstance(trained_metrics, dict) else {}
    per_repository = trained_metrics.get('per_repository', {})
    per_repository = per_repository if isinstance(per_repository, dict) else {}
    checked = {name: _confusion(summary) for name, summary in per_repository.items()}
    if (not checked or set(checked) != set(evaluated) or any(summary is None for summary in checked.values())):
        reasons.append('missing_or_invalid_candidate_repository_metrics')
    valid = [summary for summary in checked.values() if summary is not None]
    if pooled and any(sum(summary[key] for summary in valid) != pooled[key] for key in CONFUSION_COUNTS):
        reasons.append('repository_metrics_do_not_match_pooled_counts')
    specificities = [summary['specificity'] for summary in valid if summary['negative_labels']]
    macro_specificity = sum(specificities) / len(specificities) if specificities else None
    if len(specificities) < POLICY['minimum_negative_bearing_repositories']:
        reasons.append('need_at_least_5_negative_bearing_repositories')
    elif macro_specificity < POLICY['minimum_macro_specificity']:
        reasons.append('macro_specificity_below_50_percent')
    scanner_counts = coverage_report.get('counts', {})
    scanner_selected = coverage_report.get('selected_repositories')
    scanner_counts = dict(scanner_counts) if isinstance(scanner_counts, dict) else {}
    scanner_input = dict(coverage_report, counts=scanner_counts,
                         selected_repositories=scanner_selected if _count(scanner_selected) else 0)
    invalid_scanner_evidence = False
    for name in ('annotations_T', 'annotations_F'):
        if not _count(scanner_counts.get(name)):
            invalid_scanner_evidence = True
            scanner_counts[name] = 0
    for name in ('positive_annotation_recall', 'labeled_alert_precision'):
        value = scanner_input.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            invalid_scanner_evidence = True
            scanner_input[name] = 0.
    scanner = assess_scanner(scanner_input)
    if invalid_scanner_evidence:
        scanner['passed'] = False
        scanner['reasons'].append('invalid_scanner_evidence')
    coverage_reasons, _ = _coverage(coverage_report)
    if coverage_reasons:
        scanner['passed'] = False
        scanner['reasons'] = list(dict.fromkeys(scanner['reasons'] + coverage_reasons))
    provenance_reasons = [reason for reason in reasons if reason in
        ('independent_evaluation_not_established', 'selected_repositories_overlap_model_development',
         'dataset_identity_does_not_match_evaluation', 'model_identity_does_not_match_evaluation')]
    if provenance_reasons:
        scanner['passed'] = False
        scanner['reasons'] = list(dict.fromkeys(scanner['reasons'] + provenance_reasons))
    return {
        'passed': not reasons,
        'reasons': list(dict.fromkeys(reasons)),
        'policy': dict(POLICY),
        'independence': independence,
        'evidence_sha256': dict(artifact_hashes or {}),
        'selected_repositories': coverage_report.get('selected_repositories'),
        'candidate_repositories': len(evaluated),
        'candidate_metrics': pooled,
        'negative_bearing_repositories': len(specificities),
        'macro_specificity': macro_specificity,
        'scope': 'Line-labeled candidate triage only; emitted candidates exclude detector misses. Scores are not active-exposure probabilities.',
        'full_scanner_gate': scanner,
        'full_scanner_readiness_established': scanner['passed'],
        'deployment': 'Candidate acceptance does not authorize default promotion or certify full scanner accuracy.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate_report')
    parser.add_argument('coverage_report')
    parser.add_argument('output')
    parser.add_argument('--model', required=True, help='Frozen model for artifact identity and development overlap checks')
    parser.add_argument('--dataset', required=True, help='Numeric candidate dataset for artifact identity check')
    parser.add_argument('--independence', choices=('independent', 'diagnostic', 'unverified'), default='unverified')
    parser.add_argument('--require-ready', action='store_true')
    args = parser.parse_args()
    def read(path):
        return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    hashes = {key: hashlib.sha256(Path(path).read_bytes()).hexdigest() for key, path in (
        ('dataset_sha256', args.dataset), ('model_sha256', args.model),
        ('candidate_report_sha256', args.candidate_report), ('coverage_report_sha256', args.coverage_report))}
    result = assess(read(args.candidate_report), read(args.coverage_report),
                    independence=args.independence, model_metadata=read(args.model), artifact_hashes=hashes)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return int(args.require_ready and not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
