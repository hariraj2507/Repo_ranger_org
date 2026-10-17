"""Bind release evidence to current code, then assess validity and readiness.

An alpha needs valid evidence: current revisions and detector code, a declared
independent sample of at least 20 repositories, and complete source coverage.
A stable release also needs the unchanged benchmarks.readiness thresholds.
Independence is an evaluator declaration, never inferred from favorable scores.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from backend.revisions import DETECTOR_REVISION, SCORING_REVISION
from .readiness import assess as assess_readiness

REPO_ROOT = Path(__file__).resolve().parents[1]
HASH_ENCODING = 'utf8-lf-v1'
ERROR_COUNTS = ('missing_files', 'oversized_files', 'undecodable_files',
                'invalid_label_files', 'repository_errors')
ALERT_COUNTS = ('alerts_true_positive', 'alerts_false_positive', 'alerts_unknown',
                'alerts_unlabeled', 'alerts_ambiguous')


def _count(value):
    return type(value) is int and value >= 0


def _confined(path, root, *, existing=True):
    """Reject external paths, including paths redirected by a symbolic link."""
    root = Path(root).resolve(strict=True)
    path = Path(path)
    resolved = (path if path.is_absolute() else root / path).resolve(strict=existing)
    resolved.relative_to(root)
    return resolved


def content_sha256(path):
    """Hash UTF-8 content with LF line endings on both supported platforms."""
    content = Path(path).read_text(encoding='utf-8')
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def detector_code_hashes(root=REPO_ROOT):
    """Cover all detector/AST/validator modules and analysis feature extraction."""
    root = Path(root).resolve(strict=True)
    paths = []
    for directory in ('backend/detectors', 'backend/ast', 'backend/validators'):
        paths.extend((root / directory).rglob('*.py'))
    paths.extend(root / name for name in (
        'backend/analysis_pipeline.py', 'backend/ml/feature_extractor.py'))
    return {path.relative_to(root).as_posix(): content_sha256(_confined(path, root))
            for path in sorted(paths)}


def make_manifest(report_path, manifest_path, *, root=REPO_ROOT, independence='independent'):
    """Write the current evidence binding; verification remains a separate check.

    The caller declares independence after freezing development and selecting
    untouched repositories. This function does not establish that provenance.
    Both paths must be inside root. The returned mapping is also saved as JSON.
    """
    root = Path(root).resolve(strict=True)
    report_path = _confined(report_path, root)
    manifest_path = _confined(manifest_path, root, existing=False)
    if report_path == manifest_path:
        raise ValueError('Report and manifest must be separate files')
    if independence not in {'independent', 'diagnostic', 'unverified'}:
        raise ValueError('Unsupported independence declaration')
    report = json.loads(report_path.read_text(encoding='utf-8-sig'))
    repositories = report.get('repositories', []) if isinstance(report, dict) else []
    manifest = {
        'schema_version': 1, 'hash_encoding': HASH_ENCODING,
        'report_path': report_path.relative_to(root).as_posix(),
        'report_sha256': content_sha256(report_path),
        'detector_revision': DETECTOR_REVISION, 'scoring_revision': SCORING_REVISION,
        'independence': independence,
        'selected_repository_ids': sorted(entry.get('id', '') for entry in repositories
                                          if isinstance(entry, dict)),
        'detector_code_sha256': detector_code_hashes(root),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return manifest


def _coverage(report):
    reasons = []
    selected = report.get('selected_repositories')
    repositories = report.get('repositories')
    counts = report.get('counts')
    if not _count(selected) or selected < 20:
        reasons.append('need_at_least_20_independent_selected_repositories')
    if (not isinstance(repositories, list) or not repositories
            or selected != len(repositories)):
        reasons.append('missing_or_inconsistent_repository_coverage')
        repositories = repositories if isinstance(repositories, list) else []
    ids = [entry.get('id') for entry in repositories if isinstance(entry, dict)]
    if (len(ids) != len(repositories) or any(not isinstance(name, str) or not name for name in ids)
            or len(set(name for name in ids if isinstance(name, str))) != len(ids)):
        reasons.append('invalid_or_duplicate_repository_identifiers')
    summaries = [counts] + [entry.get('counts') for entry in repositories if isinstance(entry, dict)]
    valid_counts = all(isinstance(summary, dict) and all(
        isinstance(key, str) and _count(value) for key, value in summary.items()) for summary in summaries)
    if not valid_counts:
        reasons.append('missing_or_invalid_coverage_counts')
        return reasons, ids
    for summary in summaries:
        expected, scanned = summary.get('expected_files'), summary.get('scanned_files')
        if (not _count(expected) or expected == 0 or not _count(scanned) or expected != scanned
                or any(summary.get(key, 0) for key in ERROR_COUNTS)):
            reasons.append('incomplete_file_coverage')
            break
    if report.get('errors') or any(entry.get('error') or entry.get('errors') for entry in repositories
                                  if isinstance(entry, dict)):
        reasons.append('evaluation_errors_present')
    if repositories:
        combined = Counter()
        for summary in summaries[1:]:
            combined.update(summary)
        if any(counts.get(key, 0) != combined.get(key, 0) for key in set(counts) | set(combined)):
            reasons.append('repository_counts_do_not_match_aggregates')
    for summary in summaries:
        if (not _count(summary.get('expected_annotations'))
                or not _count(summary.get('annotations_T', 0))
                or not _count(summary.get('annotations_F', 0))
                or summary.get('expected_annotations') != sum(summary.get('annotations_' + key, 0) for key in ('T', 'F', 'X'))
                or summary.get('annotations_T', 0) != sum(summary.get(key, 0) for key in (
                    'positive_annotations_detected', 'positive_annotations_missed'))
                or not _count(summary.get('alerts'))
                or summary.get('alerts') != sum(summary.get(key, 0) for key in ALERT_COUNTS)):
            reasons.append('inconsistent_annotation_or_alert_counts')
            break
    for metric, numerator, denominator in (
        ('labeled_alert_precision', counts.get('alerts_true_positive', 0),
         counts.get('alerts_true_positive', 0) + counts.get('alerts_false_positive', 0)),
        ('positive_annotation_recall', counts.get('positive_annotations_detected', 0),
         counts.get('annotations_T', 0)),
    ):
        expected = numerator / denominator if denominator else None
        actual = report.get(metric)
        if (expected is None and actual is not None) or (expected is not None and (
                type(actual) not in (int, float) or not math.isfinite(actual)
                or not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12))):
            reasons.append('reported_metrics_do_not_match_counts')
            break
    return reasons, ids


def verify(manifest_path, *, root=REPO_ROOT):
    """Return separate validity/readiness results, failing closed on bad evidence."""
    reasons = []
    report = None
    ids = []
    try:
        root = Path(root).resolve(strict=True)
        manifest_path = _confined(manifest_path, root)
        manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
        if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
            raise ValueError('Unsupported manifest schema')
        if manifest.get('hash_encoding') != HASH_ENCODING:
            reasons.append('unsupported_hash_encoding')
        if manifest.get('independence') != 'independent':
            reasons.append('independent_evaluation_not_established')
        if (manifest.get('detector_revision') != DETECTOR_REVISION
                or manifest.get('scoring_revision') != SCORING_REVISION):
            reasons.append('manifest_revisions_are_not_current')
        if manifest.get('detector_code_sha256') != detector_code_hashes(root):
            reasons.append('detector_code_does_not_match_evidence')
        path = manifest.get('report_path')
        if not isinstance(path, str) or Path(path).is_absolute():
            raise ValueError('Report path must be relative to root')
        report_path = _confined(path, root)
        if content_sha256(report_path) != manifest.get('report_sha256'):
            reasons.append('report_sha256_does_not_match_evidence')
        report = json.loads(report_path.read_text(encoding='utf-8-sig'))
        if not isinstance(report, dict):
            raise ValueError('Report must be a JSON object')
        # Raw detection does not run the risk scorer. Its explicit null revision
        # is valid; a triage report must bind the current scorer instead.
        raw_without_scoring = (
            'scoring_revision' in report
            and report['scoring_revision'] is None
            and report.get('triage') is None
        )
        if (report.get('detector_revision') != DETECTOR_REVISION
                or (report.get('scoring_revision') != SCORING_REVISION
                    and not raw_without_scoring)):
            reasons.append('report_revisions_are_not_current')
        coverage_reasons, ids = _coverage(report)
        reasons.extend(coverage_reasons)
        if manifest.get('selected_repository_ids') != sorted(name for name in ids if isinstance(name, str)):
            reasons.append('selected_repositories_do_not_match_manifest')
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        reasons.append('unreadable_invalid_or_unconfined_evidence')
    readiness = {'passed': False, 'reasons': ['valid_current_evidence_required']}
    if report is not None:
        counts = report.get('counts')
        selected = report.get('selected_repositories')
        if isinstance(counts, dict) and _count(selected):
            try:
                readiness = assess_readiness(report)
            except (KeyError, TypeError, ValueError):
                pass
    valid = not reasons
    return {
        'valid': valid, 'validity_reasons': list(dict.fromkeys(reasons)),
        'ready': valid and readiness['passed'], 'readiness': readiness,
        'requirements': {'alpha': 'Valid current independent evidence with complete coverage',
                         'stable': 'Valid evidence plus the existing benchmarks.readiness thresholds'},
        'scope': 'Minimum detector evidence; does not certify active credentials or operational readiness',
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create', help='Bind a frozen report to current detector code')
    create.add_argument('report')
    create.add_argument('manifest')
    create.add_argument('--independence', choices=('independent', 'diagnostic', 'unverified'), default='unverified')
    check = commands.add_parser('verify', help='Check current release evidence')
    check.add_argument('manifest')
    check.add_argument('--require-ready', action='store_true')
    args = parser.parse_args(arguments)
    if args.command == 'create':
        try:
            make_manifest(args.report, args.manifest, independence=args.independence)
        except (OSError, ValueError, TypeError, UnicodeError):
            parser.error('Cannot create a manifest from these report and manifest paths')
        result = verify(args.manifest)
        print(json.dumps(result, indent=2))
        return int(not result['valid'])
    result = verify(args.manifest)
    print(json.dumps(result, indent=2))
    return int(not result['valid'] or (args.require_ready and not result['ready']))


if __name__ == '__main__':
    raise SystemExit(main())
