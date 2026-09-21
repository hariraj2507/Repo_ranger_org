"""External CredData pilot: fixed sampling, source archives, aggregate output only.

Never executes corpus code or validates credentials online. Original source files
remain in ignored local storage; do not redistribute them or commit the corpus.
"""
from __future__ import annotations

import argparse
import binascii
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request
import os
from contextlib import nullcontext
import urllib.error

from backend.analysis_pipeline import FindingAnalyzer
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.classifier import CandidateClassifier
from backend.ml.confidence_engine import ConfidenceEngine
from backend.engine.risk_engine import RiskEngine

from backend.detectors.detection_engine import DetectionEngine
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata

SEED = "reporanger-external-pilot-v1"
MAX_ARCHIVE = 150 * 1024 * 1024


def source_members(archive, wanted, cache, key, url, fallback, stats, max_file_bytes=5*1024*1024, original_paths=None):
    """Read archive files, then recover export-ignored files from pinned Git objects."""
    seen = set()
    with (tarfile.open(archive, 'r:gz') if archive.exists() else nullcontext(())) as tar:
        for member in tar:
            if not member.isfile() or '/' not in member.name:
                continue
            name = member.name.split('/', 1)[1]
            file_id = hashlib.sha256(name.encode()).hexdigest()[:8]
            if file_id not in wanted:
                continue
            if file_id in seen:
                raise ValueError('Duplicate file ID in archive')
            seen.add(file_id)
            if original_paths is not None:
                original_paths[file_id] = name
            yield file_id, member.size, tar.extractfile(member).read() if member.size <= max_file_bytes else b''
    missing = set(wanted) - seen
    if not missing or not fallback:
        return
    repository = cache / ('git-' + key[:40])
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GCM_INTERACTIVE': 'Never'}
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repository), *args], stderr=subprocess.PIPE, env=env, timeout=180)
    if not repository.exists():
        subprocess.run(['git', 'init', '--bare', str(repository)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        git('cat-file', '-e', key[:40] + '^{commit}')
    except subprocess.CalledProcessError:
        if 'origin' not in git('remote').decode().split():
            git('remote', 'add', 'origin', url)
        if git('remote', 'get-url', 'origin').decode().strip() != url:
            raise ValueError('Cached Git remote differs from snapshot')
        git('config', 'remote.origin.promisor', 'true')
        git('config', 'remote.origin.partialclonefilter', 'blob:none')
        git('fetch', '--depth=1', '--no-tags', '--filter=blob:none', 'origin', key[:40])
    for entry in git('ls-tree', '-rz', key[:40]).split(b'\0'):
        if not entry:
            continue
        info, name = entry.split(b'\t', 1)
        mode, kind, oid = info.split()
        file_id = hashlib.sha256(name).hexdigest()[:8]
        if file_id not in missing or kind != b'blob' or mode == b'120000':
            continue
        size = int(git('cat-file', '-s', oid.decode()))
        raw = git('cat-file', 'blob', oid.decode()) if size <= max_file_bytes else b''
        if original_paths is not None:
            original_paths[file_id] = name.decode('utf-8')
        stats['git_recovered_files'] += 1
        yield file_id, size, raw


def classify_alert(start, end, rows):
    """Line overlap only; conflicting labels are explicitly ambiguous."""
    labels = {r['GroundTruth'] for r in rows
              if start <= int(r['LineEnd']) and end >= int(r['LineStart'])}
    if len(labels) > 1:
        return 'ambiguous'
    return {'T': 'true_positive', 'F': 'false_positive', 'X': 'unknown'}.get(
        next(iter(labels), ''), 'unlabeled')


def selected_repositories(root, count, offset=0):
    snapshot = json.loads((root / 'snapshot.json').read_text(encoding='utf-8'))
    entries = []
    for key, url in snapshot.items():
        repo_id = f'{binascii.crc32(binascii.unhexlify(key)):08x}'
        meta = root / 'meta' / (repo_id + '.csv')
        if meta.exists():
            entries.append((repo_id, key, url, meta))
    entries.sort(key=lambda x: hashlib.sha256((SEED + x[0]).encode()).hexdigest())
    return entries[offset:offset + count], len(entries)


def download_archive(url, commit, target):
    if target.exists():
        return
    repo = url.removesuffix('.git').removeprefix('https://github.com/').strip('/')
    if not url.startswith('https://github.com/') or len(repo.split('/')) != 2:
        raise ValueError('Unsupported snapshot URL')
    request = urllib.request.Request(f'https://codeload.github.com/{repo}/tar.gz/{commit}',
                                     headers={'User-Agent': 'RepoRanger-external-evaluation'})
    temporary = target.with_suffix('.partial')
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=90) as response, temporary.open('wb') as out:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE:
                        raise ValueError('Archive exceeds pilot size limit')
                    out.write(chunk)
            temporary.replace(target)
            return
        except (http.client.IncompleteRead, ConnectionError, TimeoutError):
            if attempt == 2:
                raise
        finally:
            temporary.unlink(missing_ok=True)



def evaluate(root, cache, count, download=False, offset=0, git_fallback=False, feature_rows=None, max_file_bytes=5*1024*1024, triage=False, use_original_paths=False):
    entries, population = selected_repositories(root, count, offset)
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    cache.mkdir(parents=True, exist_ok=True)
    totals = Counter()
    categories = {}
    priority = Counter()
    classifier, confidence, risk = CandidateClassifier(), ConfidenceEngine(), RiskEngine()
    repositories = []
    engine = DetectionEngine()
    analyzer, extractor = FindingAnalyzer(), FeatureExtractor()
    for repo_id, key, url, meta in entries:
        with meta.open(encoding='utf-8', newline='') as source:
            rows = list(csv.DictReader(source))
        by_file = {}
        for row in rows:
            by_file.setdefault(row['FileID'], []).append(row)
        archive = cache / (repo_id + '.tar.gz')
        stats = Counter(expected_files=len(by_file), expected_annotations=len(rows))
        try:
            if download:
                try:
                    download_archive(url, key[:40], archive)
                except urllib.error.HTTPError as exc:
                    if not git_fallback or exc.code not in (422, 500, 502, 503, 504):
                        raise
                    stats['archive_download_fallbacks'] += 1
            seen = set()
            paths = {} if use_original_paths else None
            for file_id, size, raw in source_members(archive, by_file, cache, key, url, git_fallback, stats, max_file_bytes, paths):
                if file_id in seen:
                    raise ValueError('Duplicate file ID in archive')
                seen.add(file_id)
                labels = by_file[file_id]
                if size > max_file_bytes:
                    stats['oversized_files'] += 1
                    continue
                try:
                    source = raw.decode('utf-8-sig')
                except UnicodeDecodeError:
                    stats['undecodable_files'] += 1
                    continue
                line_count = len(source.splitlines())
                if any(not 1 <= int(r['LineStart']) <= int(r['LineEnd']) <= line_count for r in labels):
                    stats['invalid_label_files'] += 1
                    continue
                path = paths[file_id] if paths is not None else labels[0]['FilePath']
                file = NormalizedTextFile(FileMetadata(path, len(raw), datetime.now(timezone.utc), 'utf-8'), source)
                findings = engine.scan(ParsedRepository(RepositoryMetadata('external', 'external'), (file,))).findings
                if feature_rows is not None or triage:
                    analyzed = analyzer.analyze(ParsedRepository(RepositoryMetadata('external', 'external'), (file,)))
                    for item in analyzed:
                        kind = classify_alert(item.finding.line_start, item.finding.line_end, labels)
                        if feature_rows is not None and kind in ('true_positive', 'false_positive'):
                            feature_rows.append({'group': repo_id, 'label': int(kind == 'true_positive'),
                                'features': dict(extractor.extract(item.finding, item.validation, item.context).values)})
                if triage:
                    retained = []
                    for item in analyzed:
                        vector = extractor.extract(item.finding, item.validation, item.context)
                        assessment = risk.assess(item.finding, confidence.assess(classifier.classify(vector), vector))
                        band = 'medium_or_higher' if assessment.score >= 0.4 else 'low'
                        priority[band + '_' + classify_alert(item.finding.line_start, item.finding.line_end, labels)] += 1
                        if band == 'medium_or_higher':
                            retained.append(item.finding)
                    for row in labels:
                        if row['GroundTruth'] == 'T':
                            hit = any(f.line_start <= int(row['LineEnd']) and f.line_end >= int(row['LineStart']) for f in retained)
                            priority['positive_annotations_' + ('detected' if hit else 'missed')] += 1
                stats['scanned_files'] += 1
                stats['alerts'] += len(findings)
                for finding in findings:
                    stats['alerts_' + classify_alert(finding.line_start, finding.line_end, labels)] += 1
                for row in labels:
                    label = row['GroundTruth']
                    stats['annotations_' + label] += 1
                    hit = any(f.line_start <= int(row['LineEnd']) and f.line_end >= int(row['LineStart']) for f in findings)
                    if label == 'T':
                        stats['positive_annotations_detected' if hit else 'positive_annotations_missed'] += 1
                        cat = categories.setdefault(row['Category'], Counter())
                        cat['detected' if hit else 'missed'] += 1
            stats['missing_files'] = len(set(by_file) - seen)
        except (OSError, ValueError, http.client.IncompleteRead, tarfile.TarError, subprocess.SubprocessError) as exc:
            # Exception messages can include paths; persist only the exception type.
            stats['repository_errors'] += 1
            print(f'{repo_id}: {type(exc).__name__}', flush=True)
        totals.update(stats)
        repositories.append({'id': repo_id, 'source_commit': key[:40], 'counts': dict(stats),
                             'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest() if archive.exists() else None})
        print(f'{repo_id}: {stats["scanned_files"]}/{stats["expected_files"]} files', flush=True)
    tp, fp = totals['alerts_true_positive'], totals['alerts_false_positive']
    positives = totals['annotations_T']
    return {'dataset': 'https://github.com/Samsung/CredData', 'dataset_revision': revision,
            'detector_revision': 8, 'scoring_revision': 5 if triage else None, 'seed': SEED, 'repository_offset': offset, 'eligible_repositories': population,
            'requested_repositories': count, 'selected_repositories': len(entries),
            'file_size_limit_bytes': max_file_bytes,
            'source_mode': 'Original pinned source archives; no upstream obfuscation applied',
            'path_mode': 'original repository paths (not exported)' if use_original_paths else 'obfuscated annotation paths',
            'matching': 'Inclusive line overlap; annotation recall and alert precision use different units. Conflicting labels excluded from precision.',
            'scope': 'Independent repository sample, labeled files only; raw detection, no history, ML, live validation or risk threshold. Not a production accuracy estimate.',
            'triage': {'threshold': 0.4, 'counts': dict(priority), 'scope': 'Medium-or-higher risk review queue; low-priority findings remain visible'} if triage else None,
            'counts': dict(totals), 'labeled_alert_precision': tp / (tp + fp) if tp + fp else None,
            'positive_annotation_recall': totals['positive_annotations_detected'] / positives if positives else None,
            'categories': {k: dict(v) for k, v in sorted(categories.items())}, 'repositories': repositories}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path('tmp/creddata-archives'))
    parser.add_argument('--repositories', type=int, default=5)
    parser.add_argument('--offset', type=int, default=0, help='Skip ranked repositories already used for development')
    parser.add_argument('--download', action='store_true', help='Fetch public pinned source archives')
    parser.add_argument('--git-fallback', action='store_true', help='Fetch pinned Git objects for archive omissions')
    parser.add_argument('--max-file-mib', type=int, default=5, help='Benchmark-only source size bound, 1-64 MiB')
    parser.add_argument('--original-paths', action='store_true', help='Use original paths in memory for context features; never export paths')
    parser.add_argument('--triage', action='store_true', help='Also measure the medium-or-higher risk review queue; keeps all raw findings')
    parser.add_argument('--features', type=Path, help='Export numeric, repository-grouped labeled candidate features')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.max_file_mib <= 64:
        parser.error('--max-file-mib must be between 1 and 64')
    if args.repositories < 1 or args.offset < 0:
        parser.error('--repositories must be positive and --offset nonnegative')
    rows = [] if args.features else None
    report = evaluate(args.metadata, args.cache, args.repositories, args.download, args.offset, args.git_fallback, rows, args.max_file_mib*1024*1024, args.triage, args.original_paths)
    if args.features:
        args.features.parent.mkdir(parents=True, exist_ok=True)
        args.features.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows), encoding='utf-8')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': report['counts'], 'precision': report['labeled_alert_precision'],
                      'recall': report['positive_annotation_recall']}, indent=2))
    return int(any(report['counts'].get(key, 0) for key in ('repository_errors', 'missing_files', 'oversized_files', 'undecodable_files', 'invalid_label_files')))


if __name__ == '__main__':
    raise SystemExit(main())
