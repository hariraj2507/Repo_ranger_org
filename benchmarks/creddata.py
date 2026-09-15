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
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

from backend.detectors.detection_engine import DetectionEngine
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata

SEED = "reporanger-external-pilot-v1"
MAX_ARCHIVE = 150 * 1024 * 1024


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
    try:
        with urllib.request.urlopen(request, timeout=90) as response, temporary.open('wb') as out:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    raise ValueError('Archive exceeds pilot size limit')
                out.write(chunk)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def evaluate(root, cache, count, download=False, offset=0):
    entries, population = selected_repositories(root, count, offset)
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    cache.mkdir(parents=True, exist_ok=True)
    totals = Counter()
    categories = {}
    repositories = []
    engine = DetectionEngine()
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
                download_archive(url, key[:40], archive)
            with tarfile.open(archive, 'r:gz') as tar:
                seen = set()
                for member in tar:
                    if not member.isfile() or '/' not in member.name:
                        continue
                    short_path = member.name.split('/', 1)[1]
                    file_id = hashlib.sha256(short_path.encode()).hexdigest()[:8]
                    if file_id not in by_file:
                        continue
                    if file_id in seen:
                        raise ValueError('Duplicate file ID in archive')
                    seen.add(file_id)
                    labels = by_file[file_id]
                    if member.size > 5 * 1024 * 1024:
                        stats['oversized_files'] += 1
                        continue
                    raw = tar.extractfile(member).read()
                    try:
                        source = raw.decode('utf-8-sig')
                    except UnicodeDecodeError:
                        stats['undecodable_files'] += 1
                        continue
                    line_count = len(source.splitlines())
                    if any(not 1 <= int(r['LineStart']) <= int(r['LineEnd']) <= line_count for r in labels):
                        stats['invalid_label_files'] += 1
                        continue
                    path = labels[0]['FilePath']
                    file = NormalizedTextFile(FileMetadata(path, len(raw), datetime.now(timezone.utc), 'utf-8'), source)
                    findings = engine.scan(ParsedRepository(RepositoryMetadata('external', 'external'), (file,))).findings
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
        except (OSError, ValueError, tarfile.TarError) as exc:
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
            'detector_revision': 4, 'seed': SEED, 'repository_offset': offset, 'eligible_repositories': population,
            'requested_repositories': count, 'selected_repositories': len(entries),
            'source_mode': 'Original pinned source archives; no upstream obfuscation applied',
            'matching': 'Inclusive line overlap; annotation recall and alert precision use different units. Conflicting labels excluded from precision.',
            'scope': 'Independent repository sample, labeled files only; raw detection, no history, ML, live validation or risk threshold. Not a production accuracy estimate.',
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
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.repositories < 1 or args.offset < 0:
        parser.error('--repositories must be positive and --offset nonnegative')
    report = evaluate(args.metadata, args.cache, args.repositories, args.download, args.offset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': report['counts'], 'precision': report['labeled_alert_precision'],
                      'recall': report['positive_annotation_recall']}, indent=2))
    return int(any(report['counts'].get(key, 0) for key in ('repository_errors', 'missing_files', 'oversized_files', 'undecodable_files', 'invalid_label_files')))


if __name__ == '__main__':
    raise SystemExit(main())
