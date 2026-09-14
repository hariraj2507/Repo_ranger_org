"""Persist redacted scan reports and compare compatible scan snapshots."""
from __future__ import annotations

import json
from pathlib import Path
import re


class ReportStore:
    """Store portable JSON snapshots without a database or additional dependencies."""

    @staticmethod
    def save(path: str, report: dict) -> None:
        # Exclusive creation avoids accidentally destroying a previous baseline.
        try:
            with Path(path).open('x', encoding='utf-8') as output:
                json.dump(report, output, indent=2, sort_keys=True)
                output.write('\n')
        except OSError as exc:
            raise ValueError('Cannot save report; use a new filename in an existing writable directory') from exc

    @staticmethod
    def load(path: str) -> dict:
        try:
            with Path(path).open('r', encoding='utf-8-sig') as source:
                text = source.read(50_000_001)
            if len(text) > 50_000_000:
                raise ValueError('Baseline report exceeds the 50 MB limit')
            report = json.loads(text)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('Cannot read baseline as a saved JSON report') from exc
        if not isinstance(report, dict) or report.get('schema_version') != 1:
            raise ValueError('Baseline must be a version 1 saved RepoRanger report')
        return report

    @staticmethod
    def compare(current: dict, previous: dict) -> dict:
        if current.get('repository_source') != previous.get('repository_source'):
            raise ValueError('Baseline repository does not match this scan source')
        if current.get('scan_profile') != previous.get('scan_profile'):
            raise ValueError('Baseline scan settings differ; use the same detector revision, history options, limits, and policy')
        if ReportStore._incomplete(current) or ReportStore._incomplete(previous):
            raise ValueError('Cannot compare incomplete history scans; complete both scans first')
        before = ReportStore._index(previous)
        after = ReportStore._index(current)
        return {
            'new_count': len(after.keys() - before.keys()),
            'no_longer_detected_count': len(before.keys() - after.keys()),
            'unchanged_count': len(before.keys() & after.keys()),
            'new': [after[key] for key in sorted(after.keys() - before.keys())],
            'no_longer_detected': [before[key] for key in sorted(before.keys() - after.keys())],
        }

    @staticmethod
    def _incomplete(report: dict) -> bool:
        try:
            return any(stats['incomplete'] or stats['truncated']
                       for stats in report['scan']['history'].values())
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('Invalid baseline scan metadata') from exc

    @staticmethod
    def _index(report: dict) -> dict:
        findings = report.get('findings')
        if not isinstance(findings, list):
            raise ValueError('Invalid baseline findings')
        result = {}
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError('Invalid baseline finding')
            fingerprint = finding.get('fingerprint')
            path, rule = finding.get('file_path'), finding.get('rule_id')
            line = finding.get('line_start')
            history = finding.get('history', {})
            if (not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint)
                    or not isinstance(path, str) or not isinstance(rule, str)
                    or type(line) is not int or line < 1 or not isinstance(history, dict)):
                raise ValueError('Invalid baseline finding metadata')
            blob = history.get('blob_id', '')
            kind = history.get('source_kind', 'current')
            if not isinstance(blob, str) or not isinstance(kind, str):
                raise ValueError('Invalid baseline history metadata')
            # Ignore line changes and commit selection; a surviving token at the
            # same path stays unchanged. Distinct historical blob versions remain separate.
            identity = (path, rule, fingerprint, kind, blob)
            result.setdefault(identity, {'file_path': path, 'rule_id': rule, 'line_start': line,
                                         'fingerprint': fingerprint, 'source_kind': kind})
        return result
