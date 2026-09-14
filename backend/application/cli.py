"""Command-line interface for RepoRanger scans and CI policy checks."""
from __future__ import annotations

import argparse
import json
import hashlib
from backend.ml.classifier import CandidateClassifier
import sys
from dataclasses import replace, asdict
from backend.config import ScanConfig

from backend.engine.github_action import GitHubAction
from backend.engine.report_generator import ReportGenerator
from backend.engine.risk_engine import RiskLevel
from backend.scanner.models import RepositoryError
from .scan_orchestrator import ScanOrchestrator
from .report_store import ReportStore


def positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(arguments: list[str] | None = None) -> int:
    """Return 0 for success, 1 for policy findings, or 2 for scan errors."""
    parser = argparse.ArgumentParser(prog="reporanger", description="Scan a local repository or Git URL for potential credentials.")
    parser.add_argument("source", help="Local repository directory or supported Git URL")
    parser.add_argument("--format", choices=("json", "markdown", "github"), default="markdown")
    parser.add_argument("--history", action="store_true", help="Include reachable Git history (full clone for URLs)")
    parser.add_argument("--reflog", action="store_true", help="Include local reflog commit targets")
    parser.add_argument("--max-commits", type=positive_integer, default=500)
    parser.add_argument("--max-blobs", type=positive_integer, default=10_000)
    parser.add_argument("--fail-on", choices=[level.value for level in RiskLevel], help="Exit 1 for findings at this risk level or higher")
    parser.add_argument("--config", help="Explicit path to a JSON scan policy")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude a repository-relative glob; repeatable")
    parser.add_argument("--save-report", help="Save a redacted JSON snapshot to a new file")
    parser.add_argument("--compare", help="Compare with a previously saved report using identical settings")
    parser.add_argument("--model", help="Use an experimental trained JSON classifier")
    args = parser.parse_args(arguments)
    try:
        config = ScanConfig.load(args.config) if args.config else ScanConfig()
        config = replace(config, exclude=(*config.exclude, *args.exclude))
        baseline = ReportStore.load(args.compare) if args.compare else None
        classifier = CandidateClassifier.from_file(args.model) if args.model else CandidateClassifier()
        model_id = hashlib.sha256(json.dumps(classifier._weights, sort_keys=True).encode()).hexdigest()
        result = ScanOrchestrator(config=config, classifier=classifier).scan(args.source, history=args.history, reflog=args.reflog,
                                         max_commits=args.max_commits, max_blobs=args.max_blobs)
    except (RepositoryError, RuntimeError, ValueError) as exc:
        print(f"RepoRanger error: {exc}", file=sys.stderr)
        return 2
    generator = ReportGenerator()
    policy = GitHubAction().render(result.score, result.assessments,
                                  RiskLevel(args.fail_on) if args.fail_on else RiskLevel.HIGH)
    incomplete = any(stats["truncated"] or stats["incomplete"] for stats in result.history.values())
    report = generator.as_dict(result.source, result.score, result.assessments)
    report["schema_version"] = 1
    report["scan_profile"] = {
        "detector_revision": 3,
        "scoring_revision": 2, "model_id": model_id,
        "history": args.history, "reflog": args.reflog,
        "max_commits": args.max_commits, "max_blobs": args.max_blobs,
        "policy": {key: (sorted(values, key=lambda rule: rule["rule_id"]) if key == "custom_rules" else sorted(set(values)))
                   for key, values in asdict(config).items()},
    }
    report["scan"] = {"files_scanned": result.files_scanned, "skipped_files": dict(result.skipped_files),
                      "history": dict(result.history), "suppressed_findings": result.suppressed_findings}
    try:
        if baseline is not None:
            report["comparison"] = ReportStore.compare(report, baseline)
        if args.save_report:
            ReportStore.save(args.save_report, report)
    except ValueError as exc:
        print(f"RepoRanger error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "github":
        for annotation in policy.annotations:
            print(annotation)
        print(policy.summary)
        if incomplete:
            print("::warning::Git history scan is incomplete: shallow history, scan limits, or unreadable blobs.")
    else:
        print(generator.as_markdown(result.source, result.score, result.assessments))
        for kind, stats in result.history.items():
            print(f"\n{kind}: {stats['commits_scanned']} commits, {stats['blobs_scanned']} blobs, "
                  f"{stats['blobs_skipped']} skipped; truncated: {stats['truncated']}.")
    if "comparison" in report and args.format != "json":
        comparison = report["comparison"]
        print(f"Comparison: {comparison['new_count']} new, {comparison['unchanged_count']} unchanged, "
              f"{comparison['no_longer_detected_count']} no longer detected.")
    if result.suppressed_findings:
        print(f"RepoRanger: {result.suppressed_findings} findings suppressed by policy.", file=sys.stderr)
    if any(stats["shallow"] for stats in result.history.values()):
        print("RepoRanger warning: shallow repository; fetch full history with git fetch --unshallow before a complete scan.", file=sys.stderr)
    if incomplete:
        print("RepoRanger warning: Git history scan is incomplete (shallow history, scan limits, or unreadable blobs).", file=sys.stderr)
        if args.fail_on:
            return 2
    return 1 if args.fail_on and policy.should_fail else 0
