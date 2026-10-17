"""Disposable scan process: text analysis only, never repository code execution."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from backend.application.scan_orchestrator import ScanOrchestrator
from backend.config import ScanConfig
from backend.engine.report_generator import ReportGenerator
from backend.ml.classifier import CandidateClassifier
from backend.revisions import DETECTOR_REVISION, SCORING_REVISION
from backend.scanner.parser import RepositoryParser
from backend.scanner.repo_cloner import RepositoryCloner
from backend.scanner.workspace_manager import WorkspaceManager

from .service import (MAX_BODY_BYTES, MAX_CURRENT_BYTES, MAX_CURRENT_FILES, MAX_REPORT_FINDINGS, SCAN_TIMEOUT_SECONDS,
                      ScanRequest, SourcePolicy, hardened_environment, is_link)


class ConfinedWalker:
    """Skip links and limit the total text input collected by the parser."""

    def __init__(self) -> None:
        self.warnings: list[str] = []

    def walk(self, root: Path, ignored_directories: frozenset[str] = frozenset()) -> Iterator[Path]:
        root = root.resolve(strict=True)
        count, total_bytes = 0, 0
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            safe_directories = []
            for name in sorted(directories):
                if name in ignored_directories:
                    continue
                candidate = Path(current) / name
                if self._safe(candidate, root):
                    safe_directories.append(name)
                else:
                    self._warn("Symbolic links and junctions were skipped.")
            directories[:] = safe_directories
            for name in sorted(files):
                path = Path(current) / name
                if not self._safe(path, root):
                    self._warn("Symbolic links, junctions, or inaccessible files were skipped.")
                    continue
                try:
                    if not path.is_file():
                        continue
                    size = path.stat().st_size
                except OSError:
                    self._warn("Some files could not be read.")
                    continue
                if count >= MAX_CURRENT_FILES or total_bytes + size > MAX_CURRENT_BYTES:
                    self._warn("Current-file coverage was limited by the file or byte budget.")
                    return
                count += 1
                total_bytes += size
                yield path

    @staticmethod
    def _safe(path: Path, root: Path) -> bool:
        if is_link(path):
            return False
        try:
            path.resolve(strict=True).relative_to(root)
            return True
        except (OSError, ValueError, RuntimeError):
            return False

    def _warn(self, warning: str) -> None:
        if warning not in self.warnings:
            self.warnings.append(warning)


def _clone_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    # Use the cloner's 120-second timeout and reject redirects to other hosts.
    environment = hardened_environment()
    private_home = Path(command[-1]).parent / "git-home"
    private_home.mkdir(exist_ok=True)
    # Git's HTTP transport may otherwise consult a user's .netrc directly,
    # independently of its disabled credential helpers and global config.
    environment.update({"HOME": str(private_home), "USERPROFILE": str(private_home),
                        "XDG_CONFIG_HOME": str(private_home)})
    return subprocess.run(command, **kwargs, env=environment)


def _validate_git_metadata(root: Path, allowed_root: Path) -> None:
    """Disallow history redirected to linked worktrees or external object stores."""
    metadata = root / ".git"
    if is_link(metadata) or not metadata.is_dir():
        raise ValueError("History requires an ordinary Git repository within the allowed root")
    if (metadata / "commondir").exists() or any((metadata / "objects" / "info" / name).exists()
                                               for name in ("alternates", "http-alternates")):
        raise ValueError("Linked Git object stores are unsupported")
    for current, directories, files in os.walk(metadata, topdown=True, followlinks=False):
        for name in (*directories, *files):
            path = Path(current) / name
            if is_link(path):
                raise ValueError("Linked Git metadata is unsupported")
            path.resolve(strict=True).relative_to(allowed_root)


def scan_report(request: ScanRequest, policy: SourcePolicy) -> dict[str, object]:
    """Use the same guarded classifier and redacted report format as the CLI."""
    source = policy.validate(request.source)
    classifier = CandidateClassifier.default()
    config = ScanConfig()
    walker = ConfinedWalker()
    orchestrator = ScanOrchestrator(parser=RepositoryParser(walker=walker), config=config, classifier=classifier)
    if policy.is_remote(source):
        with WorkspaceManager() as workspace:
            path = RepositoryCloner(runner=_clone_runner).clone(source, workspace / "repository", shallow=not request.history)
            if request.history:
                _validate_git_metadata(path, workspace)
            result = orchestrator.scan(path, history=request.history,
                                       max_commits=request.max_commits, max_blobs=request.max_blobs)
            result = replace(result, source=source)
    else:
        if request.history:
            _validate_git_metadata(Path(source), policy.root)
        result = orchestrator.scan(source, history=request.history,
                                   max_commits=request.max_commits, max_blobs=request.max_blobs)
    report = ReportGenerator().as_dict(source, result.score, result.assessments[:MAX_REPORT_FINDINGS])
    report["schema_version"] = 1
    identity = classifier.model_identity()
    report["scan_profile"] = {
        "detector_revision": DETECTOR_REVISION, "scoring_revision": SCORING_REVISION,
        "model_id": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
        "model_kind": "trained_boosted_trees" if identity["trees"] is not None else "logistic",
        "ml_policy": "existing_alerts_only_v1" if identity["existing_alerts_only"] else "custom_model",
        "history": request.history, "reflog": False,
        "max_commits": request.max_commits, "max_blobs": request.max_blobs,
        "policy": asdict(config),
    }
    warnings = list(walker.warnings)
    findings_truncated = len(result.assessments) > MAX_REPORT_FINDINGS
    if findings_truncated:
        warnings.append("The report finding list was limited; summary counts include all detected findings.")
    incomplete = bool(warnings) or any(stats["truncated"] or stats["incomplete"] for stats in result.history.values())
    if any(stats["truncated"] or stats["incomplete"] for stats in result.history.values()):
        warnings.append("Git history coverage is incomplete because of scan limits, shallow history, or unreadable blobs.")
    coverage_gaps = {"too_large", "unreadable", "extraction_error"} & result.skipped_files.keys()
    if coverage_gaps:
        incomplete = True
        warnings.append("Some current files exceeded limits or could not be read.")
    if policy.is_remote(source) and request.history:
        warnings.append("Public GitHub history scans use a full clone with a 120-second clone limit and a five-minute total scan limit.")
    report["scan"] = {
        "files_scanned": result.files_scanned, "skipped_files": dict(result.skipped_files),
        "history": dict(result.history), "suppressed_findings": result.suppressed_findings,
        "incomplete": incomplete, "warnings": warnings,
        "findings_truncated": findings_truncated,
        "limits": {"scan_timeout_seconds": SCAN_TIMEOUT_SECONDS, "max_current_files": MAX_CURRENT_FILES,
                   "max_current_bytes": MAX_CURRENT_BYTES},
    }
    return report


def main() -> int:
    """Read only a bounded trusted job; emit only redacted JSON or a fixed error."""
    try:
        payload = json.loads(sys.stdin.read(MAX_BODY_BYTES + 1))
        policy = SourcePolicy(payload["root"])
        request = ScanRequest.parse(payload["request"], policy)
        report = scan_report(request, policy)
    except Exception:
        print(json.dumps({"error": "scan_failed"}))
        return 1
    print(json.dumps({"report": report}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
