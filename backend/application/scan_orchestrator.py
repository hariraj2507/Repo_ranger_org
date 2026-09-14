"""Single safe entry point that composes the current-file analysis pipeline."""
from __future__ import annotations

from pathlib import Path
from dataclasses import replace

from backend.config import ScanConfig
from backend.detectors.deduplication import finding_identity
from backend.analysis_pipeline import FindingAnalyzer
from backend.history.blob_scanner import BlobScanner
from backend.scanner.file_filter import FileFilter
from backend.history.history_scanner import HistoryScanner
from backend.history.reflog_scanner import ReflogScanner
from backend.scanner.repo_cloner import RepositoryCloner
from backend.scanner.workspace_manager import WorkspaceManager

from backend.ast.context_engine import ContextEngine
from backend.detectors.entropy_detector import EntropyDetector
from backend.detectors.regex_detector import RegexDetector
from backend.detectors.pattern_registry import PatternRegistry, default_pattern_registry
from backend.engine.risk_engine import RiskAssessment, RiskEngine
from backend.engine.score_engine import ScoreEngine
from backend.ml.classifier import CandidateClassifier
from backend.ml.confidence_engine import ConfidenceEngine
from backend.ml.feature_extractor import FeatureExtractor
from backend.scanner.models import ParsedRepository
from backend.scanner.parser import RepositoryParser

from .scan_result import ScanResult
from .validator_router import ValidatorRouter


class ScanOrchestrator:
    """Run parsing, detection, validation, context, and risk scoring in order.

    Raw detector candidates are used only inside ``_detect_and_validate``.
    They never appear in the returned ``ScanResult`` or reports.
    """

    def __init__(
        self,
        parser: RepositoryParser | None = None,
        validator_router: ValidatorRouter | None = None,
        context_engine: ContextEngine | None = None,
        feature_extractor: FeatureExtractor | None = None,
        classifier: CandidateClassifier | None = None,
        confidence_engine: ConfidenceEngine | None = None,
        risk_engine: RiskEngine | None = None,
        score_engine: ScoreEngine | None = None,
        config: ScanConfig | None = None,
    ) -> None:
        self._config = config or ScanConfig()
        self._parser = parser or RepositoryParser(file_filter=FileFilter(excluded_patterns=self._config.exclude))
        self._validator_router = validator_router or ValidatorRouter()
        self._context_engine = context_engine or ContextEngine()
        self._feature_extractor = feature_extractor or FeatureExtractor()
        self._classifier = classifier or CandidateClassifier()
        self._confidence_engine = confidence_engine or ConfidenceEngine()
        self._risk_engine = risk_engine or RiskEngine()
        self._score_engine = score_engine or ScoreEngine()
        registry = PatternRegistry((*default_pattern_registry().patterns(), *(rule.pattern() for rule in self._config.custom_rules)))
        self._candidate_detectors = (RegexDetector(registry), EntropyDetector())

    def scan(self, source: str | Path, *, history: bool = False, reflog: bool = False,
             max_commits: int = 500, max_blobs: int = 10_000) -> ScanResult:
        """Scan a local repository path or supported remote Git URL."""
        if max_commits <= 0 or max_blobs <= 0:
            raise ValueError("History limits must be positive")
        candidate = str(source)
        remote = not Path(candidate).exists() and ("://" in candidate or ("@" in candidate and ":" in candidate))
        if remote and reflog:
            raise ValueError("--reflog requires a local repository; remote reflogs cannot be cloned")
        if remote and history:
            with WorkspaceManager() as workspace:
                root = RepositoryCloner().clone(candidate, workspace / "repository", shallow=False)
                result = self.scan(root, history=True, max_commits=max_commits, max_blobs=max_blobs)
                return replace(result, source=candidate)
        parsed = self._parse_source(source)
        analyzer = FindingAnalyzer(self._candidate_detectors, self._validator_router, self._context_engine)
        analyses = analyzer.analyze(parsed)
        assessments: list[RiskAssessment] = []
        for item in analyses:
            features = self._feature_extractor.extract(item.finding, item.validation, item.context)
            classification = self._classifier.classify(features)
            confidence = self._confidence_engine.assess(classification, features)
            assessment = self._risk_engine.assess(item.finding, confidence)
            assessments.append(replace(assessment, validation=item.validation, context=item.context))
        history_stats = {}
        if history or reflog:
            scanner = HistoryScanner(blob_scanner=BlobScanner(analyzer=analyzer), max_commits=max_commits, max_blobs=max_blobs, excluded_patterns=self._config.exclude)
            scans = []
            if history:
                scans.append(("commit_history", scanner.scan(source)))
            if reflog:
                scans.append(("reflog", ReflogScanner(scanner, max_entries=max_commits).scan(source)))
            seen_history = set()
            for kind, historical in scans:
                history_stats[kind] = {
                    "commits_scanned": historical.commits_scanned,
                    "blobs_scanned": historical.blobs_scanned,
                    "blobs_skipped": historical.blobs_skipped,
                    "truncated": historical.truncated,
                    "incomplete": historical.incomplete,
                    "shallow": historical.shallow,
                }
                for item in historical.findings:
                    identity = (item.source.blob_id, *self._identity(item.finding))
                    if identity in seen_history:
                        continue
                    seen_history.add(identity)
                    features = self._feature_extractor.extract(item.finding, item.validation, item.context)
                    classification = self._classifier.classify(features)
                    confidence = self._confidence_engine.assess(classification, features)
                    assessment = self._risk_engine.assess(item.finding, confidence, item.source)
                    assessments.append(replace(assessment, validation=item.validation, context=item.context))
        suppressed = sum(self._config.suppresses(item.finding) for item in assessments)
        assessments = [item for item in assessments if not self._config.suppresses(item.finding)]
        ordered = tuple(sorted(assessments, key=lambda item: (-item.score, item.finding.file_path, item.finding.line_start)))
        score = self._score_engine.calculate(ordered)
        return ScanResult(str(source), score, ordered, parsed.file_count, parsed.metadata.skipped_files, history_stats, suppressed)

    def _parse_source(self, source: str | Path) -> ParsedRepository:
        """Use local parsing where possible, otherwise accept a Git URL."""
        candidate = str(source)
        if Path(candidate).exists():
            return self._parser.parse(candidate)
        if "://" in candidate or ("@" in candidate and ":" in candidate):
            return self._parser.parse_remote(candidate)
        return self._parser.parse(candidate)

    @staticmethod
    def _identity(finding) -> tuple[str, int, int, str]:
        """Return the safe stable identity shared by findings and validation data."""
        return finding_identity(finding)
