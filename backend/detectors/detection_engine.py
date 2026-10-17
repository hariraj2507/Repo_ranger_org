"""Orchestration for all Day 2 detectors."""
from __future__ import annotations
from backend.detectors.authorization_detector import AuthorizationDetector
from backend.detectors.structured_detector import StructuredDetector
from backend.detectors.literal_password_detector import LiteralPasswordDetector

from dataclasses import dataclass
from typing import Protocol

from backend.scanner.models import NormalizedTextFile, ParsedRepository

from .deduplication import unique_detections
from .entropy_detector import EntropyDetector
from .finding import Finding
from .regex_detector import RegexDetector


class FileDetector(Protocol):
    """Protocol enabling detector substitution in tests and future phases."""

    def detect(self, text_file: NormalizedTextFile) -> tuple[Finding, ...]:
        """Inspect a single normalized text file."""


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Detection output linked to the original parsed repository metadata."""

    repository: ParsedRepository
    findings: tuple[Finding, ...]

    @property
    def finding_count(self) -> int:
        """Return the number of unique findings."""
        return len(self.findings)


class DetectionEngine:
    """Run injected detectors and return deterministic, de-duplicated findings."""

    def __init__(self, detectors: tuple[FileDetector, ...] | None = None) -> None:
        self._detectors = detectors or (RegexDetector(), StructuredDetector(), AuthorizationDetector(), EntropyDetector(), LiteralPasswordDetector())

    def scan(self, repository: ParsedRepository) -> DetectionResult:
        """Scan all normalized files while suppressing duplicate token findings."""
        findings = unique_detections(
            (finding for text_file in repository.files for detector in self._detectors
             for finding in detector.detect(text_file)), lambda finding: finding)
        ordered = tuple(sorted(findings, key=lambda item: (item.file_path, item.line_start, item.rule_id)))
        return DetectionResult(repository, ordered)
