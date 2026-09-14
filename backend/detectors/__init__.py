"""Secret-detection components built on top of normalized repository text."""

from .detection_engine import DetectionEngine, DetectionResult
from .candidate import DetectionCandidate
from .finding import Finding, Severity
from .pattern_registry import PatternRegistry, default_pattern_registry

__all__ = [
    "DetectionCandidate", "DetectionEngine",
    "DetectionResult",
    "Finding",
    "PatternRegistry",
    "Severity",
    "default_pattern_registry",
]
