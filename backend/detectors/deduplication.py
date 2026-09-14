"""One deterministic duplicate policy for safe findings and raw candidates."""
from collections.abc import Callable, Iterable
from typing import TypeVar
from .finding import Finding

T = TypeVar("T")


def finding_identity(finding: Finding) -> tuple[str, int, int, str]:
    return finding.file_path, finding.line_start, finding.line_end, finding.fingerprint


def unique_detections(items: Iterable[T], to_finding: Callable[[T], Finding]) -> tuple[T, ...]:
    """Prefer signature matches over entropy matches regardless of detector order."""
    chosen = {}
    for item in items:
        finding = to_finding(item)
        identity = finding_identity(finding)
        priority = ({"regex": 0, "custom": 1, "entropy": 2}.get(finding.detector, 3), finding.rule_id)
        if identity not in chosen or priority < chosen[identity][0]:
            chosen[identity] = (priority, item)
    return tuple(chosen[key][1] for key in sorted(chosen))
