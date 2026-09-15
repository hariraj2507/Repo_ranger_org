"""Join detector findings with syntax-only source context."""
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
import re

from backend.detectors.detection_engine import DetectionResult
from backend.detectors.finding import Finding
from backend.scanner.models import ParsedRepository

from .python_ast import PythonAstAnalyzer
from .tree_sitter_parser import TreeSitterParser, TreeSitterUnavailableError


@dataclass(frozen=True, slots=True)
class CodeContext:
    """Safe structural source context for a finding, with no source text."""

    language: str
    symbol_name: str | None
    symbol_kind: str
    start_line: int
    end_line: int
    enclosing_symbols: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EnrichedFinding:
    """A finding paired with optional source-code structure."""

    finding: Finding
    context: CodeContext


@dataclass(frozen=True, slots=True)
class ContextResult:
    """Context-enriched detector output for a parsed repository."""

    detection_result: DetectionResult
    findings: tuple[EnrichedFinding, ...]


class ContextEngine:
    """Enrich findings using source structure while preserving secret safety."""

    _LANGUAGES = {
        ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "tsx",
        ".go": "go", ".java": "java", ".rb": "ruby", ".rs": "rust",
    }

    def __init__(
        self,
        python_analyzer: PythonAstAnalyzer | None = None,
        tree_sitter_parser: TreeSitterParser | None = None,
    ) -> None:
        self._python_analyzer = python_analyzer or PythonAstAnalyzer()
        self._tree_sitter_parser = tree_sitter_parser or TreeSitterParser()
        self._logger = logging.getLogger(__name__)

    def enrich(self, detection_result: DetectionResult) -> ContextResult:
        """Return syntax-only context for every detection result finding."""
        file_text = {text_file.metadata.relative_path: text_file.text for text_file in detection_result.repository.files}
        enriched = tuple(
            EnrichedFinding(finding, self._with_evidence(finding, file_text.get(finding.file_path)))
            for finding in detection_result.findings
        )
        return ContextResult(detection_result, enriched)

    def _with_evidence(self, finding, source):
        context = self._context_for(finding, source)
        lines = source.splitlines() if source else []
        line = lines[finding.line_start-1] if 0 < finding.line_start <= len(lines) else ''
        evidence = []
        if re.match(r'\s*(?:#|//|/\*|\*|<!--)', line):
            evidence.append('comment_context')
        if re.match(r'''(?i)\s*["']?[\w.-]*(?:publishable[_-]?key|client[_-]?id|public[_-]?key)["']?\s*[:=]''', line):
            evidence.append('public_identifier_context')
        if re.match(r'''(?i)\s*["']?[\w.-]+["']?\s*[:=]\s*["']?(?:example|placeholder|changeme|your[_-]|replace[_-])''', line):
            evidence.append('placeholder_context')
        return replace(context, evidence=tuple(evidence))

    def _context_for(self, finding: Finding, source: str | None) -> CodeContext:
        """Resolve safe context or return a deterministic line-only fallback."""
        if source is None:
            return CodeContext("unknown", None, "unknown", finding.line_start, finding.line_end)
        suffix = "." + finding.file_path.rsplit(".", 1)[-1].lower() if "." in finding.file_path else ""
        if suffix == ".py":
            context = self._python_analyzer.context_at_line(source, finding.line_start)
            if context is not None:
                return CodeContext(
                    "python", context.symbol_name, context.symbol_kind,
                    context.start_line, context.end_line, context.enclosing_symbols,
                )
            return CodeContext("python", None, "unparsed", finding.line_start, finding.line_end)
        language = self._LANGUAGES.get(suffix)
        if suffix in {'.env', '.ini', '.properties', '.yaml', '.yml', '.toml', '.json', '.conf'}:
            lines = source.splitlines()
            line = lines[finding.line_start-1] if 0 < finding.line_start <= len(lines) else ''
            kind = 'assignment' if re.match(r'''\s*["']?[\w.-]+["']?\s*[:=]''', line) else 'line'
            return CodeContext('configuration', None, kind, finding.line_start, finding.line_end)
        if language is not None:
            try:
                context = self._tree_sitter_parser.context_at_line(source, language, finding.line_start)
            except TreeSitterUnavailableError:
                self._logger.debug("Tree-sitter unavailable; using line-only context for %s", finding.file_path)
            else:
                if context is not None:
                    return CodeContext(language, context.symbol_name, context.symbol_kind, context.start_line, context.end_line)
            return CodeContext(language, None, "unparsed", finding.line_start, finding.line_end)
        return CodeContext("text", None, "line", finding.line_start, finding.line_end)
