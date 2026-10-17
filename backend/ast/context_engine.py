"""Join detector findings with syntax-only source context."""
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
import re
import hashlib
from backend.detectors.entropy_detector import EntropyDetector
from backend.detectors.literal_password_detector import LiteralPasswordDetector

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
        ".php": "php",
    }
    _MAPPING_ENTRY = re.compile(
        r'''(?P<key_quote>["'])(?P<key>[^"'\r\n]{1,128})(?P=key_quote)'''
        r'''\s*(?:=>|:)\s*(?P<value_quote>["'])(?P<value>[^"'\r\n]{1,2048})(?P=value_quote)'''
    )

    @classmethod
    def _translation_values(cls, source: str) -> frozenset[str]:
        """Return fingerprints supported by a dictionary of display strings.

        This is weak scoring evidence, never a detector exclusion. Require
        multiple quoted map entries and a majority of display-like neighbors;
        neither a locale path nor a credential field name establishes it.
        """
        entries = list(cls._MAPPING_ENTRY.finditer(source))
        if len(entries) < 3:
            return frozenset()

        def text_shape(value):
            return (sum(c.isalpha() for c in value) >= 2
                    and not any(c.isdigit() for c in value)
                    and all(word.islower() or word.isupper() or word.istitle()
                            for word in re.findall(r'[^\W\d_]+', value))
                    and all(c.isalpha() or c.isspace() or c in ".,!?;:()-_" for c in value))

        def display_like(entry):
            value = entry.group('value').strip()
            return text_shape(value) and (
                any(c.isspace() for c in value)
                or any(c.isalpha() and not c.isascii() for c in value)
                or value.istitle()
                or re.sub(r'\W+', '', value).casefold()
                   == re.sub(r'\W+', '', entry.group('key')).casefold())

        if sum(display_like(entry) for entry in entries) / len(entries) < .6:
            return frozenset()
        return frozenset(hashlib.sha256(entry.group('value').strip().encode()).hexdigest()
                         for entry in entries if text_shape(entry.group('value').strip()))

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
        candidate_paths = {finding.file_path for finding in detection_result.findings}
        translation_values = {path: self._translation_values(file_text[path])
                              for path in candidate_paths if path in file_text}
        enriched = tuple(
            EnrichedFinding(finding, self._with_evidence(
                finding, file_text.get(finding.file_path), translation_values.get(finding.file_path, frozenset())))
            for finding in detection_result.findings
        )
        return ContextResult(detection_result, enriched)

    def _with_evidence(self, finding, source, translation_values=frozenset()):
        context = self._context_for(finding, source)
        lines = source.splitlines() if source else []
        line = lines[finding.line_start-1] if 0 < finding.line_start <= len(lines) else ''
        evidence = []
        if any(hashlib.sha256(match.group('value').strip().encode()).hexdigest() == finding.fingerprint
               for match in self._MAPPING_ENTRY.finditer(line)):
            evidence.append('mapping_literal_context')
            if finding.fingerprint in translation_values:
                evidence.append('translation_map_context')
        scopes = context.enclosing_symbols + ((context.symbol_name,) if context.symbol_kind in {'function', 'async_function', 'class'} and context.symbol_name else ())
        if any(re.match(r'(?:test_|Test[A-Z])', name) for name in scopes):
            evidence.append('test_context')
        if re.match(r'\s*(?:#|//|/\*|\*|<!--)', line):
            evidence.append('comment_context')
        for match in LiteralPasswordDetector._ASSIGNMENT.finditer(line):
            group = next(g for g in ('double', 'single', 'bare') if match.group(g) is not None)
            value = match.group(group).strip()
            if hashlib.sha256(value.encode()).hexdigest() != finding.fingerprint:
                continue
            name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', match.group('name')).lower()
            words = set(re.split(r'[^a-z0-9]+', name))
            if words & {'password', 'passwd', 'pwd', 'passphrase'}:
                evidence.append('password_name_context')
            if words & {'token', 'jwt'}:
                evidence.append('token_name_context')
            if (words & {'password', 'passwd', 'pwd', 'passphrase', 'secret', 'credential', 'credentials', 'authorization'}
                    or {'api', 'key'} <= words or {'private', 'key'} <= words):
                evidence.append('credential_name_context')
            if words & {'id', 'uuid', 'guid', 'fingerprint', 'checksum', 'digest', 'algorithm', 'encoding', 'certificate', 'cert', 'version', 'length'}:
                evidence.append('public_metadata_context')
            if group in {'double', 'single'}:
                evidence.append('quoted_literal_context')
                if '=>' in match.group(0)[:match.start(group)-match.start()]:
                    evidence.append('mapping_literal_context')
            if re.match(r'(?i)(?:example|placeholder|changeme|your[_-]|replace[_-])', value):
                evidence.append('placeholder_context')
            if {'public', 'key'} <= words or {'client', 'id'} <= words or 'publishable' in words:
                evidence.append('public_identifier_context')
            if words & {'expected', 'mock', 'dummy', 'fixture'}:
                evidence.append('test_value_context')
            if group == 'bare' and context.language in {'python', 'javascript', 'typescript', 'tsx', 'go', 'java', 'ruby', 'rust', 'php'}:
                evidence.append('reference_context')
        for pattern in (LiteralPasswordDetector._XML, LiteralPasswordDetector._SETTER, LiteralPasswordDetector._URL,
                        LiteralPasswordDetector._COMMAND, LiteralPasswordDetector._SQL,
                        LiteralPasswordDetector._INDEXED, EntropyDetector._AUTH_HEADER):
            for match in pattern.finditer(line):
                if hashlib.sha256(match.group('value').strip().encode()).hexdigest() == finding.fingerprint:
                    evidence.append('credential_usage_context')
                    if pattern is LiteralPasswordDetector._XML:
                        evidence.append('xml_value_context')
        return replace(context, evidence=tuple(dict.fromkeys(evidence)))

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
