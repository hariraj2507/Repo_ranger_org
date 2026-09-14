"""Tests for AST and safe code-context enrichment."""
from datetime import datetime, timezone
import unittest

from backend.ast import ContextEngine, PythonAstAnalyzer, TreeSitterParser
from backend.detectors.detection_engine import DetectionResult
from backend.detectors.finding import Finding, Severity
from backend.scanner.models import FileMetadata, NormalizedTextFile, ParsedRepository, RepositoryMetadata


def detection_for(source: str, path: str, line: int) -> DetectionResult:
    """Create a detector-result fixture for a source line."""
    repository = ParsedRepository(
        RepositoryMetadata("test", "test"),
        (NormalizedTextFile(FileMetadata(path, len(source), datetime.now(timezone.utc), "utf-8"), source),),
    )
    finding = Finding.from_match(
        detector="test", rule_id="test", category="test", severity=Severity.HIGH,
        file_path=path, line_start=line, line_end=line, matched_value="secret-value",
    )
    return DetectionResult(repository, (finding,))


class AstContextTests(unittest.TestCase):
    def test_python_analyzer_prefers_assignment_and_preserves_function_context(self) -> None:
        source = "class Client:\n    def connect(self):\n        api_key = 'secret'\n"
        context = PythonAstAnalyzer().context_at_line(source, 3)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.symbol_name, "api_key")
        self.assertEqual(context.symbol_kind, "assignment")
        self.assertEqual(context.enclosing_symbols, ("Client", "connect"))

    def test_context_engine_never_returns_source_or_secret_text(self) -> None:
        result = ContextEngine().enrich(detection_for("def run():\n    token = 'secret-value'\n", "app.py", 2))
        context = result.findings[0].context
        self.assertEqual(context.symbol_name, "token")
        self.assertFalse(hasattr(context, "source"))
        self.assertNotIn("secret-value", str(context))

    def test_invalid_python_degrades_to_unparsed_context(self) -> None:
        result = ContextEngine().enrich(detection_for("def broken(:\n", "broken.py", 1))
        self.assertEqual(result.findings[0].context.symbol_kind, "unparsed")

    def test_tree_sitter_adapter_accepts_injected_parser_provider(self) -> None:
        class Node:
            def __init__(self, node_type, start, end, children=(), name=None):
                self.type, self.start_point, self.end_point = node_type, start, end
                self.children, self.is_named, self._name = children, True, name
                self.start_byte = self.end_byte = 0
            def child_by_field_name(self, field):
                return self._name if field == "name" else None
        class Parser:
            def parse(self, source):
                name = Node("identifier", (0, 9), (0, 12))
                function = Node("function_declaration", (0, 0), (2, 1), name=name)
                root = Node("program", (0, 0), (2, 1), children=(function,))
                return type("Tree", (), {"root_node": root})()
        context = TreeSitterParser(lambda language: Parser()).context_at_line("function foo() {}", "javascript", 1)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.symbol_kind, "function_declaration")
