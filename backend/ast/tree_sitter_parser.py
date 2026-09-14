"""Optional Tree-sitter adapter for non-Python source files."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class TreeSitterUnavailableError(RuntimeError):
    """Raised only when a non-Python parser is requested but unavailable."""


@dataclass(frozen=True, slots=True)
class TreeSitterContext:
    """Minimal language-neutral context returned by a Tree-sitter parse."""

    symbol_name: str | None
    symbol_kind: str
    start_line: int
    end_line: int


class TreeSitterParser:
    """Extract enclosing syntax nodes from an optional Tree-sitter parser.

    A parser provider can be injected for a particular Tree-sitter distribution.
    If omitted, the adapter attempts to use ``tree_sitter_languages`` when it is
    installed. The base RepoRanger installation remains dependency-free.
    """

    _PREFERRED_NODE_TYPES = frozenset({
        "class_declaration", "class_definition", "function_declaration", "function_definition",
        "method_definition", "method_declaration", "arrow_function", "lexical_declaration",
        "variable_declaration", "assignment_expression",
    })

    def __init__(self, parser_provider: Callable[[str], Any] | None = None) -> None:
        self._parser_provider = parser_provider or self._default_provider

    def context_at_line(self, source: str, language: str, line_number: int) -> TreeSitterContext | None:
        """Return the smallest relevant named syntax node enclosing a line."""
        if line_number < 1:
            return None
        parser = self._parser_provider(language)
        tree = parser.parse(source.encode("utf-8"))
        candidates: list[Any] = []
        self._collect_candidates(tree.root_node, line_number - 1, candidates)
        if not candidates:
            return None
        node = min(candidates, key=lambda item: (item.end_point[0] - item.start_point[0], -item.start_point[0]))
        name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
        name = None
        if name_node is not None:
            name = source.encode("utf-8")[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        return TreeSitterContext(name, node.type, node.start_point[0] + 1, node.end_point[0] + 1)

    def _collect_candidates(self, node: Any, target_line: int, candidates: list[Any]) -> None:
        """Collect relevant nodes covering a zero-based source line."""
        if node.start_point[0] <= target_line <= node.end_point[0]:
            if getattr(node, "is_named", False) and node.type in self._PREFERRED_NODE_TYPES:
                candidates.append(node)
            for child in node.children:
                self._collect_candidates(child, target_line, candidates)

    @staticmethod
    def _default_provider(language: str) -> Any:
        """Load an optional parser provider only when it is actually needed."""
        try:
            from tree_sitter_languages import get_parser  # type: ignore[import-not-found]
        except ImportError as exc:
            raise TreeSitterUnavailableError(
                "Tree-sitter support is optional. Install tree-sitter-languages or inject a parser provider."
            ) from exc
        try:
            return get_parser(language)
        except (AttributeError, TypeError, ValueError) as exc:
            raise TreeSitterUnavailableError(
                f"No Tree-sitter grammar is available for language: {language}"
            ) from exc
