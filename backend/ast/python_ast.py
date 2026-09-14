"""Context extraction for Python source using the standard-library AST."""
from __future__ import annotations

import ast as python_ast
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PythonAstContext:
    """The smallest named Python construct enclosing a source line."""

    symbol_name: str | None
    symbol_kind: str
    start_line: int
    end_line: int
    enclosing_symbols: tuple[str, ...]


class PythonAstAnalyzer:
    """Locate classes, functions, and assignments without executing source code."""

    def context_at_line(self, source: str, line_number: int) -> PythonAstContext | None:
        """Return the most specific AST context for ``line_number``.

        ``None`` is returned for invalid Python or a line outside the source,
        allowing a caller to gracefully fall back to line-only context.
        """
        if line_number < 1 or line_number > max(1, source.count("\n") + 1):
            return None
        try:
            module = python_ast.parse(source)
        except (SyntaxError, ValueError, TypeError):
            return None
        contexts: list[PythonAstContext] = []
        self._collect(module, (), contexts)
        matches = [
            context for context in contexts
            if context.start_line <= line_number <= context.end_line
        ]
        if not matches:
            return PythonAstContext(None, "module", 1, max(1, source.count("\n") + 1), ())
        return min(matches, key=lambda context: (context.end_line - context.start_line, -context.start_line))

    def _collect(
        self,
        node: python_ast.AST,
        enclosing_symbols: tuple[str, ...],
        contexts: list[PythonAstContext],
    ) -> None:
        """Recursively collect named scopes and assignment targets."""
        scope = self._scope_for(node, enclosing_symbols)
        if scope is not None:
            contexts.append(scope)
        next_symbols = enclosing_symbols
        if scope is not None and scope.symbol_kind in {"class", "function", "async_function"} and scope.symbol_name:
            next_symbols = (*enclosing_symbols, scope.symbol_name)
        for child in python_ast.iter_child_nodes(node):
            self._collect(child, next_symbols, contexts)

    @staticmethod
    def _scope_for(node: python_ast.AST, enclosing_symbols: tuple[str, ...]) -> PythonAstContext | None:
        """Map relevant AST nodes into a stable context model."""
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        if not isinstance(start, int) or not isinstance(end, int):
            return None
        if isinstance(node, python_ast.ClassDef):
            return PythonAstContext(node.name, "class", start, end, enclosing_symbols)
        if isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
            kind = "async_function" if isinstance(node, python_ast.AsyncFunctionDef) else "function"
            return PythonAstContext(node.name, kind, start, end, enclosing_symbols)
        if isinstance(node, (python_ast.Assign, python_ast.AnnAssign, python_ast.NamedExpr)):
            target = PythonAstAnalyzer._assignment_name(node)
            return PythonAstContext(target, "assignment", start, end, enclosing_symbols)
        return None

    @staticmethod
    def _assignment_name(node: python_ast.Assign | python_ast.AnnAssign | python_ast.NamedExpr) -> str | None:
        """Return a simple assignment target name, if one is available."""
        if isinstance(node, python_ast.Assign):
            target = node.targets[0] if node.targets else None
        else:
            target = node.target
        return target.id if isinstance(target, python_ast.Name) else None
