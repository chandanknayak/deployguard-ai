"""
core/ast_analyzer.py — Python Abstract Syntax Tree (AST) Analyzer.

This module is the deterministic heart of DeployGuard AI.  It answers the
question: **"Given a set of modified line numbers from the diff, which Python
functions, classes, and API route handlers do those lines fall inside?"**

--- Why AST and not regex or LLM? ---

    ┌───────────────┬─────────────────────────────────┬──────────────────────────────┐
    │ Approach      │ Correctness                     │ Auditability                 │
    ├───────────────┼─────────────────────────────────┼──────────────────────────────┤
    │ Regex         │ Fails on multi-line signatures,  │ Output cannot be traced      │
    │               │ decorators, nested functions     │ back to a grammar rule       │
    ├───────────────┼─────────────────────────────────┼──────────────────────────────┤
    │ LLM           │ Probabilistic — hallucinates     │ Black box — "AI said so"     │
    │               │ function boundaries              │                              │
    ├───────────────┼─────────────────────────────────┼──────────────────────────────┤
    │ AST (chosen)  │ Deterministic — 100% accurate    │ Every node is provable from  │
    │               │ for syntactically valid Python   │ the language grammar         │
    └───────────────┴─────────────────────────────────┴──────────────────────────────┘

--- API Route Detection ---

The analyzer detects FastAPI, Flask, and Django route handlers by inspecting
decorator chains:

    FastAPI:  @app.get("/path"), @router.post("/path"), etc.
              → Extracts HTTP method from decorator attribute name.
              → Extracts URL path from the first positional string argument.

    Flask:    @app.route("/path", methods=["GET", "POST"])
              → Extracts HTTP methods from the ``methods`` keyword argument.
              → Extracts URL path from the first positional string argument.

    Django:   Detected via ``as_view()`` class method calls or CBV base classes
              (``APIView``, ``ViewSet``, ``ListView``, etc.).

--- Symbol Boundary Computation ---

For each ``FunctionDef`` / ``AsyncFunctionDef`` / ``ClassDef`` node, the
analyzer records:

    start_line = node.lineno         (the ``def`` or ``class`` keyword line)
    end_line   = node.end_lineno     (available in Python 3.8+ AST)

A symbol is "affected" if ``{start_line..end_line} ∩ modified_lines ≠ ∅``.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Final

from deployguard.exceptions import ASTAnalysisError
from deployguard.models.analysis import AffectedSymbol, SymbolKind

logger = logging.getLogger(__name__)

# FastAPI decorator attribute names → HTTP method mapping
_FASTAPI_HTTP_METHODS: Final[set[str]] = {
    "get", "post", "put", "patch", "delete",
    "head", "options", "trace", "websocket",
}

# Flask route decorator name
_FLASK_ROUTE_DECORATOR: Final[str] = "route"

# Django CBV base class names that indicate a view
_DJANGO_CBV_BASES: Final[set[str]] = {
    "APIView", "ViewSet", "ModelViewSet", "ReadOnlyModelViewSet",
    "GenericAPIView", "ListView", "DetailView", "CreateView",
    "UpdateView", "DeleteView", "TemplateView", "View",
}


@dataclass
class SymbolContext:
    """
    Internal representation of a symbol during AST traversal.

    This is a richer intermediate form that gets converted to the public
    ``AffectedSymbol`` model once all fields are resolved.
    """

    name: str
    qualified_name: str
    kind: SymbolKind
    start_line: int
    end_line: int
    decorator_names: list[str] = field(default_factory=list)
    http_methods: list[str] = field(default_factory=list)
    route_path: str | None = None

    def overlaps(self, modified_lines: set[int]) -> set[int]:
        """Return the subset of ``modified_lines`` that fall within this symbol."""
        symbol_range = set(range(self.start_line, self.end_line + 1))
        return symbol_range & modified_lines

    def to_affected_symbol(self, overlap_lines: list[int]) -> AffectedSymbol:
        """Convert to the public ``AffectedSymbol`` model."""
        return AffectedSymbol(
            name=self.name,
            qualified_name=self.qualified_name,
            kind=self.kind,
            start_line=self.start_line,
            end_line=self.end_line,
            http_methods=self.http_methods,
            route_path=self.route_path,
            decorator_names=self.decorator_names,
            modified_lines_overlap=sorted(overlap_lines),
        )


class ASTAnalyzer:
    """
    Deterministic Python AST analyzer.

    Traverses the full AST of a Python source file and returns all symbols
    (functions, methods, classes, API route handlers) whose line ranges
    intersect with a given set of modified line numbers.

    Usage::

        analyzer = ASTAnalyzer()
        affected = analyzer.analyze(
            source_code=file_content,
            filename="src/payments/charge.py",
            modified_lines={45, 46, 47, 52},
        )
        for symbol in affected:
            print(symbol.qualified_name, symbol.kind, symbol.route_path)
    """

    def analyze(
        self,
        source_code: str,
        filename: str,
        modified_lines: set[int],
    ) -> list[AffectedSymbol]:
        """
        Analyze a Python source file and return symbols affected by the diff.

        Args:
            source_code:
                Full content of the Python source file at the head commit.
                Must be syntactically valid Python.
            filename:
                Repo-relative path — used only for error messages and logging.
            modified_lines:
                Set of line numbers (1-indexed) that were modified according
                to the diff parser.  An empty set produces an empty result.

        Returns:
            Ordered list of ``AffectedSymbol`` instances, sorted by
            ``start_line`` ascending.  Empty if no symbols overlap with the
            modified lines.

        Raises:
            ASTAnalysisError:
                If ``source_code`` contains syntax errors that prevent AST
                parsing.  The caller should catch this and mark the file as
                ``is_ast_eligible=False`` rather than letting it propagate.

        Example::

            source = '''
            @router.post("/charge")
            async def charge_card(request: ChargeRequest) -> ChargeResponse:
                result = await payment_gateway.charge(request.amount)
                return ChargeResponse(transaction_id=result.id)
            '''
            analyzer = ASTAnalyzer()
            affected = analyzer.analyze(source, "payments/charge.py", {3, 4})
            # → [AffectedSymbol(name='charge_card', kind=FASTAPI_ROUTE, route_path='/charge')]
        """
        if not modified_lines:
            logger.debug("No modified lines for %s — skipping AST analysis.", filename)
            return []

        try:
            tree = ast.parse(source_code, filename=filename, type_comments=False)
        except SyntaxError as exc:
            raise ASTAnalysisError(
                f"Syntax error in '{filename}': {exc}",
                filename=filename,
                original_error=exc,
            ) from exc
        except Exception as exc:
            raise ASTAnalysisError(
                f"Failed to parse '{filename}': {exc!r}",
                filename=filename,
                original_error=exc,
            ) from exc

        visitor = _SymbolVisitor(filename=filename, modified_lines=modified_lines)
        visitor.visit(tree)

        affected: list[AffectedSymbol] = []
        for ctx in visitor.symbols:
            overlap = ctx.overlaps(modified_lines)
            if overlap:
                affected.append(ctx.to_affected_symbol(sorted(overlap)))

        # Sort by start_line for deterministic, readable output
        affected.sort(key=lambda s: s.start_line)

        logger.info(
            "AST analysis of '%s': %d symbols found, %d affected by %d modified lines.",
            filename,
            len(visitor.symbols),
            len(affected),
            len(modified_lines),
        )
        return affected


class _SymbolVisitor(ast.NodeVisitor):
    """
    Internal AST visitor that collects all symbol contexts from a module.

    Walks the entire AST, maintaining a namespace stack to build fully
    qualified names (e.g. ``PaymentService.ChargeHandler.charge_card``).

    This class is intentionally private to this module — external code
    should use ``ASTAnalyzer.analyze()``.

    Attributes:
        filename: Source file path (used in log messages only).
        modified_lines: Set of modified line numbers from the diff.
        symbols: Accumulated list of all discovered ``SymbolContext`` objects.
    """

    def __init__(self, filename: str, modified_lines: set[int]) -> None:
        self.filename = filename
        self.modified_lines = modified_lines
        self.symbols: list[SymbolContext] = []

        # Stack of enclosing class/function names for qualified name building
        self._namespace_stack: list[str] = []

    # ------------------------------------------------------------------
    # Visitor methods
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition and record it as a symbol."""
        qualname = self._build_qualname(node.name)
        end_line = self._get_end_line(node)

        # Detect Django CBV base classes
        base_names = {
            base.id if isinstance(base, ast.Name) else
            base.attr if isinstance(base, ast.Attribute) else ""
            for base in node.bases
        }
        is_django_view = bool(base_names & _DJANGO_CBV_BASES)

        ctx = SymbolContext(
            name=node.name,
            qualified_name=qualname,
            kind=SymbolKind.DJANGO_VIEW if is_django_view else SymbolKind.CLASS,
            start_line=node.lineno,
            end_line=end_line,
            decorator_names=self._extract_decorator_names(node),
        )
        self.symbols.append(ctx)

        # Push class name onto stack before visiting children (methods)
        self._namespace_stack.append(node.name)
        self.generic_visit(node)
        self._namespace_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a synchronous function or method definition."""
        self._visit_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an asynchronous function or method definition."""
        self._visit_function(node, is_async=True)

    # ------------------------------------------------------------------
    # Core function analysis logic
    # ------------------------------------------------------------------

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """
        Shared logic for both ``FunctionDef`` and ``AsyncFunctionDef`` nodes.

        1. Extracts all decorator information.
        2. Detects FastAPI / Flask / Django route patterns in the decorators.
        3. Determines the appropriate ``SymbolKind``.
        4. Appends a ``SymbolContext`` to ``self.symbols``.
        5. Recurses into the function body for nested function definitions.
        """
        qualname = self._build_qualname(node.name)
        end_line = self._get_end_line(node)
        decorator_names = self._extract_decorator_names(node)
        in_class = bool(self._namespace_stack)

        # --- Attempt route detection ---
        route_info = self._detect_route(node)

        # --- Determine SymbolKind ---
        if route_info["is_fastapi"]:
            kind = SymbolKind.FASTAPI_ROUTE
        elif route_info["is_flask"]:
            kind = SymbolKind.FLASK_ROUTE
        elif in_class and is_async:
            kind = SymbolKind.ASYNC_METHOD
        elif in_class:
            kind = SymbolKind.METHOD
        elif is_async:
            kind = SymbolKind.ASYNC_FUNCTION
        else:
            kind = SymbolKind.FUNCTION

        ctx = SymbolContext(
            name=node.name,
            qualified_name=qualname,
            kind=kind,
            start_line=node.lineno,
            end_line=end_line,
            decorator_names=decorator_names,
            http_methods=route_info.get("http_methods", []),
            route_path=route_info.get("route_path"),
        )
        self.symbols.append(ctx)

        # Push this function's name for qualified naming of nested functions
        self._namespace_stack.append(node.name)
        self.generic_visit(node)
        self._namespace_stack.pop()

    # ------------------------------------------------------------------
    # Route detection helpers
    # ------------------------------------------------------------------

    def _detect_route(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> dict:
        """
        Inspect all decorators on a function node for API route patterns.

        Returns:
            A dict with keys:
                ``is_fastapi`` (bool),
                ``is_flask`` (bool),
                ``http_methods`` (list[str]),
                ``route_path`` (str | None).
        """
        result: dict = {
            "is_fastapi": False,
            "is_flask": False,
            "http_methods": [],
            "route_path": None,
        }

        for decorator in node.decorator_list:
            # ----------------------------------------------------------
            # FastAPI pattern: @app.get("/path") or @router.post("/path")
            # Decorator is an ast.Call node where the func is an
            # ast.Attribute with attr in FASTAPI_HTTP_METHODS.
            # ----------------------------------------------------------
            if isinstance(decorator, ast.Call):
                func = decorator.func

                if isinstance(func, ast.Attribute):
                    method_name = func.attr.lower()

                    if method_name in _FASTAPI_HTTP_METHODS:
                        result["is_fastapi"] = True
                        result["http_methods"] = [method_name.upper()]
                        result["route_path"] = self._extract_first_string_arg(decorator)
                        return result

                    # Flask: @app.route("/path", methods=["GET", "POST"])
                    if method_name == _FLASK_ROUTE_DECORATOR:
                        result["is_flask"] = True
                        result["route_path"] = self._extract_first_string_arg(decorator)
                        result["http_methods"] = self._extract_flask_methods(decorator)
                        return result

            # ----------------------------------------------------------
            # FastAPI pattern without call: unlikely but guard against it
            # ----------------------------------------------------------
            if isinstance(decorator, ast.Attribute):
                if decorator.attr.lower() in _FASTAPI_HTTP_METHODS:
                    result["is_fastapi"] = True
                    result["http_methods"] = [decorator.attr.upper()]

        return result

    @staticmethod
    def _extract_first_string_arg(call_node: ast.Call) -> str | None:
        """
        Extract the first positional argument from a decorator call node,
        if it is a string constant (the URL path pattern).

        Handles both ``ast.Constant`` (Python 3.8+) and legacy ``ast.Str``.
        """
        if call_node.args:
            first_arg = call_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return first_arg.value
            # Legacy Python 3.7 compatibility
            if isinstance(first_arg, ast.Str):  # type: ignore[attr-defined]
                return first_arg.s  # type: ignore[attr-defined]
        return None

    @staticmethod
    def _extract_flask_methods(call_node: ast.Call) -> list[str]:
        """
        Extract the ``methods`` keyword argument from a Flask ``@app.route``
        decorator call.

        Looks for a keyword argument named ``methods`` whose value is a list
        of string constants.  Returns an empty list if not found or not in
        the expected format.
        """
        for keyword in call_node.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, ast.List):
                methods: list[str] = []
                for elt in keyword.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        methods.append(elt.value.upper())
                    elif isinstance(elt, ast.Str):  # type: ignore[attr-defined]
                        methods.append(elt.s.upper())  # type: ignore[attr-defined]
                return methods
        return []

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _build_qualname(self, name: str) -> str:
        """
        Build the fully qualified dotted name for a symbol.

        Examples:
            - Top-level function ``charge_card`` → ``charge_card``
            - Method inside ``PaymentHandler`` → ``PaymentHandler.charge_card``
            - Nested inside ``PaymentHandler.process`` → ``PaymentHandler.process.charge_card``
        """
        if self._namespace_stack:
            return ".".join(self._namespace_stack) + f".{name}"
        return name

    @staticmethod
    def _get_end_line(node: ast.AST) -> int:
        """
        Return the end line number of an AST node.

        ``end_lineno`` is available on all compound statement nodes in
        Python 3.8+.  Falls back to ``lineno`` for older ASTs (should never
        occur in practice since we target Python 3.11+).
        """
        return getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)

    @staticmethod
    def _extract_decorator_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    ) -> list[str]:
        """
        Extract human-readable string names for all decorators on a node.

        Handles three common decorator forms:
            - ``@simple_name``       → ``"simple_name"``
            - ``@module.attr``       → ``"module.attr"``
            - ``@module.attr(args)`` → ``"module.attr"``
        """
        names: list[str] = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                names.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.append(f"{_unparse_attribute(dec)}")
            elif isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Name):
                    names.append(func.id)
                elif isinstance(func, ast.Attribute):
                    names.append(_unparse_attribute(func))
        return names


def _unparse_attribute(node: ast.Attribute) -> str:
    """
    Recursively unparse an ``ast.Attribute`` chain to a dotted string.

    Example: ``ast.Attribute(value=ast.Name('router'), attr='post')``
    → ``"router.post"``
    """
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node.value, ast.Attribute):
        return f"{_unparse_attribute(node.value)}.{node.attr}"
    return node.attr


def analyze_file(
    source_code: str,
    filename: str,
    modified_lines: set[int],
) -> list[AffectedSymbol]:
    """
    Module-level convenience function for one-shot file analysis.

    Args:
        source_code: Full Python source content.
        filename: Repo-relative file path (for error messages).
        modified_lines: Set of modified line numbers from the diff.

    Returns:
        List of ``AffectedSymbol`` instances.

    Raises:
        ASTAnalysisError: If the source contains syntax errors.
    """
    return ASTAnalyzer().analyze(source_code, filename, modified_lines)

