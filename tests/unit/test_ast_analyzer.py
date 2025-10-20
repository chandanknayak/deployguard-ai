"""
tests/unit/test_ast_analyzer.py — Unit tests for the Python AST analyzer.

Tests cover:
    - Plain function detection and qualification
    - Class method detection
    - FastAPI route handler detection (GET, POST, PUT, DELETE)
    - Flask route handler detection (with methods= kwarg)
    - Async function / async method detection
    - Nested function handling
    - Overlap detection (modified lines vs symbol boundaries)
    - Empty modified lines → empty result
    - Syntax error handling
    - Multi-decorator functions
"""

from __future__ import annotations

import pytest

from deployguard.core.ast_analyzer import ASTAnalyzer, analyze_file
from deployguard.exceptions import ASTAnalysisError
from deployguard.models.analysis import SymbolKind


# ──────────────────────────────────────────────────────────────────────────
# Fixtures — Python source strings
# ──────────────────────────────────────────────────────────────────────────


SIMPLE_FUNCTION_SOURCE = """\
def add(a: int, b: int) -> int:
    return a + b


def subtract(a: int, b: int) -> int:
    return a - b
"""

CLASS_WITH_METHODS_SOURCE = """\
class PaymentService:
    def __init__(self) -> None:
        self.gateway = None

    def charge(self, amount: float) -> bool:
        return self.gateway.charge(amount)

    async def async_refund(self, txn_id: str) -> bool:
        return await self.gateway.refund(txn_id)
"""

FASTAPI_SOURCE = """\
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.post("/charge")
async def charge_card(request: dict) -> dict:
    return {"charged": True}


@router.put("/update/{item_id}")
def update_item(item_id: int, data: dict) -> dict:
    return {}


@router.delete("/cancel/{txn_id}")
async def cancel_transaction(txn_id: str) -> dict:
    return {"cancelled": True}
"""

FLASK_SOURCE = """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["GET", "POST"])
def login():
    return "ok"


@app.route("/logout")
def logout():
    return "bye"
"""

NESTED_FUNCTION_SOURCE = """\
def outer():
    x = 1

    def inner():
        return x

    return inner
"""

ASYNC_FUNCTION_SOURCE = """\
async def fetch_data(url: str) -> bytes:
    pass


async def process_data(raw: bytes) -> dict:
    pass
"""

MULTI_DECORATOR_SOURCE = """\
import functools


def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper


@require_auth
@router.post("/secure")
async def secure_endpoint():
    return {}
"""

INVALID_SYNTAX_SOURCE = """\
def broken(:
    pass
"""


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────


def _lines(*ranges: range) -> set[int]:
    """Build a set of line numbers from one or more ranges."""
    result: set[int] = set()
    for r in ranges:
        result.update(r)
    return result


# ──────────────────────────────────────────────────────────────────────────
# Tests — Plain Functions
# ──────────────────────────────────────────────────────────────────────────


class TestPlainFunctionDetection:
    analyzer = ASTAnalyzer()

    def test_finds_function_overlapping_modified_line(self) -> None:
        # Line 2 is inside `add` (lines 1-2)
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        assert any(s.name == "add" for s in affected)

    def test_does_not_return_function_outside_modified_lines(self) -> None:
        # Line 2 is inside `add`; `subtract` starts at line 5
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        assert not any(s.name == "subtract" for s in affected)

    def test_kind_is_function(self) -> None:
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        add_sym = next(s for s in affected if s.name == "add")
        assert add_sym.kind == SymbolKind.FUNCTION

    def test_qualified_name_is_bare_for_top_level(self) -> None:
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        add_sym = next(s for s in affected if s.name == "add")
        assert add_sym.qualified_name == "add"

    def test_both_functions_returned_when_both_lines_modified(self) -> None:
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2, 6})
        names = {s.name for s in affected}
        assert "add" in names
        assert "subtract" in names

    def test_empty_modified_lines_returns_empty(self) -> None:
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", set())
        assert affected == []

    def test_modified_lines_overlap_populated(self) -> None:
        affected = self.analyzer.analyze(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        add_sym = next(s for s in affected if s.name == "add")
        assert 2 in add_sym.modified_lines_overlap


# ──────────────────────────────────────────────────────────────────────────
# Tests — Classes and Methods
# ──────────────────────────────────────────────────────────────────────────


class TestClassMethodDetection:
    analyzer = ASTAnalyzer()

    def test_class_symbol_detected(self) -> None:
        # Line 1 is the class definition
        affected = self.analyzer.analyze(CLASS_WITH_METHODS_SOURCE, "service.py", {1})
        assert any(s.name == "PaymentService" for s in affected)

    def test_class_symbol_kind_is_class(self) -> None:
        affected = self.analyzer.analyze(CLASS_WITH_METHODS_SOURCE, "service.py", {1})
        cls_sym = next(s for s in affected if s.name == "PaymentService")
        assert cls_sym.kind == SymbolKind.CLASS

    def test_method_kind_is_method(self) -> None:
        # Line 6 is inside the `charge` method
        affected = self.analyzer.analyze(CLASS_WITH_METHODS_SOURCE, "service.py", {6})
        charge = next((s for s in affected if s.name == "charge"), None)
        assert charge is not None
        assert charge.kind == SymbolKind.METHOD

    def test_async_method_kind_is_async_method(self) -> None:
        # Line 9 is inside `async_refund`
        affected = self.analyzer.analyze(CLASS_WITH_METHODS_SOURCE, "service.py", {9})
        refund = next((s for s in affected if s.name == "async_refund"), None)
        assert refund is not None
        assert refund.kind == SymbolKind.ASYNC_METHOD

    def test_method_qualified_name_includes_class(self) -> None:
        affected = self.analyzer.analyze(CLASS_WITH_METHODS_SOURCE, "service.py", {6})
        charge = next(s for s in affected if s.name == "charge")
        assert charge.qualified_name == "PaymentService.charge"


# ──────────────────────────────────────────────────────────────────────────
# Tests — FastAPI Route Detection
# ──────────────────────────────────────────────────────────────────────────


class TestFastAPIRouteDetection:
    analyzer = ASTAnalyzer()

    def test_get_route_detected(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {7})
        route = next((s for s in affected if s.name == "health_check"), None)
        assert route is not None
        assert route.kind == SymbolKind.FASTAPI_ROUTE

    def test_get_route_http_method(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {7})
        route = next(s for s in affected if s.name == "health_check")
        assert "GET" in route.http_methods

    def test_get_route_path_extracted(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {7})
        route = next(s for s in affected if s.name == "health_check")
        assert route.route_path == "/health"

    def test_post_route_detected(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {12})
        route = next((s for s in affected if s.name == "charge_card"), None)
        assert route is not None
        assert route.kind == SymbolKind.FASTAPI_ROUTE

    def test_post_route_http_method(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {12})
        route = next(s for s in affected if s.name == "charge_card")
        assert "POST" in route.http_methods

    def test_post_route_path_extracted(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {12})
        route = next(s for s in affected if s.name == "charge_card")
        assert route.route_path == "/charge"

    def test_delete_route_detected(self) -> None:
        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {23})
        route = next((s for s in affected if s.name == "cancel_transaction"), None)
        assert route is not None
        assert "DELETE" in route.http_methods

    def test_has_api_changes_flag(self) -> None:
        """FileAnalysis.has_api_changes should be True when route handlers are affected."""
        from deployguard.models.analysis import FileAnalysis, SymbolKind

        affected = self.analyzer.analyze(FASTAPI_SOURCE, "api.py", {7})
        assert any(s.kind == SymbolKind.FASTAPI_ROUTE for s in affected)


# ──────────────────────────────────────────────────────────────────────────
# Tests — Flask Route Detection
# ──────────────────────────────────────────────────────────────────────────


class TestFlaskRouteDetection:
    analyzer = ASTAnalyzer()

    def test_flask_route_detected(self) -> None:
        # Line 8 is inside the `login` function
        affected = self.analyzer.analyze(FLASK_SOURCE, "views.py", {8})
        login = next((s for s in affected if s.name == "login"), None)
        assert login is not None
        assert login.kind == SymbolKind.FLASK_ROUTE

    def test_flask_route_methods_extracted(self) -> None:
        affected = self.analyzer.analyze(FLASK_SOURCE, "views.py", {8})
        login = next(s for s in affected if s.name == "login")
        assert "GET" in login.http_methods
        assert "POST" in login.http_methods

    def test_flask_route_path_extracted(self) -> None:
        affected = self.analyzer.analyze(FLASK_SOURCE, "views.py", {8})
        login = next(s for s in affected if s.name == "login")
        assert login.route_path == "/login"

    def test_flask_route_without_methods_kwarg(self) -> None:
        # `logout` has @app.route("/logout") with no `methods=` kwarg
        affected = self.analyzer.analyze(FLASK_SOURCE, "views.py", {13})
        logout = next((s for s in affected if s.name == "logout"), None)
        assert logout is not None
        assert logout.kind == SymbolKind.FLASK_ROUTE
        assert logout.http_methods == []  # No methods kwarg → empty list


# ──────────────────────────────────────────────────────────────────────────
# Tests — Async Functions
# ──────────────────────────────────────────────────────────────────────────


class TestAsyncFunctionDetection:
    analyzer = ASTAnalyzer()

    def test_async_function_kind(self) -> None:
        affected = self.analyzer.analyze(ASYNC_FUNCTION_SOURCE, "async_mod.py", {2})
        fetch = next((s for s in affected if s.name == "fetch_data"), None)
        assert fetch is not None
        assert fetch.kind == SymbolKind.ASYNC_FUNCTION

    def test_second_async_function_detected(self) -> None:
        affected = self.analyzer.analyze(ASYNC_FUNCTION_SOURCE, "async_mod.py", {6})
        process = next((s for s in affected if s.name == "process_data"), None)
        assert process is not None
        assert process.kind == SymbolKind.ASYNC_FUNCTION


# ──────────────────────────────────────────────────────────────────────────
# Tests — Nested Functions
# ──────────────────────────────────────────────────────────────────────────


class TestNestedFunctionDetection:
    analyzer = ASTAnalyzer()

    def test_outer_function_detected(self) -> None:
        affected = self.analyzer.analyze(NESTED_FUNCTION_SOURCE, "nested.py", {2})
        assert any(s.name == "outer" for s in affected)

    def test_inner_function_qualified_name(self) -> None:
        # Line 5 is inside `inner`
        affected = self.analyzer.analyze(NESTED_FUNCTION_SOURCE, "nested.py", {5})
        inner = next((s for s in affected if s.name == "inner"), None)
        assert inner is not None
        assert inner.qualified_name == "outer.inner"

    def test_results_sorted_by_start_line(self) -> None:
        affected = self.analyzer.analyze(NESTED_FUNCTION_SOURCE, "nested.py", {2, 5})
        start_lines = [s.start_line for s in affected]
        assert start_lines == sorted(start_lines)


# ──────────────────────────────────────────────────────────────────────────
# Tests — Error Handling
# ──────────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    analyzer = ASTAnalyzer()

    def test_syntax_error_raises_ast_analysis_error(self) -> None:
        with pytest.raises(ASTAnalysisError) as exc_info:
            self.analyzer.analyze(INVALID_SYNTAX_SOURCE, "broken.py", {1})
        assert exc_info.value.filename == "broken.py"
        assert exc_info.value.original_error is not None

    def test_convenience_function_analyze_file(self) -> None:
        affected = analyze_file(SIMPLE_FUNCTION_SOURCE, "math.py", {2})
        assert any(s.name == "add" for s in affected)

