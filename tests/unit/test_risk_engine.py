"""
tests/unit/test_risk_engine.py — Tests for AST structural compatibility diffing,
cross-file dependency tracing, and deterministic 40/30/20/10 risk scoring.
"""

from __future__ import annotations

from deployguard.core.ast_analyzer import (
    ASTAnalyzer,
    build_cross_file_impact_graph,
    compare_ast_versions,
)
from deployguard.core.comment_renderer import REPORT_MARKER, render_pr_comment
from deployguard.core.risk_engine import RiskEvaluationInput, compute_risk_assessment
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel


BASE_PAYMENT_CODE = """\
from fastapi import APIRouter

router = APIRouter()

@router.post("/v1/payments/charge")
def process_charge_v1(order_id: str, amount: int) -> dict:
    return {"ok": True}

def helper_ok(x: int) -> int:
    return x + 1
"""

HEAD_BREAKING_CODE = """\
from fastapi import APIRouter

router = APIRouter()

@router.post("/v2/payments/charge")
def process_charge_v2(order_id: str, amount: int) -> dict:
    return {"ok": True}

def helper_ok(x: int, extra_required: str) -> int:
    return x + 1
"""

HEAD_NON_BREAKING_CODE = """\
from fastapi import APIRouter

router = APIRouter()

@router.post("/v1/payments/charge")
def process_charge_v1(order_id: str, amount: int) -> dict:
    return {"ok": True}

def helper_ok(x: int, optional_flag: bool = False) -> int:
    return x + 1

def new_utility(name: str) -> str:
    return name.upper()
"""

CONSUMER_CHECKOUT_CODE = """\
from fastapi import APIRouter
from services.payments import process_charge_v1

router = APIRouter()

@router.post("/checkout/pay")
def checkout_pay(order_id: str):
    return process_charge_v1(order_id, 100)
"""


class TestCompareAstVersions:
    def test_detects_removed_route_and_breaking_signature(self):
        res = compare_ast_versions(BASE_PAYMENT_CODE, HEAD_BREAKING_CODE, "services/payments.py")
        assert res["has_breaking_changes"] is True
        types = {bc["type"] for bc in res["breaking_changes"]}
        symbols = {bc["symbol"] for bc in res["breaking_changes"]}
        assert "REMOVED_ROUTE" in types
        assert "BREAKING_SIGNATURE" in types
        assert "process_charge_v1" in symbols
        assert "helper_ok" in symbols

    def test_allows_optional_arg_with_default_and_new_function(self):
        res = compare_ast_versions(BASE_PAYMENT_CODE, HEAD_NON_BREAKING_CODE, "services/payments.py")
        assert res["has_breaking_changes"] is False
        assert res["breaking_changes"] == []
        assert "new_utility" in res["added_symbols"]


class TestCrossFileImpactGraph:
    def test_traces_consumer_file_and_route(self):
        graph = build_cross_file_impact_graph(
            module_sources={
                "services/payments.py": BASE_PAYMENT_CODE,
                "routes/checkout.py": CONSUMER_CHECKOUT_CODE,
            },
            changed_file_symbols={"services/payments.py": ["process_charge_v1"]},
        )
        assert "routes/checkout.py" in graph["downstream_consumers"]
        assert "POST /checkout/pay" in graph["affected_routes"]
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["symbol"] == "process_charge_v1"


class TestDeterministicRiskEngine:
    def test_docs_only_pr_scores_zero_and_passes(self):
        out = compute_risk_assessment(
            RiskEvaluationInput(
                repo_full_name="acme/payments",
                changed_filenames=["README.md", "docs/architecture.png"],
                additions=40,
                deletions=5,
            )
        )
        assert out["risk_score"] == 0
        assert out["risk_level"] == RiskLevel.PASS.value
        assert out["is_docs_or_config_only"] is True
        assert out["signals"] == {"ast": 0, "blast": 0, "critical_path": 0, "test_gap": 0}

    def test_empty_diff_scores_zero_not_unknown(self):
        out = compute_risk_assessment(
            RiskEvaluationInput(repo_full_name="acme/payments", changed_filenames=[])
        )
        assert out["risk_score"] == 0
        assert out["risk_level"] == RiskLevel.PASS.value

    def test_breaking_route_with_p0_consumer_blocks(self):
        cmp_res = compare_ast_versions(BASE_PAYMENT_CODE, HEAD_BREAKING_CODE, "services/payments.py")
        out = compute_risk_assessment(
            RiskEvaluationInput(
                repo_full_name="acme/payments",
                changed_filenames=["services/payments.py"],
                additions=10,
                deletions=12,
                breaking_changes=cmp_res["breaking_changes"],
                downstream_consumers=["routes/checkout.py"],
                has_p0_impact=True,
            )
        )
        assert out["risk_level"] == RiskLevel.BLOCK.value
        assert out["risk_score"] >= 70
        assert out["signals"]["ast"] > 50
        assert out["signals"]["test_gap"] >= 40

    def test_test_coverage_reduces_test_gap_signal(self):
        syms = ASTAnalyzer().analyze(HEAD_NON_BREAKING_CODE, "utils/helper.py", {12, 13})
        fa = FileAnalysis(filename="utils/helper.py", language="python", is_ast_eligible=True, affected_symbols=syms)
        no_tests = compute_risk_assessment(
            RiskEvaluationInput(
                repo_full_name="acme/utils",
                changed_filenames=["utils/helper.py"],
                file_analyses=[fa],
                additions=12,
            )
        )
        with_tests = compute_risk_assessment(
            RiskEvaluationInput(
                repo_full_name="acme/utils",
                changed_filenames=["utils/helper.py", "tests/test_helper.py"],
                file_analyses=[fa],
                additions=12,
            )
        )
        assert with_tests["signals"]["test_gap"] < no_tests["signals"]["test_gap"]


def test_comment_renderer_includes_marker_signals_and_breaking_changes():
    res = AnalysisResult(
        assessment_id="abc12345-0000-0000-0000-000000000000",
        pr_number=103,
        repo_full_name="acme/payments",
        head_sha="deadbeef1234",
        risk_level=RiskLevel.BLOCK,
        risk_score=88,
        source="GITHUB_WEBHOOK",
        signal_breakdown={"ast": 95, "blast": 90, "critical_path": 90, "test_gap": 75},
        breaking_changes=[{"type": "REMOVED_ROUTE", "file": "payments.py", "detail": "Removed /v1/charge"}],
        dependency_edges=[{"source_file": "payments.py", "symbol": "charge", "consumer_file": "checkout.py", "consumer_routes": ["POST /pay"]}],
    )
    md = render_pr_comment(res)
    assert REPORT_MARKER in md
    assert "Weighted Risk Signals" in md
    assert "Breaking Changes Detected" in md
    assert "Cross-File Dependency Impact" in md


def test_shared_pipeline_runs_deterministically_without_agent():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from deployguard.core.pipeline import run_pr_analysis

    async def _run():
        mock_gh = MagicMock()
        mock_gh.__aenter__ = AsyncMock(return_value=mock_gh)
        mock_gh.__aexit__ = AsyncMock(return_value=None)
        mock_gh.get_pull_request = AsyncMock(return_value={
            "title": "refactor: drop v1 endpoint",
            "user": {"login": "sam"},
            "head": {"sha": "head123", "ref": "drop-v1"},
            "base": {"sha": "base123", "ref": "main"},
            "additions": 3,
            "deletions": 8,
        })
        mock_gh.get_pull_request_diff = AsyncMock(return_value=(
            "diff --git a/services/payments.py b/services/payments.py\n"
            "--- a/services/payments.py\n"
            "+++ b/services/payments.py\n"
            "@@ -1,4 +1,2 @@\n"
            "-@router.post('/v1/payments/charge')\n"
            "-def process_charge_v1(order_id: str, amount: int):\n"
            "+def noop():\n"
            "+    return None\n"
        ))
        mock_gh.get_repo_python_files = AsyncMock(return_value=["routes/checkout.py"])

        async def _try_get(path, ref):
            if path == "services/payments.py" and ref == "base123":
                return BASE_PAYMENT_CODE
            if path == "services/payments.py" and ref == "head123":
                return "def noop():\n    return None\n"
            if path == "routes/checkout.py" and ref == "head123":
                return CONSUMER_CHECKOUT_CODE
            return None

        mock_gh.try_get_file_content = AsyncMock(side_effect=_try_get)
        mock_gh.create_check_run = AsyncMock(return_value={"id": 1})
        mock_gh.upsert_pr_comment = AsyncMock(return_value={"id": 2})

        with patch("deployguard.core.pipeline.GitHubClient", return_value=mock_gh):
            result = await run_pr_analysis(
                repo_full_name="acme/payments",
                pr_number=77,
                source="GITHUB_WEBHOOK",
                agent=None,  # Explicitly prove no UNKNOWN even when OpenAI is disabled
                db_client=None,
                post_to_github=True,
            )

        assert result.status == "COMPLETED"
        assert result.risk_level == RiskLevel.BLOCK
        assert result.risk_score >= 70
        assert result.source == "GITHUB_WEBHOOK"
        assert any(bc["type"] == "REMOVED_ROUTE" for bc in result.breaking_changes)
        assert any(e["consumer_file"] == "routes/checkout.py" for e in result.dependency_edges)
        mock_gh.create_check_run.assert_awaited_once()
        mock_gh.upsert_pr_comment.assert_awaited_once()

    asyncio.run(_run())

