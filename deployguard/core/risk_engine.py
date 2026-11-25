"""
core/risk_engine.py — Deterministic Weighted Multi-Signal Risk Engine.

Eliminates UNKNOWN verdicts on valid PRs by combining four deterministic
signals into a transparent 0-100 risk score and state machine:

    1. AST Structural Diff       (Weight: 40%)
    2. Cross-File & Graph Blast  (Weight: 30%)
    3. Critical Path Sensitivity (Weight: 20%)
    4. Test-to-Churn Coverage    (Weight: 10%)

State Machine:
    0  - 35 : PASS  (SAFE)
    36 - 69 : WARN  (REVIEW_REQUIRED)
    70 - 100: BLOCK (BLOCKED)

Explicit Non-Runtime / Empty Handling:
    Empty diffs (+0/-0 with no runtime files) and pure docs/assets PRs
    deterministically score 0/100 PASS ("Docs/Non-Runtime Only").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from deployguard.models.analysis import FileAnalysis, RiskLevel, SymbolKind


_DOCS_ASSET_EXTENSIONS: set[str] = {
    ".md", ".markdown", ".txt", ".rst", ".adoc",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".scss", ".less", ".map",
    ".pdf", ".csv",
}

_DOCS_EXACT_NAMES: set[str] = {
    "readme", "readme.md", "license", "license.md", "changelog.md",
    "contributing.md", ".gitignore", ".gitattributes", ".editorconfig",
}

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.py$|\.(test|spec)\.[jt]sx?$",
    re.IGNORECASE,
)

_CRITICAL_PATH_RULES: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"(auth|oauth|jwt|token|session|rbac|permission|security)", re.I), 85, "Authentication / Authorization"),
    (re.compile(r"(payment|billing|charge|stripe|checkout|ledger|invoice|refund|payout)", re.I), 90, "Payments / Financial Ledger"),
    (re.compile(r"(migration|alembic|schema|models/|database|db/)", re.I), 75, "Database Schema / Persistence"),
    (re.compile(r"(dockerfile|docker-compose|render\.yaml|\.github/workflows|terraform|k8s|helm)", re.I), 65, "Deployment / CI-CD Infra"),
    (re.compile(r"(pyproject\.toml|requirements.*\.txt|package\.json|package-lock\.json|poetry\.lock)", re.I), 55, "Runtime Dependencies"),
    (re.compile(r"(router|endpoint|api/|routes/|controller)", re.I), 60, "Public API Surface"),
]


def is_docs_or_asset_file(filename: str) -> bool:
    """Return True if filename is documentation, static asset, or repo metadata."""
    clean = filename.strip().lower().replace("\\", "/")
    basename = clean.rsplit("/", 1)[-1]
    if basename in _DOCS_EXACT_NAMES:
        return True
    ext = f".{basename.rsplit('.', 1)[-1]}" if "." in basename else ""
    if clean.startswith("docs/") and ext in _DOCS_ASSET_EXTENSIONS:
        return True
    return ext in _DOCS_ASSET_EXTENSIONS


def is_test_file(filename: str) -> bool:
    """Return True if filename belongs to automated tests."""
    return bool(_TEST_PATH_RE.search(filename.replace("\\", "/")))


@dataclass
class RiskEvaluationInput:
    """Normalized inputs for deterministic weighted risk computation."""

    repo_full_name: str
    pr_title: str = ""
    changed_filenames: list[str] = field(default_factory=list)
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0
    breaking_changes: list[dict[str, Any]] = field(default_factory=list)
    dependency_edges: list[dict[str, Any]] = field(default_factory=list)
    downstream_consumers: list[str] = field(default_factory=list)
    graph_services: list[dict[str, Any]] = field(default_factory=list)
    has_p0_impact: bool = False
    has_p1_impact: bool = False
    similar_incidents: list[dict[str, Any]] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    diff_preview: list[dict[str, str]] = field(default_factory=list)


def compute_risk_assessment(ctx: RiskEvaluationInput) -> dict[str, Any]:
    """
    Compute deterministic 0-100 score, state machine verdict, and 40/30/20/10 signals.
    """
    all_files = ctx.changed_filenames or [fa.filename for fa in ctx.file_analyses]
    max_auto_merge_score = int(ctx.policy.get("max_auto_merge_score", 35))
    block_on_p0 = bool(ctx.policy.get("block_on_p0_sla", True))
    block_on_api = bool(ctx.policy.get("block_on_api_changes", False))

    # 1. Explicit Docs / Empty Diff short-circuit (Fixes UNKNOWN & +0 -0 paradox)
    non_docs_files = [f for f in all_files if not is_docs_or_asset_file(f)]
    if not all_files or not non_docs_files:
        reason = (
            "Empty diff (+0/-0) — no runtime code modified."
            if not all_files
            else f"Docs/Asset only change ({len(all_files)} file(s): {', '.join(all_files[:3])})."
        )
        return {
            "risk_score": 0,
            "risk_level": RiskLevel.PASS.value,
            "decision": RiskLevel.PASS.value,
            "is_docs_or_config_only": True,
            "signals": {"ast": 0, "blast": 0, "critical_path": 0, "test_gap": 0},
            "deployment_strategy": "STANDARD",
            "escalation_required": False,
            "plain_explanation": f"0/100 — SAFE (Docs/Non-Runtime Only). {reason}",
            "rationale": f"Deterministic policy gate: {reason} Zero downstream or API impact.",
            "recommended_tests": ["Markdown / static asset lint check (no runtime test required)."],
            "breaking_changes": [],
            "dependency_edges": [],
            "diff_preview": ctx.diff_preview or [{"type": "ctx", "text": f"  {reason}"}],
            "affected_services": [],
        }

    # Test-only PR (safe to merge, very low risk)
    prod_files = [f for f in non_docs_files if not is_test_file(f)]
    if not prod_files:
        return {
            "risk_score": 8,
            "risk_level": RiskLevel.PASS.value,
            "decision": RiskLevel.PASS.value,
            "is_docs_or_config_only": False,
            "signals": {"ast": 5, "blast": 0, "critical_path": 5, "test_gap": 0},
            "deployment_strategy": "STANDARD",
            "escalation_required": False,
            "plain_explanation": f"8/100 — SAFE (Test Suite Only). Modifies {len(non_docs_files)} test file(s) with zero production impact.",
            "rationale": "Only automated test files modified; production behavior and public contracts are untouched.",
            "recommended_tests": ["Run modified test suite in CI."],
            "breaking_changes": [],
            "dependency_edges": [],
            "diff_preview": ctx.diff_preview or [{"type": "add", "text": f"+ Updated {len(non_docs_files)} test file(s)"}],
            "affected_services": [],
        }

    # 2. Signal 1: AST Structural Diff (Weight 40%)
    total_symbols = sum(len(fa.affected_symbols) for fa in ctx.file_analyses)
    has_api_changes = any(fa.has_api_changes for fa in ctx.file_analyses)
    has_init_change = any(
        sym.name == "__init__"
        for fa in ctx.file_analyses
        for sym in fa.affected_symbols
    )
    breaking_count = len(ctx.breaking_changes)

    ast_raw = 12
    ast_raw += min(70, breaking_count * 38)
    if has_api_changes:
        ast_raw += 22
    if has_init_change:
        ast_raw += 12
    ast_raw += min(24, total_symbols * 6)
    total_churn = ctx.additions + ctx.deletions
    if total_churn > 300:
        ast_raw += 14
    elif total_churn > 100:
        ast_raw += 7
    ast_signal = max(5, min(100, ast_raw))

    # 3. Signal 2: Blast Radius & Cross-File Impact (Weight 30%)
    consumer_count = len(ctx.downstream_consumers)
    graph_count = len(ctx.graph_services)
    blast_raw = 10
    if ctx.has_p0_impact:
        blast_raw += 55
    elif ctx.has_p1_impact:
        blast_raw += 32
    blast_raw += min(35, consumer_count * 18 + graph_count * 12)
    blast_signal = max(0, min(100, blast_raw))

    # 4. Signal 3: Critical Path Sensitivity (Weight 20%)
    matched_critical_labels: list[str] = []
    crit_max = 15
    for fname in prod_files:
        for pattern, weight, label in _CRITICAL_PATH_RULES:
            if pattern.search(fname):
                crit_max = max(crit_max, weight)
                if label not in matched_critical_labels:
                    matched_critical_labels.append(label)
    if ctx.has_p0_impact:
        crit_max = max(crit_max, 85)
    elif ctx.has_p1_impact:
        crit_max = max(crit_max, 60)
    if has_api_changes and crit_max < 70:
        crit_max = 70
    if ctx.similar_incidents:
        top_sim = max(float(inc.get("similarity_score", inc.get("similarity", 0)) or 0) for inc in ctx.similar_incidents)
        if top_sim > 1.0:
            top_sim = top_sim / 100.0
        if top_sim >= 0.80:
            crit_max = max(crit_max, 88)
        elif top_sim >= 0.65:
            crit_max = max(crit_max, 72)
    critical_signal = max(0, min(100, crit_max))

    # 5. Signal 4: Test-to-Churn Coverage Gap (Weight 10%)
    test_files = [f for f in non_docs_files if is_test_file(f)]
    if test_files:
        # Tests updated alongside prod code lowers test gap risk
        test_ratio = len(test_files) / max(1, len(prod_files))
        test_gap_signal = max(5, min(35, int(30 - test_ratio * 25)))
    else:
        if total_churn > 200 or breaking_count > 0 or total_symbols >= 3:
            test_gap_signal = 75
        elif total_churn > 40 or total_symbols >= 1:
            test_gap_signal = 45
        else:
            test_gap_signal = 20

    # 6. Composite Weighted Score (40/30/20/10) + Policy Overrides
    weighted_score = round(
        ast_signal * 0.40
        + blast_signal * 0.30
        + critical_signal * 0.20
        + test_gap_signal * 0.10
    )

    # Hard safety floor when breaking API removals or critical incidents exist
    if breaking_count >= 1:
        weighted_score = max(weighted_score, 74)
    if ctx.has_p0_impact and block_on_p0 and (has_api_changes or total_symbols >= 2 or breaking_count > 0):
        weighted_score = max(weighted_score, 72)
    if block_on_api and (has_api_changes or breaking_count > 0):
        weighted_score = max(weighted_score, 70)

    final_score = max(1, min(99, weighted_score))

    # State machine decision honoring tenant threshold
    warn_floor = max(10, max_auto_merge_score + 1)
    if final_score >= 70:
        level = RiskLevel.BLOCK
        strategy = "BLOCK" if breaking_count > 0 or final_score >= 85 else "ROLLBACK_READY"
    elif final_score >= warn_floor:
        level = RiskLevel.WARN
        strategy = "CANARY"
    else:
        level = RiskLevel.PASS
        strategy = "STANDARD"

    # Build human explanations
    svc_names = [
        s.get("service_name", s.get("service", ""))
        for s in ctx.graph_services
        if s.get("service_name") or s.get("service")
    ]
    if not svc_names:
        svc_names = [ctx.repo_full_name.split("/")[-1]]

    if breaking_count > 0:
        first_bc = ctx.breaking_changes[0].get("detail", "Breaking API/signature removal")
        plain = f"BLOCKED ({final_score}/100): {breaking_count} breaking change(s) detected — {first_bc}"
    elif level == RiskLevel.BLOCK:
        plain = f"High deployment risk ({final_score}/100) affecting {len(svc_names)} service(s) across {', '.join(matched_critical_labels) or 'core code'}."
    elif level == RiskLevel.WARN:
        plain = (
            f"Moderate risk ({final_score}/100): Modifies {total_symbols or len(prod_files)} symbol(s)/file(s)"
            f"{' touching ' + ', '.join(matched_critical_labels) if matched_critical_labels else ''}. Deploy via 10% Canary."
        )
    else:
        plain = f"Safe change ({final_score}/100): {total_symbols} symbol(s) modified across {len(prod_files)} file(s) with no breaking API changes."

    rationale_parts = [
        f"Weighted score {final_score}/100 (AST {ast_signal}%×40% + Blast {blast_signal}%×30% + CriticalPath {critical_signal}%×20% + TestGap {test_gap_signal}%×10%).",
    ]
    if matched_critical_labels:
        rationale_parts.append(f"Critical areas: {', '.join(matched_critical_labels)}.")
    if ctx.downstream_consumers:
        rationale_parts.append(f"Cross-file callers affected: {', '.join(ctx.downstream_consumers[:5])}.")
    if not test_files:
        rationale_parts.append("No test files accompanied production changes.")

    rec_tests = []
    if breaking_count > 0:
        rec_tests.append(f"Restore backward compatibility or migrate callers for: {ctx.breaking_changes[0].get('symbol', 'removed symbol')}.")
    for fa in ctx.file_analyses[:3]:
        for sym in fa.affected_symbols[:2]:
            rec_tests.append(f"Add integration/regression tests for '{sym.qualified_name}' in {fa.filename}.")
    if ctx.downstream_consumers:
        rec_tests.append(f"Run contract verification across downstream consumer(s): {', '.join(ctx.downstream_consumers[:3])}.")
    if not rec_tests:
        rec_tests.append(
            "Deploy to 10% canary and monitor 5xx / latency p95 before full rollout."
            if level != RiskLevel.PASS
            else "Run standard unit & smoke regression suite."
        )

    diff_preview = list(ctx.diff_preview)
    if not diff_preview:
        for bc in ctx.breaking_changes[:3]:
            diff_preview.append({"type": "del", "text": f"- BREAKING: {bc.get('detail', bc.get('symbol', ''))}"})
        for fa in ctx.file_analyses[:3]:
            for sym in fa.affected_symbols[:2]:
                prefix = f"[{sym.kind.value}] "
                route = f" ({','.join(sym.http_methods)} {sym.route_path})" if sym.route_path else ""
                diff_preview.append({"type": "add", "text": f"+ {prefix}{sym.qualified_name}{route} in {fa.filename}"})
        if not diff_preview:
            diff_preview.append({"type": "ctx", "text": f"  Modified {len(prod_files)} file(s): +{ctx.additions} / -{ctx.deletions}"})

    return {
        "risk_score": final_score,
        "risk_level": level.value,
        "decision": level.value,
        "is_docs_or_config_only": False,
        "signals": {
            "ast": ast_signal,
            "blast": blast_signal,
            "critical_path": critical_signal,
            "test_gap": test_gap_signal,
        },
        "deployment_strategy": strategy,
        "escalation_required": bool(ctx.has_p0_impact and final_score >= 70),
        "plain_explanation": plain,
        "rationale": " ".join(rationale_parts),
        "recommended_tests": rec_tests,
        "breaking_changes": ctx.breaking_changes,
        "dependency_edges": ctx.dependency_edges,
        "diff_preview": diff_preview,
        "affected_services": svc_names,
    }
