"""
core/comment_renderer.py — Renders Markdown PR comments from Risk Assessment results.
"""

from __future__ import annotations

from deployguard.models.analysis import AnalysisResult, RiskLevel

REPORT_MARKER = "<!-- deployguard-ai-report -->"


def render_pr_comment(result: AnalysisResult) -> str:
    """
    Format the complete analysis result as an enterprise-grade GitHub PR comment
    with an idempotency marker so repeat pushes update the same comment in place.
    """
    assessment = result.agent_assessment or {}
    blast_radius = result.blast_radius_summary or {}

    score = result.risk_score if result.risk_score is not None else 0

    if result.risk_level == RiskLevel.BLOCK:
        header_emoji = "🚫"
        badge = "🔴 **DECISION: BLOCK — Merge Gate Failed**"
    elif result.risk_level == RiskLevel.WARN:
        header_emoji = "⚠️"
        badge = "🟡 **DECISION: WARN — Review & Canary Recommended**"
    elif result.risk_level == RiskLevel.PASS:
        header_emoji = "✅"
        badge = "🟢 **DECISION: PASS — Safe to Merge**"
    else:
        header_emoji = "❓"
        badge = "⚪ **DECISION: UNKNOWN**"

    lines = [
        REPORT_MARKER,
        f"## {header_emoji} DeployGuard AI — Release Risk & Impact Report",
        "",
        f"> {badge} &nbsp;|&nbsp; **Risk Score: {score}/100** &nbsp;|&nbsp; Source: `{result.source}` &nbsp;|&nbsp; ID: `{result.assessment_id[:8]}`",
        "",
    ]

    if result.is_docs_or_config_only:
        lines.extend([
            "> 📄 **Docs / Non-Runtime Only:** No runtime Python code, APIs, or production paths modified (`0/100 SAFE`).",
            "",
        ])

    # Weighted 40/30/20/10 Signal Breakdown
    signals = result.signal_breakdown or assessment.get("signals") or {}
    if signals:
        lines.extend([
            "### 📊 Weighted Risk Signals",
            "| Signal | Weight | Score |",
            "|---|:---:|:---:|",
            f"| AST Structural Diff | 40% | **{signals.get('ast', 0)}%** |",
            f"| Cross-File & Graph Blast Radius | 30% | **{signals.get('blast', 0)}%** |",
            f"| Critical Path Sensitivity | 20% | **{signals.get('critical_path', 0)}%** |",
            f"| Test-to-Churn Coverage Gap | 10% | **{signals.get('test_gap', 0)}%** |",
            "",
        ])

    # Breaking Changes
    if result.breaking_changes:
        lines.append("### 🚨 Breaking Changes Detected")
        for bc in result.breaking_changes[:10]:
            lines.append(f"- `{bc.get('type', 'BREAKING')}` in `{bc.get('file', '?')}`: {bc.get('detail', bc.get('symbol', ''))}")
        lines.append("")

    # Rationale
    rationale = assessment.get("rationale")
    if rationale:
        lines.extend([
            "### 🧠 Risk Rationale",
            f"{rationale}",
            "",
        ])

    strategy = assessment.get("deployment_strategy")
    if strategy:
        lines.extend([
            f"**Recommended Deployment Strategy:** `{strategy}`",
            "",
        ])

    tests = assessment.get("recommended_tests", [])
    if tests:
        lines.append("### 🧪 Pre-Merge Verification Checklist")
        for t in tests:
            lines.append(f"- [ ] {t}")
        lines.append("")

    # Cross-file dependency edges
    if result.dependency_edges:
        lines.extend([
            "### 🔀 Cross-File Dependency Impact",
            "| Modified File | Symbol | Downstream Consumer | Consumer Routes |",
            "|---|---|---|---|",
        ])
        for edge in result.dependency_edges[:12]:
            routes = ", ".join(edge.get("consumer_routes") or []) or "-"
            lines.append(
                f"| `{edge.get('source_file')}` | `{edge.get('symbol')}` | `{edge.get('consumer_file')}` | {routes} |"
            )
        lines.append("")

    # Service Blast Radius Table
    critical_services = blast_radius.get("critical_services", [])
    total_affected = blast_radius.get("total_affected", 0)
    origin_service = blast_radius.get("origin_service", "unknown")

    lines.append(f"### 🌐 Service Blast Radius (Origin: `{origin_service}`, Downstream: `{total_affected}`)")
    if critical_services:
        lines.extend([
            "| Service | SLA Tier | Distance (Hops) | Team Owner |",
            "|---|:---:|:---:|---|",
        ])
        for s in critical_services[:10]:
            lines.append(f"| `{s.get('service')}` | **{s.get('sla_tier')}** | {s.get('hops')} | {s.get('team', '-')} |")
    else:
        lines.append("_No critical SLA services identified in the downstream dependency path._")
    lines.append("")

    # Changed AST Symbols
    affected_symbols = result.context_bundle.get("affected_symbols", [])
    if affected_symbols:
        lines.extend([
            "### 🔍 Modified Code Symbols (AST)",
            "| Symbol | Category | Lines | Route / Endpoint |",
            "|---|---|:---:|---|",
        ])
        for sym in affected_symbols[:15]:
            route = sym.get("route", "-")
            lines.append(f"| `{sym.get('symbol')}` | {sym.get('kind')} | {sym.get('lines')} | {route} |")
        lines.append("")

    lines.extend([
        "---",
        "_Report auto-updated by DeployGuard AI gate enforcer._",
    ])

    return "\n".join(lines)
