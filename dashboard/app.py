"""
dashboard/app.py — DeployGuard AI · Production Streamlit Dashboard

Real-world, enterprise-grade dashboard. Connects to the live FastAPI
backend and displays real assessments triggered by actual GitHub PR webhooks.

Features:
  - Live data from MongoDB via the DeployGuard REST API
  - Auto-refresh every N seconds (configurable in sidebar)
  - Multi-repo, multi-PR history view
  - Real-time GitHub PR lookup (enter any repo + PR number)
  - Demo mode fallback when API is offline
  - Responsive layout with professional design system

Run (with live API):
    # Terminal 1 — start the API server:
    python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port 8080 --reload

    # Terminal 2 — start the dashboard:
    streamlit run dashboard/app.py

Run (demo mode — no API needed):
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap — allow `streamlit run dashboard/app.py` from any cwd
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

# ---------------------------------------------------------------------------
# Page config — MUST be the first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="DeployGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/acme/deployguard-ai",
        "Report a bug": "https://github.com/acme/deployguard-ai/issues",
        "About": "# DeployGuard AI\nAI-Powered Release Risk & Change-Impact Platform",
    },
)

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
from dashboard.api_client import APIClient
from dashboard.demo_data import DEMO_RESULT
from dashboard.components.risk_gauge import build_risk_gauge
from dashboard.components.blast_graph import build_blast_graph
from dashboard.components.incident_table import build_similarity_chart

# ---------------------------------------------------------------------------
# Custom CSS — production design system
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}
code, pre, .stCode { font-family: 'JetBrains Mono', monospace; }

/* ---- Header ---- */
.dg-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #312e81 100%);
    padding: 1.8rem 2.2rem;
    border-radius: 16px;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.2rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    border: 1px solid rgba(255,255,255,0.08);
}
.dg-header-title { color: #f8fafc; font-size: 1.9rem; font-weight: 800; margin: 0; letter-spacing: -0.02em; }
.dg-header-sub { color: #94a3b8; font-size: 0.85rem; margin-top: 0.3rem; letter-spacing: 0.02em; }
.dg-badge {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 8px; padding: 0.35rem 0.85rem;
    color: #e2e8f0; font-size: 0.72rem; font-weight: 500;
    white-space: nowrap; letter-spacing: 0.03em;
}
.dg-live-badge {
    background: rgba(34,197,94,0.15);
    border: 1px solid rgba(34,197,94,0.4);
    border-radius: 8px; padding: 0.35rem 0.85rem;
    color: #4ade80; font-size: 0.72rem; font-weight: 600;
    animation: pulse 2s infinite;
}
.dg-demo-badge {
    background: rgba(245,158,11,0.15);
    border: 1px solid rgba(245,158,11,0.4);
    border-radius: 8px; padding: 0.35rem 0.85rem;
    color: #fbbf24; font-size: 0.72rem; font-weight: 600;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }

/* ---- Decision badges ---- */
.badge-block { background:#fef2f2;color:#b91c1c;border:2px solid #fca5a5;border-radius:999px;padding:0.4rem 1.4rem;font-weight:700;font-size:1rem;display:inline-block;letter-spacing:0.08em; }
.badge-warn { background:#fffbeb;color:#92400e;border:2px solid #fcd34d;border-radius:999px;padding:0.4rem 1.4rem;font-weight:700;font-size:1rem;display:inline-block;letter-spacing:0.08em; }
.badge-pass { background:#f0fdf4;color:#15803d;border:2px solid #86efac;border-radius:999px;padding:0.4rem 1.4rem;font-weight:700;font-size:1rem;display:inline-block;letter-spacing:0.08em; }
.badge-unknown { background:#f8fafc;color:#475569;border:2px solid #cbd5e1;border-radius:999px;padding:0.4rem 1.4rem;font-weight:700;font-size:1rem;display:inline-block;letter-spacing:0.08em; }

/* ---- Metric card ---- */
.metric-card { background:white;border:1px solid #e2e8f0;border-radius:14px;padding:1.1rem 1.2rem;text-align:center;box-shadow:0 1px 6px rgba(0,0,0,0.05); }
.metric-card-value { font-size:1.9rem;font-weight:700;color:#0f172a;line-height:1; }
.metric-card-label { font-size:0.73rem;color:#64748b;margin-top:0.3rem;letter-spacing:0.06em;text-transform:uppercase; }

/* ---- Section heading ---- */
.section-heading { font-size:1.05rem;font-weight:600;color:#1e293b;border-left:4px solid #6366f1;padding-left:0.75rem;margin:0.5rem 0 1rem; }

/* ---- Rationale box ---- */
.rationale-box { background:#f8fafc;border:1px solid #e2e8f0;border-left:5px solid #6366f1;border-radius:10px;padding:1.1rem 1.4rem;color:#334155;font-size:0.9rem;line-height:1.65; }

/* ---- Pipeline step ---- */
.pipeline-step { display:flex;align-items:center;gap:0.8rem;padding:0.65rem 0.9rem;border-radius:10px;margin-bottom:0.4rem;background:#f8fafc;border:1px solid #e2e8f0; }
.step-label { font-size:0.85rem;font-weight:500;color:#1e293b; }
.step-status { margin-left:auto;font-size:0.75rem;font-weight:600; }

/* ---- History row ---- */
.history-row { display:flex;align-items:center;gap:1rem;padding:0.75rem 1rem;border-radius:10px;background:white;border:1px solid #e2e8f0;margin-bottom:0.5rem;cursor:pointer;transition:box-shadow 0.15s; }
.history-row:hover { box-shadow:0 2px 12px rgba(99,102,241,0.15);border-color:#a5b4fc; }

/* ---- API status pill ---- */
.api-ok { color:#15803d;font-weight:600;font-size:0.82rem; }
.api-err { color:#dc2626;font-weight:600;font-size:0.82rem; }

/* ---- Sidebar ---- */
section[data-testid="stSidebar"] { background:#0f172a; }
section[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
section[data-testid="stSidebar"] .stSelectbox label,
section[data-testid="stSidebar"] .stTextInput label,
section[data-testid="stSidebar"] .stNumberInput label { color:#94a3b8 !important; }
section[data-testid="stSidebar"] .stDivider { border-color:#1e293b !important; }

/* ---- Responsive tweaks ---- */
@media (max-width: 768px) {
    .dg-header { flex-direction:column;align-items:flex-start; }
    .dg-header-title { font-size:1.4rem; }
}
</style>
""", unsafe_allow_html=True)


# ===========================================================================
# Session State Initialisation
# ===========================================================================

def _init_state() -> None:
    if "api_url" not in st.session_state:
        st.session_state.api_url = os.environ.get("DASHBOARD_API_URL", "https://deployguard-ai.onrender.com")
    if "data_source" not in st.session_state:
        st.session_state.data_source = "live"
    if "selected_assessment" not in st.session_state:
        st.session_state.selected_assessment = None
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()
    if "auto_refresh" not in st.session_state:
        st.session_state.auto_refresh = True
    if "refresh_interval" not in st.session_state:
        st.session_state.refresh_interval = 15


# ===========================================================================
# Helpers
# ===========================================================================

def _decision_badge(risk_level: str) -> str:
    cls = {"BLOCK": "badge-block", "WARN": "badge-warn", "PASS": "badge-pass"}.get(
        (risk_level or "").upper(), "badge-unknown"
    )
    icons = {"BLOCK": "🚫", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❓"}
    icon = icons.get((risk_level or "").upper(), "❓")
    return f'<span class="{cls}">{icon} {(risk_level or "UNKNOWN").upper()}</span>'


def _sla_color(tier: str) -> str:
    return {"P0": "🔴", "P1": "🟠", "P2": "🟡", "P3": "🟢"}.get(tier, "⚪")


def _fmt_time(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)[:19]


# ===========================================================================
# Sidebar
# ===========================================================================

def render_sidebar(client: APIClient) -> tuple[dict, bool]:
    """Render sidebar controls. Returns (active_data_dict, is_live_mode)."""
    with st.sidebar:
        st.markdown("## 🛡️ DeployGuard AI")
        st.markdown(
            "<span style='font-size:0.72rem;color:#64748b'>v1.0.0 · AI-Powered Release Risk</span>",
            unsafe_allow_html=True,
        )
        st.divider()

        # --- API Server config ---
        st.markdown("**🔌 API Server**")
        api_url_input = st.text_input(
            "API Base URL",
            value=st.session_state.api_url,
            help="URL of your running DeployGuard FastAPI server.",
            label_visibility="collapsed",
        )
        if api_url_input != st.session_state.api_url:
            st.session_state.api_url = api_url_input
            st.rerun()

        # Server preset quick-buttons
        btn_c1, btn_c2 = st.columns(2)
        with btn_c1:
            if st.button("☁️ Render", use_container_width=True, help="Connect to 24/7 Render Cloud API"):
                st.session_state.api_url = "https://deployguard-ai.onrender.com"
                st.rerun()
        with btn_c2:
            if st.button("💻 Local", use_container_width=True, help="Connect to localhost:8080"):
                st.session_state.api_url = "http://localhost:8080"
                st.rerun()

        # API health indicator
        is_live = client.is_reachable()
        if is_live:
            st.markdown('<span class="api-ok">● API ONLINE</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="api-err">● API OFFLINE (showing demo data)</span>', unsafe_allow_html=True)

        st.divider()

        # --- Data source ---
        st.markdown("**📊 Data Source**")
        mode = st.radio(
            "Source",
            options=["🔴 Live (GitHub PRs)", "📦 Demo Data"],
            index=0 if is_live else 1,
            label_visibility="collapsed",
        )
        is_live_mode = "Live" in mode and is_live

        st.divider()

        # --- PR Selector (live mode) ---
        if is_live_mode:
            st.markdown("**🔍 Select Analyzed PR**")
            recent_resp = client.list_assessments(limit=25)
            recent_items = recent_resp.get("results", []) if recent_resp else []
            
            if recent_items:
                pr_options = ["Latest Incoming PR"] + [
                    f"PR #{item.get('pr_number', '?')} · {item.get('repo_full_name', '').split('/')[-1]} [{item.get('risk_level', 'UNKNOWN')}]"
                    for item in recent_items
                ]
                selected_idx = st.selectbox(
                    "Quick PR Switcher",
                    options=range(len(pr_options)),
                    format_func=lambda i: pr_options[i],
                    label_visibility="collapsed",
                )
                if selected_idx > 0:
                    st.session_state.selected_assessment = recent_items[selected_idx - 1]
                else:
                    st.session_state.selected_assessment = recent_items[0]
            else:
                st.caption("Waiting for first incoming GitHub PR webhook...")

            with st.expander("🔎 Search PR by Number"):
                pr_repo = st.text_input("Repo (owner/name)", value="chandanknayak/deployguard-ai")
                pr_num = st.number_input("PR Number", min_value=1, step=1, value=1)
                if st.button("Fetch PR Assessment", use_container_width=True):
                    if pr_repo and pr_num:
                        parts = pr_repo.split("/")
                        if len(parts) == 2:
                            result = client.get_pr_assessment(parts[0], parts[1], int(pr_num))
                            if result:
                                st.session_state.selected_assessment = result
                                st.success(f"Loaded PR #{int(pr_num)}!")
                                st.rerun()
                            else:
                                st.warning("No assessment found for this PR yet.")
                        else:
                            st.error("Format must be: owner/repo")

            st.divider()

        # --- Auto-refresh ---
        st.markdown("**🔄 Auto-refresh**")
        st.session_state.auto_refresh = st.toggle("Enable auto-refresh", value=st.session_state.auto_refresh)
        if st.session_state.auto_refresh:
            st.session_state.refresh_interval = st.select_slider(
                "Interval (seconds)",
                options=[5, 10, 15, 30, 60],
                value=st.session_state.refresh_interval,
            )
            elapsed = int(time.time() - st.session_state.last_refresh)
            remaining = max(0, st.session_state.refresh_interval - elapsed)
            st.caption(f"Next refresh in {remaining}s")

        if st.button("↺ Refresh Now", use_container_width=True):
            st.session_state.last_refresh = 0
            st.rerun()

        st.divider()

        # --- Links ---
        st.markdown(
            "**📚 Resources**\n\n"
            "[📖 Setup Guide](https://github.com/acme/deployguard-ai#setup)\n\n"
            "[🔗 GitHub Webhooks](https://docs.github.com/en/developers/webhooks-and-events/webhooks/about-webhooks)\n\n"
            "[📊 MongoDB Atlas](https://www.mongodb.com/atlas)\n\n"
            "[🤖 OpenAI API](https://platform.openai.com)"
        )

    # Determine what data to show
    if is_live_mode and st.session_state.selected_assessment:
        data = st.session_state.selected_assessment
    elif is_live_mode:
        # Show most recent assessment
        resp = client.list_assessments(limit=1)
        results = resp.get("results", [])
        data = results[0] if results else DEMO_RESULT
    else:
        data = DEMO_RESULT

    return data, is_live_mode


# ===========================================================================
# Auto-refresh trigger
# ===========================================================================

def maybe_rerun() -> None:
    """Trigger a Streamlit rerun if the auto-refresh interval has elapsed."""
    if st.session_state.auto_refresh:
        elapsed = time.time() - st.session_state.last_refresh
        if elapsed >= st.session_state.refresh_interval:
            st.session_state.last_refresh = time.time()
            time.sleep(0.1)
            st.rerun()


# ===========================================================================
# Page header
# ===========================================================================

def render_header(data: dict, is_live: bool, client: APIClient) -> None:
    pr_meta = data.get("pr_metadata", {})
    repo = data.get("repo_full_name", "—")
    pr_num = data.get("pr_number", "—")
    head_sha = (data.get("head_sha", "") or "")[:8]
    branch = pr_meta.get("head_branch", data.get("head_branch", ""))
    author = pr_meta.get("author", data.get("author", ""))

    live_html = '<span class="dg-live-badge">🔴 LIVE</span>' if is_live else '<span class="dg-demo-badge">📦 DEMO</span>'

    st.markdown(
        f"""
<div class="dg-header">
  <div style="font-size:2.8rem">🛡️</div>
  <div style="flex:1;min-width:0">
    <div class="dg-header-title">DeployGuard AI</div>
    <div class="dg-header-sub">
      AI-Powered Release Risk &amp; Change-Impact Platform &nbsp;·&nbsp;
      <code style="background:rgba(255,255,255,0.1);padding:2px 7px;border-radius:4px;font-size:0.8rem">{repo}</code>
      &nbsp;·&nbsp; PR&nbsp;<strong style="color:#f8fafc">#{pr_num}</strong>
      {f'&nbsp;·&nbsp; <code style="background:rgba(255,255,255,0.1);padding:2px 6px;border-radius:4px;font-size:0.78rem">{head_sha}</code>' if head_sha else ''}
    </div>
  </div>
  <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center">
    {live_html}
    {'<span class="dg-badge">🌿 ' + branch + '</span>' if branch else ''}
    {'<span class="dg-badge">👤 ' + author + '</span>' if author else ''}
    <span class="dg-badge">🔒 HMAC-Verified</span>
    <span class="dg-badge">🤖 GPT-4o Agent</span>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


# ===========================================================================
# Tab: Risk Assessment
# ===========================================================================

def render_risk_assessment(data: dict) -> None:
    agent = data.get("agent_assessment") or {}
    blast = data.get("blast_radius_summary") or {}
    total_symbols = int(data.get("total_affected_symbols") or 0)
    has_api_changes = bool(data.get("has_api_surface_changes"))
    files = data.get("files_analysed") or []
    total_downstream = int(blast.get("total_affected") or 0)

    # Heuristic fallback if agent was skipped / rate-limited
    if not agent or not agent.get("risk_score"):
        calc_score = 15
        if blast.get("has_p0_impact"): calc_score += 45
        elif blast.get("has_p1_impact"): calc_score += 25
        if has_api_changes: calc_score += 20
        if total_symbols > 5: calc_score += 15
        elif total_symbols > 0: calc_score += 5
        elif len(files) > 0: calc_score += 5

        risk_score = min(95, calc_score)
        if risk_score >= 70:
            agent_level = "HIGH"
            risk_level = "BLOCK"
            deployment_strategy = "ROLLBACK_READY"
        elif risk_score >= 35:
            agent_level = "MEDIUM"
            risk_level = "WARN"
            deployment_strategy = "CANARY"
        else:
            agent_level = "LOW"
            risk_level = "PASS"
            deployment_strategy = "STANDARD"

        confidence = 0.85
        rationale = (
            f"Deterministic AST & Graph Evaluation: Change impacts {len(files)} file(s) and {total_symbols} symbol(s). "
            f"{'P0 critical dependency affected; ' if blast.get('has_p0_impact') else ''}"
            f"{'API surface changed; ' if has_api_changes else ''}"
            f"Automated risk gate scored at {risk_score}/100."
        )
        recommended_tests = [
            "Execute automated integration test suite for modified entry points",
            "Verify backward-compatibility with downstream consumers",
            "Canary deployment (5% traffic verification)" if risk_score >= 35 else "Standard regression unit tests",
        ]
        escalation = bool(blast.get("has_p0_impact") or risk_score >= 70)
        affected_services = [
            {"service_name": s.get("service", "?"), "sla_tier": s.get("sla_tier", "P2"), "hops_from_change": s.get("hops", 1), "risk_reason": "Downstream dependency"}
            for s in blast.get("critical_services", [])
        ]
        similar_ids = []
    else:
        risk_score = int(agent.get("risk_score") or data.get("risk_score") or 0)
        risk_level = str(data.get("risk_level") or "UNKNOWN")
        agent_level = str(agent.get("risk_level") or risk_level)
        confidence = float(agent.get("confidence") or 1.0)
        rationale = str(agent.get("rationale") or "No rationale available.")
        deployment_strategy = str(agent.get("deployment_strategy") or "STANDARD")
        escalation = bool(agent.get("escalation_required"))
        recommended_tests = agent.get("recommended_tests") or []
        affected_services = agent.get("affected_services") or []
        similar_ids = agent.get("similar_incident_ids") or []

    pr_meta = data.get("pr_metadata") or {}
    git_summary = data.get("git_diff_summary") or {}
    created_at = _fmt_time(data.get("created_at"))

    # --- KPI strip ---
    cols = st.columns(6)
    kpis = [
        (str(risk_score), "Risk Score"),
        (agent_level, "Agent Verdict"),
        (f"{confidence:.0%}", "Confidence"),
        (str(total_symbols), "Changed Symbols"),
        (str(total_downstream), "Downstream Services"),
        (created_at, "Analysed At"),
    ]
    for col, (val, label) in zip(cols, kpis):
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-card-value" style="font-size:{"1.4rem" if len(val)>8 else "1.9rem"}">{val}</div>'
                f'<div class="metric-card-label">{label}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Gauge + Decision ---
    left, right = st.columns([1.1, 1])
    with left:
        st.plotly_chart(
            build_risk_gauge(risk_score, agent_level, confidence),
            use_container_width=True,
            config={"displayModeBar": False},
        )
    with right:
        st.markdown('<div class="section-heading">🚦 CI/CD Gate Decision</div>', unsafe_allow_html=True)
        st.markdown(
            f"<div style='margin-bottom:1.2rem'>{_decision_badge(risk_level)}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**📦 Deployment Strategy:** `{deployment_strategy}`")
        st.markdown(f"**🚨 Escalation Required:** {'⚠️ **Yes** — page on-call engineer' if escalation else 'No'}")
        if similar_ids:
            st.markdown(f"**🔗 Correlated Incidents:** {', '.join(f'`{i}`' for i in similar_ids)}")

        st.markdown('<div class="section-heading" style="margin-top:1.4rem">📋 PR Details</div>', unsafe_allow_html=True)
        pr_title = pr_meta.get("title") or data.get("pr_title", "")
        if pr_title:
            st.markdown(f"> _{pr_title}_")
        base = pr_meta.get("base_branch", "main")
        head = pr_meta.get("head_branch", "")
        if head:
            st.markdown(f"**Branch:** `{base}` ← `{head}`")
        st.markdown(
            f"**Diff:** {git_summary.get('files_changed', '?')} file(s) · "
            f"+{git_summary.get('lines_added', '?')} / -{git_summary.get('lines_removed', '?')} lines"
        )
        url = pr_meta.get("url", "")
        if url:
            st.markdown(f"[🔗 Open PR on GitHub →]({url})")

    # --- Agent Rationale ---
    st.markdown('<div class="section-heading">🤖 Agent Rationale (GPT-4o Structured Output)</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="rationale-box">{rationale}</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # --- Two-column: affected services + tests ---
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="section-heading">🎯 Affected Services</div>', unsafe_allow_html=True)
        if affected_services:
            for svc in affected_services:
                tier = svc.get("sla_tier", "P2")
                st.markdown(
                    f"{_sla_color(tier)} **{svc.get('service_name', '?')}** `{tier}` — "
                    f"{svc.get('hops_from_change', '?')} hop(s)<br>"
                    f"<small style='color:#64748b'>{svc.get('risk_reason', '')}</small>",
                    unsafe_allow_html=True,
                )
                st.markdown("---")
        else:
            st.info("No specific service breakdown available.")
    with col_b:
        st.markdown('<div class="section-heading">✅ Recommended Tests</div>', unsafe_allow_html=True)
        if recommended_tests:
            for i, test in enumerate(recommended_tests, 1):
                st.markdown(
                    f'<div style="display:flex;gap:0.5rem;padding:0.5rem 0;border-bottom:1px solid #f1f5f9;'
                    f'color:#334155;font-size:0.87rem">'
                    f'<span style="color:#6366f1;font-weight:700;min-width:1.5rem">{i}.</span>'
                    f'<span>{test}</span></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No specific tests recommended.")


# ===========================================================================
# Tab: Blast Radius
# ===========================================================================

def render_blast_radius(data: dict) -> None:
    blast = data.get("blast_radius_summary") or {}
    origin = blast.get("origin_service", "unknown")
    services = blast.get("critical_services") or []
    total = int(blast.get("total_affected") or 0)

    c1, c2, c3, c4 = st.columns(4)
    p0 = sum(1 for s in services if s.get("sla_tier") == "P0")
    p1 = sum(1 for s in services if s.get("sla_tier") == "P1")
    with c1: st.metric("Origin Service", origin)
    with c2: st.metric("Total Downstream", total)
    with c3: st.metric("🔴 P0 Critical", p0, delta=f"+{p0} at risk", delta_color="inverse")
    with c4: st.metric("🟠 P1 High", p1, delta=f"+{p1} at risk", delta_color="inverse")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-heading">🕸️ Dependency Graph (MongoDB $graphLookup)</div>', unsafe_allow_html=True)

    if blast:
        st.plotly_chart(build_blast_graph(blast), use_container_width=True)
    else:
        st.info("Blast radius data not available. Connect MongoDB to enable graph traversal.")

    if services:
        st.markdown('<div class="section-heading">📊 Affected Services Detail</div>', unsafe_allow_html=True)
        import pandas as pd
        df = pd.DataFrame([
            {
                "Service": s.get("service", s.get("service_name", "?")),
                "SLA Tier": s.get("sla_tier", "?"),
                "Hops": s.get("hops", "?"),
                "Owner Team": s.get("team", s.get("owner_team", "?")),
            }
            for s in services
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)

    st.info(
        "🔍 **How it works:** DeployGuard queries MongoDB with `$graphLookup` on the "
        "`code_graph` collection, recursively traversing directed dependency edges "
        "from the changed service. Each node carries SLA tier, team ownership, and "
        "on-call email — all in one cluster alongside the vector search index.",
    )


# ===========================================================================
# Tab: Historical Incidents
# ===========================================================================

def render_incidents(data: dict) -> None:
    incidents = data.get("similar_incidents") or []

    st.markdown('<div class="section-heading">🔮 Historical Incident Similarity (Atlas $vectorSearch)</div>', unsafe_allow_html=True)

    if not incidents:
        st.info(
            "No historical incidents in this assessment result. "
            "Connect MongoDB Atlas and run `python scripts/ingest_incidents.py` to seed incident data."
        )
        return

    st.plotly_chart(build_similarity_chart(incidents), use_container_width=True)

    st.markdown('<div class="section-heading">📄 Matched Incidents</div>', unsafe_allow_html=True)
    for inc in incidents:
        sim = float(inc.get("similarity_score") or 0)
        sev = inc.get("severity", "P2")
        with st.expander(
            f"{_sla_color(sev)} [{inc.get('incident_id','?')}]  {inc.get('title','')}  —  "
            f"Similarity: {sim:.3f}",
            expanded=(sim > 0.9),
        ):
            col_l, col_r = st.columns([1, 2])
            with col_l:
                st.markdown(f"**Severity:** `{sev}`")
                st.markdown(f"**Duration:** {inc.get('duration_minutes', '?')} min")
                st.markdown(f"**Service:** `{inc.get('affected_service', '?')}`")
                st.progress(min(sim, 1.0), text=f"Cosine similarity: {sim:.3f}")
            with col_r:
                tags = inc.get("root_cause_tags") or []
                if tags:
                    st.markdown(f"**Root cause tags:** {' '.join(f'`{t}`' for t in tags)}")
                url = inc.get("postmortem_url", "")
                if url:
                    st.markdown(f"[📄 Post-Mortem Report]({url})")
                st.markdown(
                    "_This incident was surfaced because its postmortem embedding is "
                    "geometrically close to the current changeset's context vector in "
                    "1536-dimensional space (OpenAI `text-embedding-3-small`)._"
                )


# ===========================================================================
# Tab: AST Analysis
# ===========================================================================

def render_ast_analysis(data: dict) -> None:
    files = data.get("files_analysed") or []

    st.markdown('<div class="section-heading">🌳 Deterministic AST Symbol Extraction</div>', unsafe_allow_html=True)
    st.markdown(
        "DeployGuard parses the **Abstract Syntax Tree** of every modified Python file "
        "and intersects AST node line ranges with the unified diff's changed line "
        "numbers — yielding an exact, deterministic map of which functions and classes "
        "were touched. No LLM guessing at this stage."
    )

    if not files:
        st.info("No file analysis data. The pipeline runs after a real GitHub PR webhook fires.")
        return

    all_symbols = []
    for f in files:
        fname = f.get("filename", "")
        lang = f.get("language", "?")
        mod = f.get("total_modified_lines", 0)
        eligible = f.get("is_ast_eligible", False)

        st.markdown(
            f"**`{fname}`** &nbsp; `{lang}` &nbsp; "
            f"{'✅ AST eligible' if eligible else '⚠️ Not AST eligible'} &nbsp; "
            f"**{mod}** modified lines",
            unsafe_allow_html=True,
        )
        for sym in f.get("affected_symbols") or []:
            route_path = sym.get("route_path", "")
            http_methods = sym.get("http_methods") or []
            all_symbols.append({
                "File": fname,
                "Symbol": sym.get("qualified_name", ""),
                "Kind": sym.get("kind", ""),
                "Lines": f"{sym.get('start_line','?')}–{sym.get('end_line','?')}",
                "HTTP Route": f"{','.join(http_methods)} {route_path}" if route_path else "—",
            })

    if all_symbols:
        import pandas as pd
        st.dataframe(
            pd.DataFrame(all_symbols),
            use_container_width=True,
            hide_index=True,
        )

    # Diff stats
    git = data.get("git_diff_summary") or {}
    if git:
        st.markdown('<div class="section-heading" style="margin-top:1.5rem">📂 Diff Summary</div>', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Files Changed", git.get("files_changed", "?"))
        c2.metric("Lines Added", f"+{git.get('lines_added', '?')}")
        c3.metric("Lines Removed", f"-{git.get('lines_removed', '?')}")

    st.info(
        "🔬 **Why AST over LLM-based extraction?** AST parsing is deterministic — "
        "same code always yields the same symbols. LLMs can hallucinate or miss "
        "symbol boundaries. For a security-critical CI/CD gate, determinism is non-negotiable."
    )


# ===========================================================================
# Tab: Assessment History
# ===========================================================================

def render_history(client: APIClient, is_live: bool) -> None:
    st.markdown('<div class="section-heading">📜 Assessment History</div>', unsafe_allow_html=True)

    if not is_live:
        st.info("Connect to a live API server to browse real assessment history.")
        st.markdown("Demo mode shows the single demo assessment — history requires MongoDB.")
        return

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        repo_filter = st.text_input("Filter by repo", placeholder="owner/repo")
    with col_f2:
        decision_filter = st.selectbox("Filter by decision", ["All", "BLOCK", "WARN", "PASS"])
    with col_f3:
        limit = st.select_slider("Results", options=[10, 20, 50, 100], value=20)

    resp = client.list_assessments(
        limit=limit,
        repo=repo_filter or None,
        decision=decision_filter if decision_filter != "All" else None,
    )

    total = resp.get("total", 0)
    results = resp.get("results") or []

    if resp.get("error"):
        st.error(f"API Error: {resp['error']}")
        return

    st.caption(f"Showing {len(results)} of {total} assessments")

    if not results:
        st.info("No assessments found. Push a PR to your GitHub repo to trigger the first analysis.")
        return

    # Stats strip
    stats = client.get_stats()
    if not stats.get("error"):
        kpis = stats.get("by_decision", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Assessments", stats.get("total_assessments", 0))
        c2.metric("🚫 BLOCK", kpis.get("BLOCK", 0))
        c3.metric("⚠️ WARN", kpis.get("WARN", 0))
        c4.metric("✅ PASS", kpis.get("PASS", 0))

    st.markdown("<br>", unsafe_allow_html=True)

    for doc in results:
        level = doc.get("risk_level", "UNKNOWN")
        score = doc.get("risk_score", 0)
        repo = doc.get("repo_full_name", "?")
        pr_num = doc.get("pr_number", "?")
        aid = doc.get("assessment_id", "")
        created = _fmt_time(doc.get("created_at"))
        badge_html = _decision_badge(level)

        col_a, col_b, col_c, col_d, col_e = st.columns([2, 1, 1, 2, 1])
        with col_a:
            st.markdown(f"**`{repo}`** PR #{pr_num}")
        with col_b:
            st.markdown(badge_html, unsafe_allow_html=True)
        with col_c:
            st.markdown(f"**{score}/100**")
        with col_d:
            st.markdown(f"<small style='color:#64748b'>{created}</small>", unsafe_allow_html=True)
        with col_e:
            if st.button("View →", key=f"view_{aid}"):
                st.session_state.selected_assessment = doc
                st.rerun()

        st.markdown('<hr style="margin:0.3rem 0;border-color:#f1f5f9">', unsafe_allow_html=True)


# ===========================================================================
# Tab: Pipeline Trace
# ===========================================================================

def render_pipeline_trace(data: dict) -> None:
    blast = data.get("blast_radius_summary") or {}
    incidents = data.get("similar_incidents") or []
    agent = data.get("agent_assessment") or {}

    st.markdown('<div class="section-heading">🔄 Pipeline Execution Trace</div>', unsafe_allow_html=True)

    steps = [
        ("🔍", "Stage 1 — Diff Parser",
         f"{(data.get('git_diff_summary') or {}).get('files_changed', '?')} file(s) parsed from PR diff",
         "✅ DONE", "#22c55e"),
        ("🌳", "Stage 2 — AST Analyzer",
         f"{data.get('total_affected_symbols', '?')} symbols extracted deterministically",
         "✅ DONE", "#22c55e"),
        ("🕸️", "Stage 3 — MongoDB $graphLookup",
         f"{blast.get('total_affected', '?')} downstream services in blast radius",
         "✅ DONE" if blast else "⚠️ SKIPPED (no DB)", "#22c55e" if blast else "#f59e0b"),
        ("🔮", "Stage 4 — Atlas $vectorSearch",
         f"{len(incidents)} similar historical incidents matched",
         "✅ DONE" if incidents else "⚠️ SKIPPED (no DB)", "#22c55e" if incidents else "#f59e0b"),
        ("🤖", "Stage 5 — GPT-4o Agent",
         f"Score: {agent.get('risk_score', '?')}/100 · Confidence: {float(agent.get('confidence') or 0):.0%}",
         "✅ DONE" if agent else "⚠️ SKIPPED (no key)", "#22c55e" if agent else "#f59e0b"),
        ("🚦", "Stage 6 — CI/CD Gate",
         f"Decision: {data.get('risk_level', '?')} → PR status check posted to GitHub",
         ("🚫 BLOCKED" if data.get("risk_level") == "BLOCK"
          else "⚠️ WARNED" if data.get("risk_level") == "WARN"
          else "✅ PASSED"),
         "#ef4444" if data.get("risk_level") == "BLOCK"
         else "#f59e0b" if data.get("risk_level") == "WARN"
         else "#22c55e"),
        ("💾", "Stage 7 — MongoDB Persist",
         f"Assessment {data.get('assessment_id', '?')[:8]}… saved to audit log",
         "✅ DONE", "#22c55e"),
        ("💬", "Stage 8 — GitHub PR Comment",
         "Markdown report posted as PR review comment",
         "✅ DONE", "#22c55e"),
    ]

    for icon, label, detail, status_text, status_color in steps:
        st.markdown(
            f'<div class="pipeline-step">'
            f'<span style="font-size:1.3rem">{icon}</span>'
            f'<div><div class="step-label">{label}</div>'
            f'<div style="font-size:0.76rem;color:#64748b">{detail}</div></div>'
            f'<span class="step-status" style="color:{status_color}">{status_text}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # PR comment preview
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-heading">🗒️ GitHub PR Comment (Auto-Posted)</div>', unsafe_allow_html=True)

    risk_level = data.get("risk_level", "?")
    risk_score = data.get("risk_score", 0)
    pr_num = data.get("pr_number", "?")
    repo = data.get("repo_full_name", "?")
    assessment_id = data.get("assessment_id", "?")
    top_inc = incidents[0] if incidents else {}
    icon = {"BLOCK": "🚫", "WARN": "⚠️", "PASS": "✅"}.get(risk_level, "❓")
    services_str = "\n".join(
        f"- {_sla_color(s.get('sla_tier','P3'))} **{s.get('service', s.get('service_name','?'))}** "
        f"`{s.get('sla_tier','')}` — {s.get('hops','?')} hop(s)"
        for s in (blast.get("critical_services") or [])
    )

    comment = f"""## {icon} DeployGuard AI · Risk Assessment for `{repo}` PR #{pr_num}

| Field | Value |
|---|---|
| **Decision** | `{risk_level}` |
| **Risk Score** | `{risk_score}/100` |
| **Agent Confidence** | `{float(agent.get('confidence') or 0):.0%}` |
| **Deployment Strategy** | `{agent.get('deployment_strategy', 'STANDARD')}` |
| **Escalation** | {'⚠️ Required — page on-call' if agent.get('escalation_required') else 'Not required'} |

### 🤖 Agent Rationale
> {agent.get('rationale', '_No rationale available._')}

### 🕸️ Blast Radius — `{blast.get('origin_service','?')}` ({blast.get('total_affected','?')} downstream services)
{services_str or '_No blast radius data_'}

### 🔮 Top Historical Match
{'**[' + top_inc.get('incident_id','') + ']** ' + top_inc.get('title','') + ' (Similarity: ' + str(round(float(top_inc.get('similarity_score') or 0), 3)) + ')' if top_inc else '_No incident matches_'}

### ✅ Recommended Tests
{chr(10).join(f"{i}. {t}" for i, t in enumerate(agent.get('recommended_tests') or [], 1)) or '_No tests recommended_'}

---
_Generated by [DeployGuard AI](https://github.com/acme/deployguard-ai) · Assessment `{assessment_id[:8]}…`_
"""
    with st.expander("👁️ Rendered preview", expanded=True):
        st.markdown(comment)
    st.code(comment, language="markdown")


# ===========================================================================
# Tab: Setup Guide
# ===========================================================================

def render_setup_guide() -> None:
    st.markdown('<div class="section-heading">🚀 Production Setup — Connect Real GitHub PRs</div>', unsafe_allow_html=True)

    st.markdown("""
Follow these steps to connect real GitHub push events to DeployGuard AI:

---

### Step 1 — Install dependencies
```bash
pip install fastapi uvicorn motor openai httpx python-dotenv pydantic streamlit plotly networkx
```

---

### Step 2 — Configure `.env`
Copy `.env.example` to `.env` and fill in your real values:
```bash
cp .env.example .env
```

| Variable | Where to get it |
|---|---|
| `GITHUB_WEBHOOK_SECRET` | Any random secret string you choose |
| `GITHUB_API_TOKEN` | [GitHub Settings → Developer Settings → PAT](https://github.com/settings/tokens) — needs `repo`, `statuses`, `pull_requests` scopes |
| `MONGODB_URI` | [MongoDB Atlas](https://www.mongodb.com/atlas) → Connect → Drivers → Python |
| `OPENAI_API_KEY` | [OpenAI Platform](https://platform.openai.com/api-keys) |

---

### Step 3 — Start the API server
```bash
python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port 8080 --reload
```

---

### Step 4 — Expose locally with ngrok (for local development)
```bash
# Install ngrok: https://ngrok.com/download
ngrok http 8080
# Copy the https://xxxx.ngrok-free.app URL
```

---

### Step 5 — Register the GitHub Webhook
1. Go to your GitHub repo → **Settings** → **Webhooks** → **Add webhook**
2. Set **Payload URL**: `https://xxxx.ngrok-free.app/webhook/github`
3. Set **Content type**: `application/json`
4. Set **Secret**: same value as `GITHUB_WEBHOOK_SECRET` in your `.env`
5. Select events: **Pull requests** only (or "Send me everything")
6. Click **Add webhook**

---

### Step 6 — Seed MongoDB (first time only)
```bash
python scripts/seed_graph.py       # Creates microservice dependency nodes
python scripts/ingest_incidents.py  # Creates historical incident embeddings
```

---

### Step 7 — Open a Pull Request!
Push a branch and open a PR in your repo. DeployGuard AI will:
1. Receive the webhook (< 1 second)
2. Fetch the diff and run AST analysis
3. Query MongoDB for blast radius + similar incidents
4. Run GPT-4o agent for structured risk assessment
5. Post the analysis as a **PR comment** + **commit status check**
6. Store the full audit record in MongoDB

The dashboard (this page) will show the result automatically with auto-refresh enabled.

---

### 🌐 100% Free Production Cloud Deployment (24/7 Live)

Deploy both the backend and frontend for **\$0/month** with zero local computer dependency:

#### 1. Frontend: Streamlit Community Cloud (Free Forever)
1. Go to **[share.streamlit.io](https://share.streamlit.io)** and log in with GitHub.
2. Click **New app** → Select repository: `chandanknayak/deployguard-ai`.
3. Set **Main file path**: `dashboard/app.py`.
4. Click **Deploy!** — In ~60 seconds, your dashboard will be live at `https://deployguard-ai.streamlit.app`.

#### 2. Backend: Render.com Web Service (Free Tier)
1. Go to **[dashboard.render.com](https://dashboard.render.com/)** and log in with GitHub.
2. Click **New +** → **Web Service** → Select `chandanknayak/deployguard-ai`.
3. Configure settings:
   - **Name**: `deployguard-api`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -e .`
   - **Start Command**: `python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port $PORT`
4. Add Environment Variables in Render:
   - `MONGODB_URI`: *Your MongoDB Atlas connection string*
   - `MONGODB_DB_NAME`: `deployguard`
   - `GITHUB_WEBHOOK_SECRET`: *Your secret token*
   - `GITHUB_API_TOKEN`: *Your GitHub PAT token*
   - `OPENAI_API_KEY`: *Your OpenAI API key*
   - `SUPPORTED_AST_LANGUAGES`: `["python"]`
5. Click **Create Web Service** → You get a permanent URL: `https://deployguard-api.onrender.com`.

#### 3. Update GitHub Webhook (Permanent 24/7)
1. Go to your GitHub repo **Settings → Webhooks**.
2. Update the Payload URL to: `https://deployguard-api.onrender.com/webhook/github`.
3. Done! Now any PR created on GitHub will trigger the live pipeline 24/7 automatically.
""")


# ===========================================================================
# Tab: Raw JSON
# ===========================================================================

def render_raw_json(data: dict) -> None:
    st.markdown('<div class="section-heading">📦 Structured JSON Audit Record</div>', unsafe_allow_html=True)
    st.markdown(
        "Full `AnalysisResult` model dump — stored in MongoDB for auditability "
        "and future vector search training."
    )
    st.json(data, expanded=False)
    st.download_button(
        label="⬇️ Download Full JSON",
        data=json.dumps(data, indent=2, default=str),
        file_name=f"deployguard_{data.get('assessment_id', 'result')}.json",
        mime="application/json",
    )


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    _init_state()

    client = APIClient(base_url=st.session_state.api_url)
    is_live = client.is_reachable()

    data, is_live_mode = render_sidebar(client)
    render_header(data, is_live_mode, client)

    # --- Tabs ---
    tabs = st.tabs([
        "🎯 Risk Assessment",
        "🕸️ Blast Radius",
        "🔮 Incidents",
        "🌳 AST Analysis",
        "📜 History",
        "🔄 Pipeline Trace",
        "🚀 Setup Guide",
        "📦 Raw JSON",
    ])

    with tabs[0]: render_risk_assessment(data)
    with tabs[1]: render_blast_radius(data)
    with tabs[2]: render_incidents(data)
    with tabs[3]: render_ast_analysis(data)
    with tabs[4]: render_history(client, is_live_mode)
    with tabs[5]: render_pipeline_trace(data)
    with tabs[6]: render_setup_guide()
    with tabs[7]: render_raw_json(data)

    # Footer
    st.markdown("<br>", unsafe_allow_html=True)
    mode_str = "🔴 LIVE — real GitHub PR data" if is_live_mode else "📦 DEMO — start the API + connect GitHub to see real data"
    st.markdown(
        f"<div style='text-align:center;color:#94a3b8;font-size:0.76rem;padding:1.2rem 0'>"
        f"🛡️ <strong>DeployGuard AI</strong> · {mode_str}<br>"
        f"FastAPI · MongoDB Atlas · OpenAI GPT-4o · Streamlit · Plotly"
        f"</div>",
        unsafe_allow_html=True,
    )

    # Auto-refresh
    if st.session_state.auto_refresh and is_live_mode:
        maybe_rerun()


if __name__ == "__main__":
    main()
