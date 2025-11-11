"""
dashboard/components/risk_gauge.py — Plotly risk-score gauge chart component.

Renders a half-donut gauge calibrated from 0–100 with three coloured
bands (Safe / Warning / Critical) and an animated needle pointer.
"""

from __future__ import annotations

import plotly.graph_objects as go


# ---------------------------------------------------------------------------
# Colour constants
# ---------------------------------------------------------------------------
_SAFE_COLOR = "#22c55e"       # green-500
_WARN_COLOR = "#f59e0b"       # amber-500
_CRITICAL_COLOR = "#ef4444"   # red-500
_NEEDLE_COLOR = "#1e293b"     # slate-900
_BG_COLOR = "rgba(0,0,0,0)"  # transparent


def build_risk_gauge(
    score: int,
    risk_level: str,
    confidence: float = 1.0,
) -> go.Figure:
    """
    Build a Plotly gauge Figure for a 0–100 risk score.

    Args:
        score:       Integer risk score (0–100).
        risk_level:  Human-readable label (e.g. ``"HIGH"``).
        confidence:  Agent confidence 0.0–1.0 shown as subtitle.

    Returns:
        A :class:`plotly.graph_objects.Figure` suitable for
        ``st.plotly_chart()``.
    """
    if score <= 35:
        bar_color = _SAFE_COLOR
    elif score <= 65:
        bar_color = _WARN_COLOR
    else:
        bar_color = _CRITICAL_COLOR

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=score,
            number={
                "suffix": "/100",
                "font": {"size": 44, "color": bar_color, "family": "Inter, sans-serif"},
            },
            delta={
                "reference": 50,
                "increasing": {"color": _CRITICAL_COLOR},
                "decreasing": {"color": _SAFE_COLOR},
                "font": {"size": 16},
            },
            title={
                "text": (
                    f"<b>Risk Score</b><br>"
                    f"<span style='font-size:14px;color:#94a3b8'>Level: {risk_level} "
                    f"| Confidence: {confidence:.0%}</span>"
                ),
                "font": {"size": 20, "family": "Inter, sans-serif"},
            },
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 2,
                    "tickcolor": "#334155",
                    "tickfont": {"size": 12, "color": "#94a3b8"},
                    "nticks": 11,
                },
                "bar": {"color": bar_color, "thickness": 0.28},
                "bgcolor": "white",
                "borderwidth": 2,
                "bordercolor": "#e2e8f0",
                "steps": [
                    {"range": [0, 35], "color": "#dcfce7"},   # green-100
                    {"range": [35, 65], "color": "#fef9c3"},  # yellow-100
                    {"range": [65, 100], "color": "#fee2e2"},  # red-100
                ],
                "threshold": {
                    "line": {"color": _NEEDLE_COLOR, "width": 4},
                    "thickness": 0.85,
                    "value": score,
                },
            },
        )
    )

    fig.update_layout(
        paper_bgcolor=_BG_COLOR,
        plot_bgcolor=_BG_COLOR,
        margin={"t": 80, "b": 10, "l": 20, "r": 20},
        height=280,
        font={"family": "Inter, sans-serif"},
    )
    return fig

