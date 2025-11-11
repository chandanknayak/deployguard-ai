"""
dashboard/components/incident_table.py — Historical incident similarity display.

Renders a styled Plotly bar chart for incident similarity scores alongside
a formatted Streamlit dataframe.
"""

from __future__ import annotations

import plotly.graph_objects as go


_SEVERITY_COLORS: dict[str, str] = {
    "P0": "#ef4444",
    "P1": "#f97316",
    "P2": "#eab308",
    "P3": "#22c55e",
}


def build_similarity_chart(incidents: list[dict]) -> go.Figure:
    """
    Build a horizontal Plotly bar chart showing incident similarity scores.

    Args:
        incidents: List of incident dicts with keys: ``incident_id``,
            ``title``, ``severity``, ``similarity_score``,
            ``duration_minutes``.

    Returns:
        A :class:`plotly.graph_objects.Figure`.
    """
    if not incidents:
        fig = go.Figure()
        fig.add_annotation(text="No historical incidents matched.", showarrow=False)
        return fig

    ids = [inc["incident_id"] for inc in incidents]
    scores = [inc["similarity_score"] for inc in incidents]
    severities = [inc.get("severity", "P2") for inc in incidents]
    colors = [_SEVERITY_COLORS.get(s, "#64748b") for s in severities]
    hover_texts = [
        (
            f"<b>{inc['incident_id']}</b><br>"
            f"{inc['title']}<br>"
            f"Severity: {inc.get('severity', 'N/A')}<br>"
            f"Duration: {inc.get('duration_minutes', '?')}m<br>"
            f"Similarity: {inc['similarity_score']:.3f}"
        )
        for inc in incidents
    ]

    fig = go.Figure(
        go.Bar(
            x=scores,
            y=ids,
            orientation="h",
            marker={"color": colors, "opacity": 0.88, "line": {"width": 0}},
            text=[f"{s:.3f}" for s in scores],
            textposition="outside",
            hovertext=hover_texts,
            hoverinfo="text",
            textfont={"size": 13, "family": "Inter, monospace"},
        )
    )

    fig.update_layout(
        title={
            "text": "<b>Historical Incident Cosine Similarity</b>",
            "font": {"size": 15, "family": "Inter, sans-serif"},
        },
        xaxis={
            "range": [0, 1.1],
            "title": "Cosine Similarity Score",
            "tickformat": ".2f",
            "showgrid": True,
            "gridcolor": "#e2e8f0",
        },
        yaxis={
            "title": "",
            "autorange": "reversed",
        },
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(248,250,252,1)",
        margin={"t": 50, "b": 40, "l": 160, "r": 60},
        height=max(180, len(incidents) * 70 + 100),
        font={"family": "Inter, sans-serif"},
        shapes=[
            dict(
                type="line",
                x0=0.75, x1=0.75, y0=-0.5, y1=len(incidents) - 0.5,
                line={"color": "#ef4444", "width": 1.5, "dash": "dot"},
            )
        ],
        annotations=[
            dict(
                x=0.75, y=len(incidents) - 0.5,
                xanchor="left", yanchor="top",
                text="High-risk threshold (0.75)",
                showarrow=False,
                font={"size": 10, "color": "#ef4444"},
            )
        ],
    )
    return fig

