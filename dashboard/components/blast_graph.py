"""
dashboard/components/blast_graph.py — Plotly network graph for blast-radius visualisation.

Renders an interactive force-directed graph where:
  - The *origin* (changed) service is the red central node.
  - Downstream dependants are coloured by SLA tier (P0=red, P1=orange, P2=yellow, P3=green).
  - Edge thickness encodes hop distance from the origin.
  - Hover tooltips show service name, tier, team, and hop count.
"""

from __future__ import annotations

import math

import plotly.graph_objects as go


# ---------------------------------------------------------------------------
# SLA tier → visual properties
# ---------------------------------------------------------------------------
_TIER_COLORS: dict[str, str] = {
    "P0": "#ef4444",   # red-500
    "P1": "#f97316",   # orange-500
    "P2": "#eab308",   # yellow-500
    "P3": "#22c55e",   # green-500
    "ORIGIN": "#7c3aed",  # violet-700
}

_TIER_SIZES: dict[str, int] = {
    "P0": 42,
    "P1": 34,
    "P2": 28,
    "P3": 22,
    "ORIGIN": 55,
}


def _circular_layout(
    nodes: list[str],
    center: tuple[float, float] = (0.0, 0.0),
    radius: float = 1.0,
) -> dict[str, tuple[float, float]]:
    """Return (x, y) positions for *nodes* evenly spaced around a circle."""
    positions: dict[str, tuple[float, float]] = {}
    n = len(nodes)
    for i, name in enumerate(nodes):
        angle = 2 * math.pi * i / max(n, 1) - math.pi / 2
        positions[name] = (
            center[0] + radius * math.cos(angle),
            center[1] + radius * math.sin(angle),
        )
    return positions


def build_blast_graph(blast_radius_summary: dict) -> go.Figure:
    """
    Build an interactive Plotly network graph for the blast-radius data.

    Args:
        blast_radius_summary: The ``blast_radius_summary`` dict from an
            ``AnalysisResult``.  Expected keys: ``origin_service``,
            ``critical_services`` (list of dicts with ``service``,
            ``sla_tier``, ``hops``, ``team``).

    Returns:
        A :class:`plotly.graph_objects.Figure` for ``st.plotly_chart()``.
    """
    origin = blast_radius_summary.get("origin_service", "origin")
    services = blast_radius_summary.get("critical_services", [])

    # --- Build node metadata ---
    nodes: dict[str, dict] = {
        origin: {
            "tier": "ORIGIN",
            "hops": 0,
            "team": "changed-service",
            "label": origin,
        }
    }
    for svc in services:
        nodes[svc["service"]] = {
            "tier": svc.get("sla_tier", "P3"),
            "hops": svc.get("hops", 1),
            "team": svc.get("team", "unknown"),
            "label": svc["service"],
        }

    # --- Compute layout: origin at centre; ring per hop distance ---
    hop_groups: dict[int, list[str]] = {}
    for name, meta in nodes.items():
        h = meta["hops"]
        hop_groups.setdefault(h, []).append(name)

    positions: dict[str, tuple[float, float]] = {origin: (0.0, 0.0)}
    for hop, group in sorted(hop_groups.items()):
        if hop == 0:
            continue
        ring = _circular_layout(group, radius=hop * 2.0)
        positions.update(ring)

    # --- Build edges (origin → hop-1, hop-1 → hop-2 …) ---
    edges: list[tuple[str, str]] = []
    # Map hop → services
    by_hop = {h: g for h, g in hop_groups.items()}
    # Connect each node to nearest-hop ancestor
    for name, meta in nodes.items():
        h = meta["hops"]
        if h == 0:
            continue
        parent_hop = h - 1
        parents = by_hop.get(parent_hop, [origin])
        if parents:
            edges.append((parents[0], name))

    # --- Plotly traces ---
    edge_x, edge_y = [], []
    for src, dst in edges:
        x0, y0 = positions[src]
        x1, y1 = positions[dst]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line={"width": 2, "color": "#94a3b8"},
        hoverinfo="none",
        showlegend=False,
    )

    node_x = [positions[n][0] for n in nodes]
    node_y = [positions[n][1] for n in nodes]
    node_colors = [_TIER_COLORS.get(nodes[n]["tier"], "#64748b") for n in nodes]
    node_sizes = [_TIER_SIZES.get(nodes[n]["tier"], 22) for n in nodes]
    node_labels = list(nodes.keys())
    hover_texts = [
        (
            f"<b>{n}</b><br>"
            f"SLA Tier: {nodes[n]['tier']}<br>"
            f"Hops from origin: {nodes[n]['hops']}<br>"
            f"Team: {nodes[n]['team']}"
        )
        for n in nodes
    ]

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        marker={
            "size": node_sizes,
            "color": node_colors,
            "line": {"width": 2, "color": "white"},
            "opacity": 0.95,
        },
        text=node_labels,
        textposition="bottom center",
        textfont={"size": 11, "family": "Inter, monospace", "color": "#1e293b"},
        hovertext=hover_texts,
        hoverinfo="text",
        showlegend=False,
    )

    # --- Legend annotations ---
    legend_items = [
        ("ORIGIN (changed)", _TIER_COLORS["ORIGIN"]),
        ("P0 — Critical SLA", _TIER_COLORS["P0"]),
        ("P1 — High SLA", _TIER_COLORS["P1"]),
        ("P2 — Medium SLA", _TIER_COLORS["P2"]),
        ("P3 — Low SLA", _TIER_COLORS["P3"]),
    ]
    legend_traces = [
        go.Scatter(
            x=[None], y=[None], mode="markers",
            marker={"size": 12, "color": color},
            name=label,
        )
        for label, color in legend_items
    ]

    fig = go.Figure(
        data=[edge_trace, node_trace] + legend_traces,
        layout=go.Layout(
            title={
                "text": f"<b>Blast Radius — {origin}</b>",
                "font": {"size": 16, "family": "Inter, sans-serif"},
                "x": 0.5,
            },
            showlegend=True,
            legend={
                "orientation": "h",
                "yanchor": "bottom",
                "y": -0.25,
                "xanchor": "center",
                "x": 0.5,
                "font": {"size": 11},
            },
            hovermode="closest",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(248,250,252,1)",
            xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            margin={"t": 60, "b": 80, "l": 20, "r": 20},
            height=420,
        ),
    )
    return fig

