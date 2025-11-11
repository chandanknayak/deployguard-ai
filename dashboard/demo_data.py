"""
dashboard/demo_data.py — Canonical demo dataset for the DeployGuard AI Dashboard.

This module provides the full structured pipeline output from the
demo_preview.py dry-run. All dashboard components consume this single
source of truth so the UI works 100% offline without MongoDB or OpenAI.
"""

from __future__ import annotations

DEMO_RESULT: dict = {
    "assessment_id": "dg-demo-preview-7f91c",
    "pr_number": 4821,
    "repo_full_name": "acme/payment-service",
    "head_sha": "c7d3e8f1a2b5094d6e81",
    "risk_level": "BLOCK",
    "risk_score": 78,
    "files_analysed": [
        {
            "filename": "deployguard/payments/charge.py",
            "language": "python",
            "is_ast_eligible": True,
            "total_modified_lines": 10,
            "affected_symbols": [
                {
                    "qualified_name": "PaymentGateway",
                    "kind": "class",
                    "start_line": 3,
                    "end_line": 10,
                    "route_path": None,
                    "http_methods": [],
                },
                {
                    "qualified_name": "PaymentGateway.execute_charge",
                    "kind": "async_method",
                    "start_line": 7,
                    "end_line": 10,
                    "route_path": None,
                    "http_methods": [],
                },
                {
                    "qualified_name": "charge_endpoint",
                    "kind": "async_function",
                    "start_line": 15,
                    "end_line": 17,
                    "route_path": "/api/v1/charge",
                    "http_methods": ["POST"],
                },
            ],
        }
    ],
    "total_affected_symbols": 3,
    "has_api_surface_changes": True,
    "blast_radius_summary": {
        "origin_service": "payment-service",
        "total_affected": 4,
        "has_p0_impact": True,
        "has_p1_impact": True,
        "critical_services": [
            {"service": "order-service", "sla_tier": "P0", "hops": 1, "team": "commerce@acme.com"},
            {"service": "subscription-billing", "sla_tier": "P0", "hops": 2, "team": "billing@acme.com"},
            {"service": "fraud-detection", "sla_tier": "P1", "hops": 2, "team": "fraud@acme.com"},
            {"service": "inventory-service", "sla_tier": "P1", "hops": 3, "team": "supply@acme.com"},
        ],
    },
    "context_bundle": {
        "affected_symbols": [
            {"symbol": "PaymentGateway", "kind": "class", "lines": "3-10", "route": None},
            {"symbol": "PaymentGateway.execute_charge", "kind": "async_method", "lines": "7-10", "route": None},
            {"symbol": "charge_endpoint", "kind": "async_function", "lines": "15-17", "route": "POST /api/v1/charge"},
        ]
    },
    "agent_assessment": {
        "risk_score": 78,
        "risk_level": "HIGH",
        "confidence": 0.93,
        "rationale": (
            "The modification to execute_charge alters retry frequency and jitter within a critical "
            "payment path. MongoDB graph traversal reveals 2 P0 services (order-service, "
            "subscription-billing) within 2 hops. Vector search matched INC-2024-0317 (0.942 "
            "similarity), an outage where uncoordinated retry backoff created a connection "
            "saturation cascade. Given P0 blast radius and high incident correlation, risk is elevated."
        ),
        "affected_services": [
            {
                "service_name": "order-service",
                "sla_tier": "P0",
                "risk_reason": "Direct upstream caller; synchronous checkout transactions fail if payment hangs.",
                "hops_from_change": 1,
            },
            {
                "service_name": "subscription-billing",
                "sla_tier": "P0",
                "risk_reason": "Batch renewal jobs retry aggressively and can saturate payment connection pools.",
                "hops_from_change": 2,
            },
        ],
        "recommended_tests": [
            "Simulate downstream gateway 503 storm with jitter_factor=0.5 to verify backoff dispersion.",
            "Run order-service checkout integration suite with payment latency injected.",
            "Verify circuit-breaker trip threshold under 100 concurrent charge failures.",
        ],
        "deployment_strategy": "ROLLBACK_READY",
        "escalation_required": True,
        "similar_incident_ids": ["INC-2024-0317"],
    },
    "similar_incidents": [
        {
            "incident_id": "INC-2024-0317",
            "title": "Payment retry storm caused 40-minute checkout outage",
            "severity": "P0",
            "duration_minutes": 40,
            "affected_service": "payment-service",
            "root_cause_tags": ["retry-logic", "payment", "thundering-herd"],
            "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-0317",
            "similarity_score": 0.942,
        },
        {
            "incident_id": "INC-2023-1105",
            "title": "Connection pool exhaustion during Black Friday peak load",
            "severity": "P1",
            "duration_minutes": 22,
            "affected_service": "payment-service",
            "root_cause_tags": ["connection-pool", "payment", "load-spike"],
            "postmortem_url": "https://wiki.acme.com/postmortems/INC-2023-1105",
            "similarity_score": 0.811,
        },
        {
            "incident_id": "INC-2023-0601",
            "title": "Charge endpoint returned 500 on malformed retry payloads",
            "severity": "P2",
            "duration_minutes": 8,
            "affected_service": "payment-service",
            "root_cause_tags": ["retry-logic", "serialization"],
            "postmortem_url": "https://wiki.acme.com/postmortems/INC-2023-0601",
            "similarity_score": 0.763,
        },
    ],
    "git_diff_summary": {
        "files_changed": 1,
        "lines_added": 6,
        "lines_removed": 0,
        "file": "deployguard/payments/charge.py",
    },
    "pr_metadata": {
        "title": "feat(payments): add exponential backoff with jitter to execute_charge",
        "author": "jsmith",
        "base_branch": "main",
        "head_branch": "feat/payment-retry-jitter",
        "url": "https://github.com/acme/payment-service/pull/4821",
        "created_at": "2024-11-04T15:32:00Z",
    },
}

