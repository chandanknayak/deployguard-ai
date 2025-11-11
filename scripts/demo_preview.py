"""
scripts/demo_preview.py — End-to-end local dry-run preview of DeployGuard AI.

Simulates receiving a GitHub PR modifying the payment service retry logic:
  1. Parses unified git diff.
  2. Traverses AST to discover affected functions and endpoints.
  3. Simulates MongoDB $graphLookup blast radius.
  4. Simulates Atlas Vector Search historical incident matches.
  5. Computes structured Risk Assessment.
  6. Renders the GitHub Markdown PR comment.

Run:
    python scripts/demo_preview.py
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure repository root is in Python path for direct script invocation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datetime import datetime, timezone

from deployguard.agent.risk_agent import (
    AffectedServiceSummary,
    DeploymentStrategy,
    RiskAssessment,
    RiskLevel as AgentRiskLevel,
)
from deployguard.core.ast_analyzer import ASTAnalyzer
from deployguard.core.comment_renderer import render_pr_comment
from deployguard.core.diff_parser import parse_diff
from deployguard.db.db_operations import BlastRadiusResult, IncidentRecord, ServiceNode
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel

# ---------------------------------------------------------------------------
# 1. Realistic Sample PR Diff
# ---------------------------------------------------------------------------
SAMPLE_DIFF = """\
diff --git a/deployguard/payments/charge.py b/deployguard/payments/charge.py
index a4f7b2c..e81d99a 100644
--- a/deployguard/payments/charge.py
+++ b/deployguard/payments/charge.py
@@ -10,6 +10,10 @@ class PaymentGateway:
     async def execute_charge(self, amount: float) -> dict:
+        # Modified exponential backoff and jitter logic
+        self.retry_count = 5
+        self.jitter_factor = 0.5
         return {"status": "success"}

@@ -25,4 +29,6 @@ router = APIRouter()
 @router.post("/api/v1/charge")
 async def charge_endpoint(amount: float) -> dict:
+    gateway = PaymentGateway()
+    return await gateway.execute_charge(amount)
"""

# Realistic Sample Python Source File
SAMPLE_SOURCE = """\
from fastapi import APIRouter

class PaymentGateway:
    def __init__(self):
        self.retry_count = 3
        self.base_delay = 1.0

    async def execute_charge(self, amount: float) -> dict:
        self.retry_count = 5
        self.jitter_factor = 0.5
        return {"status": "success"}


router = APIRouter()


@router.post("/api/v1/charge")
async def charge_endpoint(amount: float) -> dict:
    gateway = PaymentGateway()
    return await gateway.execute_charge(amount)
"""


def run_preview() -> None:
    print("=" * 80)
    print("🛡️  DEPLOYGUARD AI — END-TO-END PIPELINE PREVIEW")
    print("=" * 80)

    # Stage 1: Parse Git Diff
    print("\n[Stage 1] Parsing Unified Git Diff...")
    file_diffs = parse_diff(SAMPLE_DIFF)
    print(f"  ✓ Files parsed: {len(file_diffs)}")
    for fd in file_diffs:
        print(f"    - {fd.filename} ({len(fd.hunks)} hunks, {len(fd.all_modified_lines)} modified lines)")

    # Stage 2: Deterministic AST Analysis
    print("\n[Stage 2] Executing AST Code Graph Intersect...")
    analyzer = ASTAnalyzer()
    target_fd = file_diffs[0]
    affected_symbols = analyzer.analyze(
        source_code=SAMPLE_SOURCE,
        filename=target_fd.filename,
        modified_lines=target_fd.all_modified_lines,
    )

    print(f"  ✓ Affected symbols discovered: {len(affected_symbols)}")
    for s in affected_symbols:
        route_info = f" (Route: {','.join(s.http_methods)} {s.route_path})" if s.route_path else ""
        print(f"    - [{s.kind.value}] {s.qualified_name} (lines {s.start_line}-{s.end_line}){route_info}")

    # Stage 3: Simulated MongoDB $graphLookup Blast Radius
    print("\n[Stage 3] Querying MongoDB $graphLookup (Transitive Blast Radius)...")
    blast_radius = BlastRadiusResult(
        origin_service="payment-service",
        affected_nodes=[
            ServiceNode("order-service", "P0", "commerce-platform", "commerce@acme.com", hops=1),
            ServiceNode("subscription-billing", "P0", "billing-infra", "billing@acme.com", hops=2),
            ServiceNode("fraud-detection", "P1", "trust-safety", "fraud@acme.com", hops=2),
            ServiceNode("inventory-service", "P1", "supply-chain", "supply@acme.com", hops=3),
        ],
        has_p0_impact=True,
        has_p1_impact=True,
        max_depth_reached=3,
    )
    print(f"  ✓ Blast Radius computed: {blast_radius.total_affected} downstream services affected")
    for s in blast_radius.critical_services:
        print(f"    - [SLA: {s.sla_tier}] {s.service_name} ({s.hops} hops) -> Owner: {s.owner_team}")

    # Stage 4: Simulated MongoDB Atlas $vectorSearch
    print("\n[Stage 4] Querying Atlas Vector Search (Historical Incident Similarity)...")
    similar_incidents = [
        IncidentRecord(
            incident_id="INC-2024-0317",
            title="Payment retry storm caused 40-minute checkout outage",
            severity="P0",
            duration_minutes=40,
            affected_service="payment-service",
            root_cause_tags=["retry-logic", "payment", "thundering-herd"],
            postmortem_url="https://wiki.acme.com/postmortems/INC-2024-0317",
            similarity_score=0.942,
        )
    ]
    for inc in similar_incidents:
        print(f"  ✓ Top Match: [{inc.incident_id}] {inc.title}")
        print(f"    Cosine Similarity: {inc.similarity_score:.3f} | Severity: {inc.severity} | Duration: {inc.duration_minutes}m")

    # Stage 5: Agent Risk Assessment (Pydantic Structured Output)
    print("\n[Stage 5] Synthesizing Agent Decision (OpenAI Structured Outputs)...")
    agent_output = RiskAssessment(
        risk_score=78,
        risk_level=AgentRiskLevel.HIGH,
        confidence=0.93,
        rationale=(
            "The modification to execute_charge alters retry frequency and jitter within a critical payment path. "
            "MongoDB graph traversal reveals 2 P0 services (order-service, subscription-billing) within 2 hops. "
            "Vector search matched INC-2024-0317 (0.942 similarity), an outage where uncoordinated retry backoff "
            "created a connection saturation cascade. Given P0 blast radius and high incident correlation, risk is elevated."
        ),
        affected_services=[
            AffectedServiceSummary(
                service_name="order-service",
                sla_tier="P0",
                risk_reason="Direct upstream caller; synchronous checkout transactions fail if payment hangs.",
                hops_from_change=1,
            ),
            AffectedServiceSummary(
                service_name="subscription-billing",
                sla_tier="P0",
                risk_reason="Batch renewal jobs retry aggressively and can saturate payment connection pools.",
                hops_from_change=2,
            ),
        ],
        recommended_tests=[
            "Simulate downstream gateway 503 storm with jitter_factor=0.5 to verify backoff dispersion.",
            "Run order-service checkout integration suite with payment latency injected.",
            "Verify circuit-breaker trip threshold under 100 concurrent charge failures.",
        ],
        deployment_strategy=DeploymentStrategy.ROLLBACK_READY,
        escalation_required=True,
        similar_incident_ids=["INC-2024-0317"],
    )

    # Stage 6: Build Full Analysis Result & Render PR Comment
    file_analysis = FileAnalysis(
        filename=target_fd.filename,
        language="python",
        is_ast_eligible=True,
        total_modified_lines=len(target_fd.all_modified_lines),
        affected_symbols=affected_symbols,
    )

    result = AnalysisResult(
        assessment_id="dg-demo-preview-7f91c",
        pr_number=4821,
        repo_full_name="acme/payment-service",
        head_sha="c7d3e8f1a2b5094d6e81",
        risk_level=RiskLevel.BLOCK,
        risk_score=agent_output.risk_score,
        files_analysed=[file_analysis],
        total_affected_symbols=len(affected_symbols),
        has_api_surface_changes=True,
        blast_radius_summary={
            "origin_service": blast_radius.origin_service,
            "total_affected": blast_radius.total_affected,
            "has_p0_impact": blast_radius.has_p0_impact,
            "critical_services": [
                {"service": s.service_name, "sla_tier": s.sla_tier, "hops": s.hops, "team": s.owner_team}
                for s in blast_radius.critical_services
            ],
        },
        context_bundle={
            "affected_symbols": [
                {
                    "symbol": s.qualified_name,
                    "kind": s.kind.value,
                    "lines": f"{s.start_line}-{s.end_line}",
                    "route": f"{','.join(s.http_methods)} {s.route_path}" if s.route_path else None,
                }
                for s in affected_symbols
            ]
        },
        agent_assessment=agent_output.model_dump(),
    )

    print("\n" + "=" * 80)
    print("📋 GITHUB PR MARKDOWN COMMENT PREVIEW:")
    print("=" * 80 + "\n")
    comment_markdown = render_pr_comment(result)
    print(comment_markdown)

    print("\n" + "=" * 80)
    print("📦 STRUCTURED JSON AUDIT RECORD PREVIEW:")
    print("=" * 80 + "\n")
    print(json.dumps(result.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    run_preview()
