"""
tests/unit/test_risk_agent_resilience.py - Resilience unit tests for RiskAssessmentAgent and FastAPI security headers.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from deployguard.agent.risk_agent import (
    DeploymentStrategy,
    RiskAssessment,
    RiskAssessmentAgent,
    RiskLevel,
)
from deployguard.api.main import app
from deployguard.db.db_operations import BlastRadiusResult, IncidentRecord, ServiceNode


@pytest.fixture
def test_client():
    return TestClient(app)


class TestRiskAgentResilience:
    """Tests for RiskAssessmentAgent structured output and error propagation."""

    def test_assess_returns_validated_risk_assessment(self):
        """Test assess() returns a valid RiskAssessment when OpenAI responds cleanly."""
        agent = RiskAssessmentAgent()
        expected = RiskAssessment(
            risk_score=15,
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            rationale="Low-risk additive documentation change with zero downstream service or public API impact.",
            affected_services=[],
            recommended_tests=["Run unit tests"],
            deployment_strategy=DeploymentStrategy.STANDARD,
            escalation_required=False,
        )
        mock_choice = MagicMock()
        mock_choice.message.refusal = None
        mock_choice.message.parsed = expected
        mock_resp = MagicMock()
        mock_resp.choices = [mock_choice]

        with patch.object(
            agent._client.beta.chat.completions,
            "parse",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ):
            assessment = asyncio.run(
                agent.assess(
                    pr_title="Fix minor typo in README",
                    pr_author="dev-user",
                    changed_symbols=[],
                    blast_radius=BlastRadiusResult(origin_service="deployguard-ai"),
                    similar_incidents=[],
                )
            )
            assert isinstance(assessment, RiskAssessment)
            assert assessment.risk_level == RiskLevel.LOW
            assert assessment.risk_score == 15
            assert assessment.deployment_strategy == DeploymentStrategy.STANDARD

    def test_assess_raises_on_persistent_api_error(self):
        """Test assess() propagates RuntimeError when OpenAI client fails."""
        agent = RiskAssessmentAgent()
        high_blast = BlastRadiusResult(
            origin_service="auth-service",
            affected_nodes=[
                ServiceNode(service_name="payment-service", sla_tier="P0", hops=1, owner_team="payments", on_call_email="pay@example.com"),
                ServiceNode(service_name="order-service", sla_tier="P1", hops=2, owner_team="orders", on_call_email="ord@example.com"),
            ],
            max_depth_reached=2,
            has_p0_impact=True,
            has_p1_impact=True,
        )
        past_incidents = [
            IncidentRecord(
                incident_id="INC-101",
                title="Auth failure on deploy",
                severity="SEV-1",
                duration_minutes=45,
                affected_service="auth-service",
                root_cause_tags=["missing-env"],
                postmortem_url="https://example.com/inc-101",
                similarity_score=0.88,
            )
        ]

        with patch.object(
            agent._client.beta.chat.completions,
            "parse",
            new_callable=AsyncMock,
            side_effect=RuntimeError("OpenAI API error"),
        ):
            with pytest.raises(RuntimeError, match="OpenAI API error"):
                asyncio.run(
                    agent.assess(
                        pr_title="Refactor auth token validation",
                        pr_author="dev-user",
                        changed_symbols=[{"symbol": "verify_token", "change_type": "modified"}],
                        blast_radius=high_blast,
                        similar_incidents=past_incidents,
                    )
                )


class TestApiHealthAndSecurityHeaders:
    """Tests for FastAPI /healthz endpoint, X-Request-ID, and security headers."""

    def test_healthz_endpoint_status_and_headers(self, test_client):
        response = test_client.get("/healthz")
        assert response.status_code == 200
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0

    def test_healthz_endpoint_reuses_incoming_request_id(self, test_client):
        custom_request_id = "test-custom-req-id-12345"
        response = test_client.get("/healthz", headers={"X-Request-ID": custom_request_id})
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == custom_request_id
