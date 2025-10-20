"""
tests/unit/test_risk_agent.py — Unit tests for the LLM Risk Assessment Agent.

Tests cover:
    - Pydantic model validation and constraints
    - Dynamic risk level consistency validation (score ↔ category)
    - Prompt assembly and evidence formatting
    - Agent execution with mocked OpenAI Structured Outputs API
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from deployguard.agent.risk_agent import (
    AffectedServiceSummary,
    DeploymentStrategy,
    RiskAssessment,
    RiskAssessmentAgent,
    RiskLevel,
    _build_system_prompt,
    _build_user_message,
)
from deployguard.db.db_operations import BlastRadiusResult, IncidentRecord, ServiceNode


class TestRiskAssessmentSchema:
    """Tests for RiskAssessment Pydantic model validation."""

    def test_valid_risk_assessment(self) -> None:
        data = {
            "risk_score": 75,
            "risk_level": "HIGH",
            "confidence": 0.88,
            "rationale": (
                "The change directly impacts order_service (P0) within 1 hop. "
                "Historical incident INC-2024-0317 matches with 0.92 similarity score."
            ),
            "affected_services": [
                {
                    "service_name": "order_service",
                    "sla_tier": "P0",
                    "risk_reason": "Direct dependency on modified charge_card signature.",
                    "hops_from_change": 1,
                }
            ],
            "recommended_tests": [
                "Run checkout integration tests with payment gateway mock."
            ],
            "deployment_strategy": "ROLLBACK_READY",
            "escalation_required": False,
            "similar_incident_ids": ["INC-2024-0317"],
        }
        assessment = RiskAssessment.model_validate(data)
        assert assessment.risk_score == 75
        assert assessment.risk_level == RiskLevel.HIGH
        assert assessment.deployment_strategy == DeploymentStrategy.ROLLBACK_READY
        assert len(assessment.affected_services) == 1

    def test_risk_score_bounds(self) -> None:
        with pytest.raises(ValidationError):
            RiskAssessment.model_validate(
                {
                    "risk_score": 105,  # Invalid: > 100
                    "risk_level": "CRITICAL",
                    "confidence": 0.9,
                    "rationale": "Valid rationale of sufficient length to pass the validator.",
                    "recommended_tests": ["test"],
                    "deployment_strategy": "BLOCK",
                    "escalation_required": True,
                }
            )

    def test_inconsistent_risk_level_is_auto_corrected(self) -> None:
        """If LLM outputs score=85 with level='LOW', validator auto-corrects to HIGH."""
        data = {
            "risk_score": 85,
            "risk_level": "LOW",  # Inconsistent with 85
            "confidence": 0.9,
            "rationale": "A comprehensive rationale exceeding fifty characters in length.",
            "recommended_tests": ["test endpoint"],
            "deployment_strategy": "ROLLBACK_READY",
            "escalation_required": False,
        }
        assessment = RiskAssessment.model_validate(data)
        assert assessment.risk_level == RiskLevel.HIGH


class TestUserMessageFormatting:
    """Tests for agent context prompt formatting."""

    def test_formats_symbols_and_incidents(self) -> None:
        symbols = [
            {
                "kind": "fastapi_route",
                "symbol": "charge_card",
                "route": "POST /charge",
                "lines": "10-25",
                "modified_line_count": 4,
            }
        ]
        blast_radius = BlastRadiusResult(
            origin_service="payment-service",
            affected_nodes=[
                ServiceNode(
                    service_name="order-service",
                    sla_tier="P0",
                    owner_team="commerce",
                    on_call_email="oncall@test.com",
                    hops=1,
                )
            ],
            has_p0_impact=True,
        )
        incidents = [
            IncidentRecord(
                incident_id="INC-2024-001",
                title="Payment failure outage",
                severity="P0",
                duration_minutes=30,
                affected_service="payment-service",
                root_cause_tags=["retry", "timeout"],
                postmortem_url="https://wiki/inc-1",
                similarity_score=0.91,
            )
        ]

        msg = _build_user_message(
            pr_title="refactor: payment backoff",
            pr_author="alice",
            changed_symbols=symbols,
            blast_radius=blast_radius,
            similar_incidents=incidents,
        )

        assert "refactor: payment backoff" in msg
        assert "alice" in msg
        assert "POST /charge" in msg
        assert "order-service" in msg
        assert "INC-2024-001" in msg
        assert "0.910" in msg


class TestRiskAssessmentAgentExecution:
    """Tests for the RiskAssessmentAgent calling AsyncOpenAI."""

    def test_successful_agent_call(self) -> None:
        import asyncio

        async def _test() -> None:
            expected_assessment = RiskAssessment(
                risk_score=72,
                risk_level=RiskLevel.HIGH,
                confidence=0.89,
                rationale=(
                    "Blast radius touches order-service (P0) within 1 hop. "
                    "INC-2024-001 has 0.91 similarity with an analogous failure mode."
                ),
                affected_services=[],
                recommended_tests=["Test charge_card under simulated network partition."],
                deployment_strategy=DeploymentStrategy.ROLLBACK_READY,
                escalation_required=False,
                similar_incident_ids=["INC-2024-001"],
            )

            mock_parsed_choice = MagicMock()
            mock_parsed_choice.message.refusal = None
            mock_parsed_choice.message.parsed = expected_assessment

            mock_completion_response = MagicMock()
            mock_completion_response.choices = [mock_parsed_choice]
            mock_completion_response.usage = None

            with patch("deployguard.agent.risk_agent.AsyncOpenAI") as mock_openai_cls:
                mock_client = MagicMock()
                mock_client.beta = MagicMock()
                mock_client.beta.chat = MagicMock()
                mock_client.beta.chat.completions = MagicMock()
                mock_client.beta.chat.completions.parse = AsyncMock(
                    return_value=mock_completion_response
                )
                mock_openai_cls.return_value = mock_client

                agent = RiskAssessmentAgent()
                blast_radius = BlastRadiusResult(origin_service="payment-service")

                result = await agent.assess(
                    pr_title="test",
                    pr_author="bob",
                    changed_symbols=[],
                    blast_radius=blast_radius,
                    similar_incidents=[],
                )

                assert result.risk_score == 72
                assert result.risk_level == RiskLevel.HIGH
                assert result.deployment_strategy == DeploymentStrategy.ROLLBACK_READY

        asyncio.run(_test())

