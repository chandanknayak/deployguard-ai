"""
tests/unit/test_db_operations.py — Unit tests for MongoDB blast radius and vector search.

Uses mock Motor clients/cursors so tests run hermetically without requiring a
live MongoDB Atlas instance.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from deployguard.db.client import MongoDBClient
from deployguard.db.db_operations import (
    BlastRadiusResult,
    IncidentRecord,
    ServiceNode,
    find_similar_incidents,
    get_blast_radius,
    save_risk_assessment,
)


@pytest.fixture
def mock_db_client() -> MongoDBClient:
    """Create a MongoDBClient backed by mocked Motor collections."""
    client = MagicMock(spec=MongoDBClient)
    client.code_graph = MagicMock()
    client.incidents = MagicMock()
    client.assessments = MagicMock()
    return client


class TestGetBlastRadius:
    """Tests for get_blast_radius using MongoDB $graphLookup."""

    def test_returns_empty_result_when_service_not_found(
        self, mock_db_client: MongoDBClient
    ) -> None:
        async def _test() -> None:
            mock_cursor = MagicMock()
            mock_cursor.to_list = AsyncMock(return_value=[])
            mock_db_client.code_graph.aggregate.return_value = mock_cursor

            result = await get_blast_radius(mock_db_client, "unknown-service")
            assert isinstance(result, BlastRadiusResult)
            assert result.origin_service == "unknown-service"
            assert result.total_affected == 0
            assert not result.has_p0_impact

        asyncio.run(_test())

    def test_parses_downstream_nodes_and_deduplicates(
        self, mock_db_client: MongoDBClient
    ) -> None:
        async def _test() -> None:
            raw_graph_doc = {
                "service_name": "payment-service",
                "blast_radius": [
                    {
                        "service_name": "order-service",
                        "sla_tier": "P0",
                        "owner_team": "commerce",
                        "on_call_email": "oncall@commerce.com",
                        "repo": "acme/order-service",
                        "hops": 1,
                    },
                    {
                        "service_name": "order-service",  # duplicate with higher hop
                        "sla_tier": "P0",
                        "owner_team": "commerce",
                        "on_call_email": "oncall@commerce.com",
                        "repo": "acme/order-service",
                        "hops": 3,
                    },
                    {
                        "service_name": "analytics-service",
                        "sla_tier": "P3",
                        "owner_team": "data",
                        "on_call_email": "",
                        "repo": "acme/analytics",
                        "hops": 2,
                    },
                ],
            }

            mock_cursor = MagicMock()
            mock_cursor.to_list = AsyncMock(return_value=[raw_graph_doc])
            mock_db_client.code_graph.aggregate.return_value = mock_cursor

            result = await get_blast_radius(mock_db_client, "payment-service")

            assert result.origin_service == "payment-service"
            assert result.total_affected == 2  # Deduplicated
            assert result.has_p0_impact is True
            assert result.has_p1_impact is False

            order_node = next(n for n in result.affected_nodes if n.service_name == "order-service")
            assert order_node.hops == 1
            assert order_node.sla_tier == "P0"

            critical = result.critical_services
            assert len(critical) == 1
            assert critical[0].service_name == "order-service"

        asyncio.run(_test())


class TestFindSimilarIncidents:
    """Tests for find_similar_incidents using Atlas $vectorSearch."""

    def test_executes_aggregation_and_filters_low_similarity(
        self, mock_db_client: MongoDBClient
    ) -> None:
        async def _test() -> None:
            raw_incidents = [
                {
                    "incident_id": "INC-2024-001",
                    "title": "Payment gateway timeout storm",
                    "severity": "P0",
                    "duration_minutes": 45,
                    "affected_service": "payment-service",
                    "root_cause_tags": ["retry-storm", "timeout"],
                    "postmortem_url": "https://wiki/inc-1",
                    "similarity_score": 0.92,
                },
                {
                    "incident_id": "INC-2024-002",
                    "title": "Minor cache eviction latency",
                    "severity": "P3",
                    "duration_minutes": 10,
                    "affected_service": "payment-service",
                    "root_cause_tags": ["cache"],
                    "postmortem_url": "",
                    "similarity_score": 0.75,
                },
            ]

            mock_cursor = MagicMock()
            mock_cursor.to_list = AsyncMock(return_value=raw_incidents)
            mock_db_client.incidents.aggregate.return_value = mock_cursor

            query_vector = [0.1] * 1536
            results = await find_similar_incidents(
                db_client=mock_db_client,
                query_embedding=query_vector,
                affected_service="payment-service",
                min_similarity=0.70,
            )

            assert len(results) == 2
            assert results[0].incident_id == "INC-2024-001"
            assert results[0].similarity_score == 0.92
            assert results[0].severity == "P0"

            called_pipeline = mock_db_client.incidents.aggregate.call_args[0][0]
            vsearch_stage = called_pipeline[0]["$vectorSearch"]
            assert vsearch_stage["filter"] == {"affected_service": {"$eq": "payment-service"}}

        asyncio.run(_test())


class TestSaveRiskAssessment:
    """Tests for save_risk_assessment audit log persistence."""

    def test_inserts_document_and_returns_id(
        self, mock_db_client: MongoDBClient
    ) -> None:
        async def _test() -> None:
            mock_insert_result = MagicMock()
            mock_insert_result.inserted_id = "6639b56f1a8c4b1234567890"
            mock_db_client.assessments.insert_one = AsyncMock(return_value=mock_insert_result)

            doc = {"assessment_id": "test-123", "risk_score": 75}
            inserted_id = await save_risk_assessment(mock_db_client, doc)

            assert inserted_id == "6639b56f1a8c4b1234567890"
            mock_db_client.assessments.insert_one.assert_called_once_with(doc)

        asyncio.run(_test())


