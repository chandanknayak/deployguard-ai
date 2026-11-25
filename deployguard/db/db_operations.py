"""
db/db_operations.py — Core MongoDB query operations for DeployGuard AI.

This module contains the two database intelligence functions that form the
factual backbone of the risk assessment pipeline:

┌──────────────────────────────────────────────────────────────────────────┐
│  FUNCTION 1: get_blast_radius()                                          │
│                                                                          │
│  Uses MongoDB $graphLookup to perform recursive, multi-hop traversal     │
│  of the code dependency graph, answering:                                │
│  "If service X changes, which downstream services are transitively       │
│   affected — and what are their SLA tiers?"                              │
│                                                                          │
│  Why $graphLookup over a dedicated graph database (Neo4j)?               │
│  → Single data store: graph + vector search live in one Atlas cluster.   │
│  → No ETL pipeline to keep a separate graph DB in sync.                 │
│  → Document model stores rich node metadata (SLA tier, team, on-call)   │
│    co-located with edges — no joins needed.                              │
│  → maxDepth prevents runaway traversal on cyclic or deeply-nested graphs.│
│                                                                          │
│  FUNCTION 2: find_similar_incidents()                                    │
│                                                                          │
│  Uses MongoDB Atlas $vectorSearch to perform approximate nearest         │
│  neighbour (ANN) search over historical incident embeddings, answering:  │
│  "Have we seen a deployment failure that looks like this change before?" │
│                                                                          │
│  Why Atlas Vector Search over a separate vector DB (Pinecone, Weaviate)?│
│  → Operational simplicity: no second database to provision or monitor.  │
│  → Pre-filtering via ``filter`` runs at the HNSW index level, not post- │
│    fetch — far more efficient than filtering after retrieval.            │
│  → Results can be joined with the graph context in a single aggregation  │
│    pipeline using $lookup, enabling compound risk scoring.               │
└──────────────────────────────────────────────────────────────────────────┘

Collection schema contracts
───────────────────────────

``code_graph`` collection (one document per service/symbol node):
{
  "_id": ObjectId,
  "service_name":  str,          # e.g. "payment-service"
  "symbol":        str,          # fully qualified symbol: "payment_service.charge_card"
  "sla_tier":      "P0"|"P1"|"P2"|"P3",
  "owner_team":    str,          # e.g. "billing-infra"
  "on_call_email": str,
  "language":      str,          # "python" | "java" | "go" | etc.
  "repo":          str,          # "acme/payment-service"
  "downstream_services": [str],  # list of service_name values this node calls
}

``incidents`` collection (one document per historical incident):
{
  "_id":            ObjectId,
  "incident_id":    str,         # e.g. "INC-2024-0317"
  "title":          str,
  "severity":       "P0"|"P1"|"P2"|"P3",
  "duration_minutes": int,
  "affected_service": str,       # primary service that caused the incident
  "root_cause_tags": [str],      # e.g. ["retry-logic", "thundering-herd"]
  "postmortem_url": str,
  "embedding":      [float],     # 1536-dim text-embedding-3-small vector
  "created_at":     datetime,
}
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from deployguard.config import settings
from deployguard.db.client import MongoDBClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Return-type dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ServiceNode:
    """
    A single node in the blast radius graph — one transitively affected service.

    Attributes:
        service_name:   Unique service identifier (matches ``code_graph.service_name``).
        sla_tier:       Service-level agreement classification (P0 = most critical).
        owner_team:     Team responsible for this service.
        on_call_email:  Current on-call contact (may be empty if not configured).
        hops:           Number of dependency hops from the changed service.
        repo:           Repository containing this service.
    """

    service_name: str
    sla_tier: str
    owner_team: str
    on_call_email: str
    hops: int
    repo: str = ""


@dataclass
class BlastRadiusResult:
    """
    Complete blast radius result for a single changed service.

    Attributes:
        origin_service:   The service whose code was changed (the epicentre).
        affected_nodes:   All transitively reachable downstream service nodes.
        max_depth_reached: The hop depth at which the traversal stopped.
        has_p0_impact:    True if any P0-tier service is in the blast radius.
        has_p1_impact:    True if any P1-tier service is in the blast radius.
    """

    origin_service: str
    affected_nodes: list[ServiceNode] = field(default_factory=list)
    max_depth_reached: int = 0
    has_p0_impact: bool = False
    has_p1_impact: bool = False

    @property
    def total_affected(self) -> int:
        return len(self.affected_nodes)

    @property
    def critical_services(self) -> list[ServiceNode]:
        """Return only P0 and P1 nodes sorted by hop distance."""
        return sorted(
            [n for n in self.affected_nodes if n.sla_tier in ("P0", "P1")],
            key=lambda n: (n.hops, n.sla_tier),
        )


@dataclass
class IncidentRecord:
    """
    A single historical incident returned by the vector similarity search.

    Attributes:
        incident_id:       Unique incident identifier (e.g. "INC-2024-0317").
        title:             Human-readable incident description.
        severity:          Incident severity tier.
        duration_minutes:  How long the incident lasted.
        affected_service:  The primary service that caused the incident.
        root_cause_tags:   Labels describing the failure mode.
        postmortem_url:    Link to the full postmortem document.
        similarity_score:  Vector Search cosine similarity score [0.0, 1.0].
    """

    incident_id: str
    title: str
    severity: str
    duration_minutes: int
    affected_service: str
    root_cause_tags: list[str]
    postmortem_url: str
    similarity_score: float


# ---------------------------------------------------------------------------
# Function 1: Blast Radius via $graphLookup
# ---------------------------------------------------------------------------


async def get_blast_radius(
    db_client: MongoDBClient,
    service_name: str,
    max_depth: int | None = None,
) -> BlastRadiusResult:
    """
    Compute the transitive blast radius of a service using MongoDB ``$graphLookup``.

    Starting from ``service_name``, recursively traverses the ``code_graph``
    collection along the ``downstream_services`` edges to find every service
    that *depends on* (directly or transitively) the changed code.

    --- Why $graphLookup? ---

    ``$graphLookup`` is MongoDB's native recursive aggregation stage for
    graph traversal. It is equivalent to a recursive CTE in SQL but is
    purpose-built for document collections:

        $graphLookup: {
          from: <collection>,
          startWith: <initial value>,
          connectFromField: <field to follow outward>,
          connectToField: <field to match inward>,
          as: <output array>,
          maxDepth: <hop limit>,
          depthField: <field to record hop count>,
          restrictSearchWithMatch: <optional filter applied at each hop>
        }

    The ``maxDepth`` bound prevents runaway traversal on graphs with long
    dependency chains or accidental cycles. ``depthField`` enriches each
    returned node with its hop distance from the origin.

    --- Graph direction convention ---

    The ``downstream_services`` field on each document lists services that
    the current service calls (i.e. its dependencies). We traverse
    *callers* → *callees* to find who is downstream of a change:

        payment-service  ──calls──►  order-service
        order-service    ──calls──►  notification-service

    If ``payment-service`` changes, both ``order-service`` and
    ``notification-service`` are in the blast radius.

    Args:
        db_client:
            Active ``MongoDBClient`` instance.
        service_name:
            The service whose change is being analysed (the epicentre).
            Must match the ``service_name`` field in ``code_graph``.
        max_depth:
            Maximum number of hops to traverse. Defaults to
            ``settings.graph_max_depth`` (configurable via env var).

    Returns:
        A ``BlastRadiusResult`` containing all reachable downstream nodes,
        enriched with SLA tier, team ownership, and hop distance.

    Raises:
        ``pymongo.errors.PyMongoError``: On MongoDB connectivity failure.

    Example::

        result = await get_blast_radius(db, "payment-service")
        print(f"P0 services at risk: {[n.service_name for n in result.critical_services]}")
    """
    depth_limit = max_depth if max_depth is not None else settings.graph_max_depth

    logger.info(
        "Computing blast radius for service='%s' (max_depth=%d)...",
        service_name,
        depth_limit,
    )

    # -----------------------------------------------------------------------
    # Aggregation Pipeline
    # -----------------------------------------------------------------------
    # Stage 1 ($match):
    #   Locate the origin service document in the graph. This is the starting
    #   node; we match on service_name for a clean, indexed lookup.
    #
    # Stage 2 ($graphLookup):
    #   Recursively follow downstream_services edges.
    #   - connectFromField: the field on each intermediate node to expand
    #   - connectToField:   the field on target nodes to match against
    #   - depthField:       populated on each result doc with its hop count
    #   - restrictSearchWithMatch: optional — here we skip deleted services
    #
    # Stage 3 ($project):
    #   Return only the fields we need; exclude raw embeddings and internal
    #   fields from the result to keep payloads small.
    # -----------------------------------------------------------------------

    pipeline: list[dict[str, Any]] = [
        # Stage 1: Start from the changed service
        {
            "$match": {
                "service_name": service_name,
            }
        },
        # Stage 2: Recursive graph traversal
        {
            "$graphLookup": {
                "from": settings.mongodb_code_graph_collection,
                "startWith": "$downstream_services",
                "connectFromField": "downstream_services",
                "connectToField": "service_name",
                "as": "blast_radius",
                "maxDepth": depth_limit,
                # Record the hop distance on each node in the output array.
                # This is critical for prioritising near vs. far dependencies.
                "depthField": "_hops",
                # Only traverse nodes that are active (skip deprecated services).
                # This filter is applied at every hop, not just the final results,
                # which significantly prunes unnecessary traversal paths.
                "restrictSearchWithMatch": {
                    "status": {"$ne": "deprecated"},
                },
            }
        },
        # Stage 3: Project only what we need downstream
        {
            "$project": {
                "_id": 0,
                "service_name": 1,
                "blast_radius": {
                    "$map": {
                        "input": "$blast_radius",
                        "as": "node",
                        "in": {
                            "service_name": "$$node.service_name",
                            "sla_tier": "$$node.sla_tier",
                            "owner_team": "$$node.owner_team",
                            "on_call_email": {
                                "$ifNull": ["$$node.on_call_email", ""]
                            },
                            "repo": {"$ifNull": ["$$node.repo", ""]},
                            # _hops is injected by $graphLookup's depthField
                            "hops": "$$node._hops",
                        },
                    }
                },
            }
        },
    ]

    cursor = db_client.code_graph.aggregate(pipeline)
    documents = await cursor.to_list(length=1)

    if not documents:
        logger.warning(
            "No code_graph document found for service_name='%s'. "
            "Ensure the graph is seeded with 'scripts/seed_graph.py'.",
            service_name,
        )
        return BlastRadiusResult(origin_service=service_name)

    raw_blast: list[dict] = documents[0].get("blast_radius", [])

    # Deduplicate: $graphLookup may return the same node via multiple paths
    # (e.g. service C is reachable via A→B→C and A→C). Keep the shortest path.
    seen: dict[str, ServiceNode] = {}
    for raw_node in raw_blast:
        svc = raw_node.get("service_name", "")
        hop = int(raw_node.get("hops", 0))
        if svc not in seen or hop < seen[svc].hops:
            seen[svc] = ServiceNode(
                service_name=svc,
                sla_tier=raw_node.get("sla_tier", "P3"),
                owner_team=raw_node.get("owner_team", "unknown"),
                on_call_email=raw_node.get("on_call_email", ""),
                hops=hop,
                repo=raw_node.get("repo", ""),
            )

    affected_nodes = list(seen.values())
    # Sort by (hops ASC, sla_tier ASC) so P0 near-hops appear first
    affected_nodes.sort(key=lambda n: (n.hops, n.sla_tier))

    result = BlastRadiusResult(
        origin_service=service_name,
        affected_nodes=affected_nodes,
        max_depth_reached=max(n.hops for n in affected_nodes) if affected_nodes else 0,
        has_p0_impact=any(n.sla_tier == "P0" for n in affected_nodes),
        has_p1_impact=any(n.sla_tier == "P1" for n in affected_nodes),
    )

    logger.info(
        "Blast radius computed: service='%s' → %d downstream nodes "
        "(P0=%s, P1=%s, max_depth=%d).",
        service_name,
        result.total_affected,
        result.has_p0_impact,
        result.has_p1_impact,
        result.max_depth_reached,
    )
    return result


# ---------------------------------------------------------------------------
# Function 2: Historical Incidents via Atlas $vectorSearch
# ---------------------------------------------------------------------------


async def find_similar_incidents(
    db_client: MongoDBClient,
    query_embedding: list[float],
    affected_service: str | None = None,
    top_k: int | None = None,
    min_similarity: float = 0.70,
) -> list[IncidentRecord]:
    """
    Find the most semantically similar historical incidents using MongoDB
    Atlas Vector Search (``$vectorSearch``).

    The query embedding is compared against pre-computed embeddings stored
    in the ``incidents`` collection using Approximate Nearest Neighbour
    (ANN) search powered by the HNSW (Hierarchical Navigable Small World)
    algorithm in Atlas Search.

    --- Why $vectorSearch over post-fetch filtering? ---

    A naive approach would fetch all incidents and compute cosine similarity
    in Python. This does not scale — with 100k+ incident documents, Python-
    side filtering is O(n) per query.

    ``$vectorSearch`` pushes the similarity computation into the MongoDB
    HNSW index, returning the top-K candidates in O(log n) time. The
    ``filter`` parameter applies an indexed pre-filter *at the HNSW level*,
    not after retrieval, which means we never load non-matching documents
    into memory.

    --- Index requirement ---

    The ``incidents`` collection must have an Atlas Vector Search index
    with the following configuration:

        {
          "mappings": {
            "dynamic": false,
            "fields": {
              "embedding": [{
                "type": "knnVector",
                "dimensions": 1536,
                "similarity": "cosine"
              }],
              "affected_service": [{
                "type": "token"
              }]
            }
          }
        }

    Create this index with::

        mongosh $MONGODB_URI --eval "
          db.incidents.createSearchIndex(
            'incident_embedding_index',
            'vectorSearch',
            { mappings: { ... } }
          )
        "

    Args:
        db_client:
            Active ``MongoDBClient`` instance.
        query_embedding:
            A 1536-dimensional float list produced by
            ``openai.embeddings.create(model='text-embedding-3-small')``.
            Must match the dimensionality of the stored embeddings.
        affected_service:
            Optional service name to pre-filter results. When provided,
            only incidents affecting this specific service are considered.
            This narrows the vector search space for higher precision.
        top_k:
            Number of results to return. Defaults to ``settings.vector_search_limit``.
        min_similarity:
            Minimum cosine similarity score threshold [0.0, 1.0]. Results
            below this threshold are discarded. Prevents low-relevance
            incidents from polluting the risk context.

    Returns:
        List of ``IncidentRecord`` objects ordered by similarity score
        descending (most similar first). May be shorter than ``top_k`` if
        fewer results exceed ``min_similarity``.

    Raises:
        ``pymongo.errors.PyMongoError``: On MongoDB connectivity failure.
        ``pymongo.errors.OperationFailure``: If the vector search index
            does not exist or the embedding dimension is incorrect.

    Example::

        embedding = await get_embedding("payment service retry logic timeout")
        incidents = await find_similar_incidents(db, embedding, "payment-service")
        for inc in incidents:
            print(f"{inc.incident_id}: {inc.title} (similarity={inc.similarity_score:.3f})")
    """
    limit = top_k if top_k is not None else settings.vector_search_limit
    num_candidates = settings.vector_search_num_candidates

    logger.info(
        "Running vector search: service_filter='%s', top_k=%d, num_candidates=%d.",
        affected_service or "any",
        limit,
        num_candidates,
    )

    # -----------------------------------------------------------------------
    # Aggregation Pipeline
    # -----------------------------------------------------------------------
    # Stage 1 ($vectorSearch):
    #   Atlas Vector Search ANN lookup against the HNSW index.
    #   - index:         The Atlas Search index name (must exist on the cluster).
    #   - path:          The field containing the stored embedding vectors.
    #   - queryVector:   The query embedding to compare against.
    #   - numCandidates: Controls the recall/latency trade-off. Higher values
    #                    search more of the HNSW graph → better recall, more
    #                    compute. Recommend: numCandidates = limit * 10–30.
    #   - limit:         Maximum results to return from the HNSW search.
    #   - filter:        Pre-filter applied INSIDE the HNSW index traversal.
    #                    This is a MongoDB query expression on indexed fields.
    #                    Only fields with a "token" mapping can be filtered here.
    #
    # Stage 2 ($addFields):
    #   Materialise the Vector Search score as a named field using the
    #   special ``{"$meta": "vectorSearchScore"}`` expression.
    #
    # Stage 3 ($match):
    #   Discard results below the minimum similarity threshold AFTER score
    #   materialisation (cannot use $meta in the $vectorSearch filter).
    #
    # Stage 4 ($project):
    #   Return only the fields consumed by the risk agent; exclude raw
    #   embedding vectors (1536 floats × 4 bytes = ~6KB per document).
    # -----------------------------------------------------------------------

    # Build the optional pre-filter for $vectorSearch
    # Only fields indexed as "token" type in the Atlas Search index can be
    # used here. Applying this filter at the HNSW level avoids loading
    # unrelated service incidents into the result set.
    vector_search_filter: dict | None = None
    if affected_service:
        vector_search_filter = {"affected_service": {"$eq": affected_service}}

    # Construct the $vectorSearch stage
    vector_search_stage: dict[str, Any] = {
        "$vectorSearch": {
            "index": settings.vector_search_index_name,
            "path": "embedding",
            "queryVector": query_embedding,
            "numCandidates": num_candidates,
            "limit": limit,
        }
    }

    # Inject the pre-filter only when a service name was provided.
    # Including an empty/None filter causes a validation error in Atlas.
    if vector_search_filter:
        vector_search_stage["$vectorSearch"]["filter"] = vector_search_filter

    pipeline: list[dict[str, Any]] = [
        # Stage 1: ANN vector search
        vector_search_stage,
        # Stage 2: Materialise the similarity score as a named field
        {
            "$addFields": {
                "similarity_score": {"$meta": "vectorSearchScore"},
            }
        },
        # Stage 3: Apply minimum similarity threshold
        {
            "$match": {
                "similarity_score": {"$gte": min_similarity},
            }
        },
        # Stage 4: Project safe output fields (exclude the raw embedding vector)
        {
            "$project": {
                "_id": 0,
                "incident_id": 1,
                "title": 1,
                "severity": 1,
                "duration_minutes": 1,
                "affected_service": 1,
                "root_cause_tags": 1,
                "postmortem_url": {"$ifNull": ["$postmortem_url", ""]},
                "similarity_score": 1,
            }
        },
    ]

    cursor = db_client.incidents.aggregate(pipeline)
    raw_results: list[dict] = await cursor.to_list(length=limit)

    incidents: list[IncidentRecord] = [
        IncidentRecord(
            incident_id=doc.get("incident_id", "UNKNOWN"),
            title=doc.get("title", ""),
            severity=doc.get("severity", "P3"),
            duration_minutes=int(doc.get("duration_minutes", 0)),
            affected_service=doc.get("affected_service", ""),
            root_cause_tags=doc.get("root_cause_tags", []),
            postmortem_url=doc.get("postmortem_url", ""),
            similarity_score=float(doc.get("similarity_score", 0.0)),
        )
        for doc in raw_results
    ]

    logger.info(
        "Vector search complete: %d incidents returned (similarity >= %.2f).",
        len(incidents),
        min_similarity,
    )
    return incidents


# ---------------------------------------------------------------------------
# Persistence: Save completed risk assessment to MongoDB
# ---------------------------------------------------------------------------


async def save_risk_assessment(
    db_client: MongoDBClient,
    assessment: dict[str, Any],
) -> str:
    """
    Persist a completed risk assessment document to the ``risk_assessments``
    collection for audit logging and trend analysis.
    """
    import datetime

    assessment.setdefault("source", "MANUAL_SCAN")
    assessment.setdefault("status", "COMPLETED")
    assessment["created_at"] = datetime.datetime.now(datetime.timezone.utc)
    result = await db_client.assessments.insert_one(assessment)
    inserted_id = str(result.inserted_id)
    logger.info(
        "Risk assessment persisted: assessment_id=%s source=%s -> _id=%s.",
        assessment.get("assessment_id", "?"),
        assessment.get("source"),
        inserted_id,
    )
    return inserted_id


async def ensure_indexes(db_client: MongoDBClient) -> None:
    """
    Create idempotent MongoDB indexes at startup so queries on assessments,
    users, policies, deployments, and audit logs stay fast and multi-tenant safe.
    """
    if db_client is None or getattr(db_client, "db", None) is None:
        return

    index_specs = [
        (db_client.assessments, [("assessment_id", 1)], {"unique": True, "name": "idx_assessment_id_unique"}),
        (db_client.assessments, [("repo_full_name", 1), ("pr_number", 1), ("created_at", -1)], {"name": "idx_repo_pr_time"}),
        (db_client.assessments, [("source", 1), ("created_at", -1)], {"name": "idx_source_time"}),
        (db_client.assessments, [("owner_email", 1), ("created_at", -1)], {"name": "idx_owner_time"}),
        (db_client.db["users"], [("email", 1)], {"unique": True, "name": "idx_user_email_unique"}),
        (db_client.db["enterprise_policy"], [("owner_email", 1)], {"name": "idx_policy_owner"}),
        (db_client.db["audit_log"], [("owner_email", 1), ("timestamp", -1)], {"name": "idx_audit_owner_time"}),
        (db_client.db["audit_log"], [("repo", 1), ("timestamp", -1)], {"name": "idx_audit_repo_time"}),
        (db_client.db["deployments"], [("owner_email", 1), ("timestamp", -1)], {"name": "idx_deploy_owner_time"}),
    ]

    for col, keys, kwargs in index_specs:
        try:
            await col.create_index(keys, **kwargs)
        except Exception as exc:
            logger.debug("Skipping index %s: %s", kwargs.get("name"), exc)

