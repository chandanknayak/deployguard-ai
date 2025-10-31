"""
api/routers/assessments.py — Read-side API for Risk Assessment results.

Provides REST endpoints for the Streamlit dashboard (and any external
consumer) to query completed risk assessments persisted in MongoDB.

Endpoints:
    GET /assessments/                    — Paginated list of recent assessments.
    GET /assessments/{assessment_id}     — Single assessment by ID.
    GET /assessments/pr/{repo}/{pr_num}  — Latest assessment for a specific PR.
    GET /assessments/stats               — Aggregate statistics.
    GET /assessments/live                — Server-Sent Events stream for real-time updates.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"],
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_collection(request: Request):
    """Return the MongoDB assessments collection from app state."""
    db_client = getattr(request.app.state, "db", None)
    if db_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not connected. Set MONGODB_URI in your .env file.",
        )
    return db_client.db["risk_assessments"]


def _sanitize(doc: dict) -> dict:
    """Strip MongoDB ObjectId (not JSON-serializable) and return clean dict."""
    doc.pop("_id", None)
    return doc


# ---------------------------------------------------------------------------
# GET /assessments/stats
# ---------------------------------------------------------------------------

@router.get(
    "/stats",
    summary="Aggregate assessment statistics",
    description="Returns counts of PASS / WARN / BLOCK assessments, plus average risk score.",
)
async def get_stats(request: Request) -> JSONResponse:
    """
    Returns aggregated statistics across all stored assessments.
    Used by the dashboard header KPI strip.
    """
    col = _get_collection(request)
    try:
        pipeline = [
            {
                "$group": {
                    "_id": "$risk_level",
                    "count": {"$sum": 1},
                    "avg_score": {"$avg": "$risk_score"},
                }
            }
        ]
        cursor = col.aggregate(pipeline)
        raw = await cursor.to_list(length=100)

        totals = {"PASS": 0, "WARN": 0, "BLOCK": 0, "UNKNOWN": 0}
        avg_scores: dict[str, float] = {}
        total_count = 0

        for row in raw:
            level = (row.get("_id") or "UNKNOWN").upper()
            count = row.get("count", 0)
            totals[level] = count
            avg_scores[level] = round(row.get("avg_score") or 0, 1)
            total_count += count

        return JSONResponse({
            "total_assessments": total_count,
            "by_decision": totals,
            "avg_scores_by_decision": avg_scores,
        })
    except Exception as exc:
        logger.error("Stats aggregation failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /assessments/
# ---------------------------------------------------------------------------

@router.get(
    "/",
    summary="List recent assessments",
    description="Returns the most recent risk assessments, newest first.",
)
async def list_assessments(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100, description="Number of results to return"),
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    repo: str | None = Query(default=None, description="Filter by repo (e.g. acme/payment-service)"),
    decision: str | None = Query(default=None, description="Filter by decision: PASS, WARN, BLOCK"),
) -> JSONResponse:
    """
    Paginated list of risk assessments from MongoDB, sorted by creation time.
    Used by the dashboard 'History' view.
    """
    col = _get_collection(request)
    try:
        query: dict = {}
        if repo:
            query["repo_full_name"] = repo
        if decision:
            query["risk_level"] = decision.upper()

        cursor = col.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        total = await col.count_documents(query)

        return JSONResponse({
            "total": total,
            "skip": skip,
            "limit": limit,
            "results": docs,
        })
    except Exception as exc:
        logger.error("list_assessments failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /assessments/{assessment_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{assessment_id}",
    summary="Get assessment by ID",
    description="Fetches a single risk assessment record by its UUID.",
)
async def get_assessment(request: Request, assessment_id: str) -> JSONResponse:
    """Return one assessment document from MongoDB."""
    col = _get_collection(request)
    try:
        doc = await col.find_one({"assessment_id": assessment_id}, {"_id": 0})
        if doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment '{assessment_id}' not found.",
            )
        return JSONResponse(doc)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_assessment(%s) failed: %s", assessment_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /assessments/pr/{repo_owner}/{repo_name}/{pr_number}
# ---------------------------------------------------------------------------

@router.get(
    "/pr/{repo_owner}/{repo_name}/{pr_number}",
    summary="Get latest assessment for a specific PR",
    description="Returns the most recent assessment for the given repo + PR number.",
)
async def get_pr_assessment(
    request: Request,
    repo_owner: str,
    repo_name: str,
    pr_number: int,
) -> JSONResponse:
    """
    Look up the latest DeployGuard assessment for a specific PR.
    Useful for GitHub App UI integrations and status badge lookups.
    """
    col = _get_collection(request)
    repo_full = f"{repo_owner}/{repo_name}"
    try:
        doc = await col.find_one(
            {"repo_full_name": repo_full, "pr_number": pr_number},
            {"_id": 0},
            sort=[("created_at", -1)],
        )
        if doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No assessment found for PR #{pr_number} in {repo_full}.",
            )
        return JSONResponse(doc)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_pr_assessment(%s#%d) failed: %s", repo_full, pr_number, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /assessments/live  — Server-Sent Events (SSE) real-time stream
# ---------------------------------------------------------------------------

@router.get(
    "/live",
    summary="Real-time SSE stream of new assessments",
    description=(
        "Server-Sent Events endpoint. The Streamlit dashboard subscribes "
        "here to receive new assessment notifications in real time without polling."
    ),
    response_class=StreamingResponse,
)
async def live_assessments(request: Request) -> StreamingResponse:
    """
    Push new assessments to connected clients via SSE.

    Streams the last 5 assessments on connect, then pushes new ones
    as they arrive (polls MongoDB every 2 seconds for new documents
    inserted since the stream started).
    """
    col = _get_collection(request)

    async def event_generator() -> AsyncIterator[str]:
        # Send a heartbeat immediately so the browser doesn't time out
        yield "event: connected\ndata: {\"status\": \"streaming\"}\n\n"

        import datetime

        since = datetime.datetime.utcnow()

        # Backfill: last 5 existing assessments
        cursor = col.find({}, {"_id": 0}).sort("created_at", -1).limit(5)
        recent = await cursor.to_list(length=5)
        for doc in reversed(recent):
            payload = json.dumps(doc, default=str)
            yield f"event: assessment\ndata: {payload}\n\n"

        # Stream new assessments as they arrive
        while True:
            if await request.is_disconnected():
                break
            new_cursor = col.find(
                {"created_at": {"$gt": since}},
                {"_id": 0},
            ).sort("created_at", 1)
            new_docs = await new_cursor.to_list(length=50)
            for doc in new_docs:
                since = doc.get("created_at", since)
                payload = json.dumps(doc, default=str)
                yield f"event: assessment\ndata: {payload}\n\n"

            # Heartbeat to keep connection alive
            yield "event: heartbeat\ndata: {}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
