"""
api/routers/assessments.py — Tenant-scoped Read API for Risk Assessment results.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
from typing import Annotated, Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse

from deployguard.api.routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"],
)


def _get_collection(request: Request):
    """Return the MongoDB assessments collection from app state."""
    db_client = getattr(request.app.state, "db", None)
    if db_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not connected. Set MONGODB_URI in your .env file.",
        )
    return db_client.db["risk_assessments"]


def _sanitize(doc: dict | list) -> Any:
    """Clean MongoDB docs (ObjectId, datetime) for JSON serialisation."""
    if isinstance(doc, dict):
        doc.pop("_id", None)
    return jsonable_encoder(doc)


def _tenant_scope(current_user: dict[str, Any]) -> dict[str, Any]:
    """Build strict workspace/owner query filter preventing cross-tenant reads."""
    ws_id = current_user.get("workspace_id")
    email = current_user.get("email")
    repo_names = [
        r.get("full_name") for r in current_user.get("connected_repos", []) if r.get("full_name")
    ]
    clauses: list[dict[str, Any]] = []
    if ws_id:
        clauses.append({"workspace_id": ws_id})
    if email:
        clauses.append({"owner_email": email})
    if repo_names:
        clauses.append({"repo_full_name": {"$in": repo_names}})
    return {"$or": clauses} if len(clauses) > 1 else (clauses[0] if clauses else {"owner_email": "__none__"})


@router.get(
    "/stats",
    summary="Aggregate assessment statistics for workspace",
)
async def get_stats(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    include_simulations: bool = Query(default=False),
) -> JSONResponse:
    col = _get_collection(request)
    try:
        match_stage: dict[str, Any] = _tenant_scope(current_user)
        if not include_simulations:
            match_stage = {"$and": [match_stage, {"source": {"$ne": "SIMULATION"}}]}

        pipeline = [
            {"$match": match_stage},
            {
                "$group": {
                    "_id": "$risk_level",
                    "count": {"$sum": 1},
                    "avg_score": {"$avg": "$risk_score"},
                }
            },
        ]
        raw = await col.aggregate(pipeline).to_list(length=100)

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
            "include_simulations": include_simulations,
        })
    except Exception as exc:
        logger.error("Stats aggregation failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/",
    summary="List recent workspace assessments",
)
async def list_assessments(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    limit: int = Query(default=20, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    repo: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    source: str | None = Query(default=None),
    include_simulations: bool = Query(default=False),
) -> JSONResponse:
    col = _get_collection(request)
    try:
        filters: list[dict[str, Any]] = [_tenant_scope(current_user)]
        if repo:
            filters.append({"repo_full_name": repo})
        if decision:
            filters.append({"risk_level": decision.upper()})
        if source:
            filters.append({"source": source.upper()})
        elif not include_simulations:
            filters.append({"source": {"$ne": "SIMULATION"}})

        query = {"$and": filters} if len(filters) > 1 else filters[0]
        cursor = col.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        total = await col.count_documents(query)

        return JSONResponse({
            "total": total,
            "skip": skip,
            "limit": limit,
            "results": _sanitize(docs),
        })
    except Exception as exc:
        logger.error("list_assessments failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/live",
    summary="Real-time SSE stream of workspace assessments",
    response_class=StreamingResponse,
)
async def live_assessments(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> StreamingResponse:
    col = _get_collection(request)
    scope = _tenant_scope(current_user)

    async def event_generator() -> AsyncIterator[str]:
        yield 'event: connected\ndata: {"status": "streaming"}\n\n'
        since = datetime.datetime.now(datetime.timezone.utc)

        recent = await col.find(scope, {"_id": 0}).sort("created_at", -1).limit(5).to_list(length=5)
        for doc in reversed(recent):
            yield f"event: assessment\ndata: {json.dumps(doc, default=str)}\n\n"

        while True:
            if await request.is_disconnected():
                break
            poll_q = {"$and": [scope, {"created_at": {"$gt": since}}]}
            new_docs = await col.find(poll_q, {"_id": 0}).sort("created_at", 1).to_list(length=50)
            for doc in new_docs:
                since = doc.get("created_at", since)
                yield f"event: assessment\ndata: {json.dumps(doc, default=str)}\n\n"

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


@router.get(
    "/pr/{repo_owner}/{repo_name}/{pr_number}",
    summary="Get latest assessment for a specific workspace PR",
)
async def get_pr_assessment(
    request: Request,
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> JSONResponse:
    col = _get_collection(request)
    repo_full = f"{repo_owner}/{repo_name}"
    try:
        query = {"$and": [_tenant_scope(current_user), {"repo_full_name": repo_full, "pr_number": pr_number}]}
        doc = await col.find_one(query, {"_id": 0}, sort=[("created_at", -1)])
        if doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No assessment found for PR #{pr_number} in {repo_full}.",
            )
        return JSONResponse(_sanitize(doc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_pr_assessment(%s#%d) failed: %s", repo_full, pr_number, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}",
    summary="Get assessment by ID",
)
async def get_assessment(
    request: Request,
    assessment_id: str,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> JSONResponse:
    col = _get_collection(request)
    try:
        query = {"$and": [_tenant_scope(current_user), {"assessment_id": assessment_id}]}
        doc = await col.find_one(query, {"_id": 0})
        if doc is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment '{assessment_id}' not found.",
            )
        return JSONResponse(_sanitize(doc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_assessment(%s) failed: %s", assessment_id, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
