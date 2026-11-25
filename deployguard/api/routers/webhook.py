"""
api/routers/webhook.py — Multi-Tenant GitHub Webhook Ingestion Router.

Validates HMAC-SHA256 webhook signatures, acknowledges valid Pull Request events
with HTTP 202 Accepted immediately, resolves matching tenant workspace & encrypted
token if connected in MongoDB, and runs the full deterministic + optional AI pipeline.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from deployguard.config import settings
from deployguard.core.crypto import decrypt_secret
from deployguard.core.pipeline import persist_or_update_assessment, run_pr_analysis
from deployguard.core.security import extract_event_type, verify_github_signature
from deployguard.db.client import MongoDBClient
from deployguard.exceptions import WebhookSignatureError
from deployguard.models.analysis import AnalysisResult, RiskLevel
from deployguard.models.webhook import GitHubPullRequestPayload

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/webhook",
    tags=["Webhook Ingestion"],
)

_SUPPORTED_EVENT: str = "pull_request"


@router.post(
    "/github",
    summary="GitHub Pull Request Webhook Receiver",
    status_code=status.HTTP_202_ACCEPTED,
)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    delivery_id = x_github_delivery or str(uuid.uuid4())
    log_prefix = f"[delivery={delivery_id}]"

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_payload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds maximum allowed size of {settings.max_payload_size_bytes} bytes.",
        )

    raw_body: bytes = await request.body()
    if len(raw_body) > settings.max_payload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload body exceeds maximum allowed size.",
        )

    try:
        verify_github_signature(
            payload_bytes=raw_body,
            signature_header=x_hub_signature_256,
            secret=settings.github_webhook_secret.get_secret_value(),
        )
    except WebhookSignatureError as exc:
        logger.warning("%s Signature verification failed: %s", log_prefix, exc)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    try:
        event_type = extract_event_type(x_github_event)
    except WebhookSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    if event_type == "ping":
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "pong", "delivery_id": delivery_id})

    if event_type != _SUPPORTED_EVENT:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "skipped",
                "reason": f"Event type '{event_type}' is not processed by DeployGuard AI.",
                "delivery_id": delivery_id,
            },
        )

    try:
        payload_dict = json.loads(raw_body)
        payload = GitHubPullRequestPayload.model_validate(payload_dict)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    if not payload.is_actionable:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "skipped",
                "reason": f"Action '{payload.action}' or draft status does not require analysis.",
                "pr_number": payload.number,
                "delivery_id": delivery_id,
            },
        )

    assessment_id = str(uuid.uuid4())
    db_client: MongoDBClient | None = getattr(request.app.state, "db", None)
    agent = getattr(request.app.state, "agent", None)

    workspace_ctx = await _resolve_repo_workspace(db_client, payload.repository.full_name)

    queued_record = AnalysisResult(
        assessment_id=assessment_id,
        pr_number=payload.number,
        repo_full_name=payload.repository.full_name,
        head_sha=payload.pull_request.head_sha,
        risk_level=RiskLevel.UNKNOWN,
        source="GITHUB_WEBHOOK",
        status="QUEUED",
        owner_email=workspace_ctx.get("owner_email"),
        workspace_id=workspace_ctx.get("workspace_id"),
    ).model_dump()
    queued_record.update({
        "pr_title": payload.pull_request.title,
        "pr_author": payload.pull_request.user.login,
        "delivery_id": delivery_id,
    })
    await persist_or_update_assessment(db_client, queued_record)

    background_tasks.add_task(
        _run_analysis_pipeline,
        payload=payload,
        assessment_id=assessment_id,
        delivery_id=delivery_id,
        db_client=db_client,
        agent=agent,
        workspace_ctx=workspace_ctx,
    )

    logger.info(
        "%s PR #%d accepted for analysis. assessment_id=%s",
        log_prefix,
        payload.number,
        assessment_id,
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "job_status": "QUEUED",
            "assessment_id": assessment_id,
            "pr_number": payload.number,
            "repo": payload.repository.full_name,
            "delivery_id": delivery_id,
            "message": "Analysis queued. Results will be posted as a GitHub Check Run and PR summary comment.",
        },
    )


async def _resolve_repo_workspace(
    db_client: MongoDBClient | None,
    repo_full_name: str,
) -> dict[str, Any]:
    """Find workspace/tenant owning ``repo_full_name`` to fetch its encrypted PAT & policy."""
    if db_client is None or getattr(db_client, "db", None) is None:
        return {}
    try:
        ws = await db_client.db["workspaces"].find_one({"connected_repos.full_name": repo_full_name})
        if ws:
            raw_tok = ws.get("github_access_token")
            tok = decrypt_secret(raw_tok) if raw_tok else None
            policy = await db_client.db["enterprise_policy"].find_one({"workspace_id": ws["workspace_id"]})
            return {
                "workspace_id": ws.get("workspace_id"),
                "owner_email": ws.get("owner_email"),
                "github_token": tok,
                "policy": policy or {},
            }
        user = await db_client.db["users"].find_one({"connected_repos.full_name": repo_full_name})
        if user:
            raw_tok = user.get("github_access_token")
            tok = decrypt_secret(raw_tok) if raw_tok else None
            return {
                "workspace_id": user.get("workspace_id"),
                "owner_email": user.get("email"),
                "github_token": tok,
                "policy": {},
            }
    except Exception as exc:
        logger.debug("Workspace lookup skipped for webhook %s: %s", repo_full_name, exc)
    return {}


async def _run_analysis_pipeline(
    payload: GitHubPullRequestPayload,
    assessment_id: str,
    delivery_id: str,
    db_client: MongoDBClient | None = None,
    agent=None,
    workspace_ctx: dict[str, Any] | None = None,
) -> None:
    """Execute full deterministic + optional LLM PR analysis asynchronously."""
    pr = payload.pull_request
    repo = payload.repository.full_name
    ctx = workspace_ctx or {}
    await run_pr_analysis(
        repo_full_name=repo,
        pr_number=pr.number,
        source="GITHUB_WEBHOOK",
        github_token=ctx.get("github_token"),
        db_client=db_client,
        agent=agent,
        owner_email=ctx.get("owner_email"),
        workspace_id=ctx.get("workspace_id"),
        assessment_id=assessment_id,
        policy=ctx.get("policy"),
        post_to_github=True,
        pr_title_hint=pr.title,
        pr_author_hint=pr.user.login,
        head_sha_hint=pr.head_sha,
        base_sha_hint=pr.base.sha,
    )
