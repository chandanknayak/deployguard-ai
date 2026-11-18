"""
api/routers/webhook.py — GitHub Webhook Ingestion Router.

This module defines the ``/webhook/github`` FastAPI endpoint — the single
entry point through which all GitHub Pull Request events enter DeployGuard AI.

--- Security Model ---

Every request to this endpoint passes through a two-layer security check
*before* any application logic runs:

    1. HMAC-SHA256 Signature Verification (``core/security.py``)
       - Rejects any request not signed with the configured webhook secret.
       - Uses constant-time comparison (``hmac.compare_digest``).
       - Returns HTTP 403 Forbidden on failure.

    2. Event Type Filtering
       - Only ``pull_request`` events are processed.
       - Other event types (``push``, ``issues``, etc.) receive HTTP 200
         with a skip message — no error, as this is expected behaviour from
         GitHub when the webhook is configured for all events.

--- Analysis Pipeline ---

For accepted ``pull_request`` events:

    1. Deserialize payload → ``GitHubPullRequestPayload``.
    2. Skip draft PRs and non-actionable actions (labeled, assigned, etc.).
    3. Fetch the unified diff from GitHub API.
    4. Parse the diff into ``FileDiff`` objects (``DiffParser``).
    5. For each Python file in the diff:
        a. Fetch full source content at the head SHA.
        b. Run ``ASTAnalyzer`` to find affected symbols.
    6. Assemble the ``AnalysisResult`` and return it.

The analysis runs inside a ``BackgroundTask`` so the webhook endpoint
returns HTTP 202 Accepted *immediately* — GitHub requires a response within
10 seconds or it will retry the delivery.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from deployguard.agent.risk_agent import (
    DeploymentStrategy,
    RiskAssessment,
    RiskAssessmentAgent,
    RiskLevel as AgentRiskLevel,
)
from deployguard.config import settings
from deployguard.core.ast_analyzer import ASTAnalyzer
from deployguard.core.comment_renderer import render_pr_comment
from deployguard.core.diff_parser import DiffParser
from deployguard.core.github_client import GitHubClient
from deployguard.core.security import extract_event_type, verify_github_signature
from deployguard.db.client import MongoDBClient
from deployguard.db.db_operations import (
    BlastRadiusResult,
    find_similar_incidents,
    get_blast_radius,
    save_risk_assessment,
)
from deployguard.exceptions import (
    ASTAnalysisError,
    DeployGuardError,
    GitHubAPIError,
    WebhookPayloadError,
    WebhookSignatureError,
)
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel
from deployguard.models.webhook import GitHubPullRequestPayload

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/webhook",
    tags=["Webhook Ingestion"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPORTED_EVENT: str = "pull_request"
_SUPPORTED_EXTENSIONS: set[str] = {".py", ".python"} | {f".{lang}" for lang in settings.supported_ast_languages}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/github",
    summary="GitHub Pull Request Webhook Receiver",
    description=(
        "Receives GitHub ``pull_request`` webhook events, verifies the HMAC-SHA256 "
        "signature, and initiates the DeployGuard AI analysis pipeline asynchronously."
    ),
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Webhook accepted and analysis queued."},
        200: {"description": "Webhook acknowledged but skipped (non-actionable event)."},
        400: {"description": "Malformed payload."},
        403: {"description": "Invalid or missing HMAC-SHA256 signature."},
        413: {"description": "Payload exceeds maximum allowed size."},
        500: {"description": "Internal analysis error."},
    },
)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """
    Primary GitHub webhook receiver endpoint.

    This handler is intentionally thin — it validates, acknowledges, and then
    delegates all heavy lifting to ``_run_analysis_pipeline`` via
    ``BackgroundTasks``.  This ensures GitHub receives an HTTP 202 response
    well within its 10-second timeout window, regardless of how long the
    analysis takes.

    Args:
        request:
            The raw FastAPI ``Request`` object.  The body is read as raw bytes
            *before* any JSON parsing to preserve the exact byte sequence
            needed for HMAC verification.
        background_tasks:
            FastAPI ``BackgroundTasks`` instance for async pipeline execution.
        x_hub_signature_256:
            Value of the ``X-Hub-Signature-256`` header injected by GitHub.
        x_github_event:
            Value of the ``X-GitHub-Event`` header identifying the event type.
        x_github_delivery:
            Value of the ``X-GitHub-Delivery`` header — a unique UUID for this
            delivery (used for idempotency / audit logging).

    Returns:
        ``JSONResponse`` with HTTP 202 for accepted events, or HTTP 200 for
        gracefully skipped events.

    Raises:
        HTTPException(403): On HMAC signature verification failure.
        HTTPException(400): On malformed JSON payload.
        HTTPException(413): If the payload exceeds ``settings.max_payload_size_bytes``.
    """
    delivery_id = x_github_delivery or str(uuid.uuid4())
    log_prefix = f"[delivery={delivery_id}]"

    # -----------------------------------------------------------------------
    # STEP 1: Size guard — reject oversized payloads before reading body
    # -----------------------------------------------------------------------
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_payload_size_bytes:
        logger.warning("%s Payload size %s exceeds limit.", log_prefix, content_length)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds maximum allowed size of {settings.max_payload_size_bytes} bytes.",
        )

    # -----------------------------------------------------------------------
    # STEP 2: Read raw body (must happen before any JSON decoding)
    # -----------------------------------------------------------------------
    raw_body: bytes = await request.body()

    if len(raw_body) > settings.max_payload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload body exceeds maximum allowed size.",
        )

    # -----------------------------------------------------------------------
    # STEP 3: HMAC-SHA256 Signature Verification
    # -----------------------------------------------------------------------
    try:
        verify_github_signature(
            payload_bytes=raw_body,
            signature_header=x_hub_signature_256,
            secret=settings.github_webhook_secret.get_secret_value(),
        )
    except WebhookSignatureError as exc:
        logger.warning("%s Signature verification failed: %s", log_prefix, exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    # -----------------------------------------------------------------------
    # STEP 4: Event type filter
    # -----------------------------------------------------------------------
    try:
        event_type = extract_event_type(x_github_event)
    except WebhookSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    if event_type != _SUPPORTED_EVENT:
        logger.info("%s Skipping unsupported event type: %r.", log_prefix, event_type)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "skipped",
                "reason": f"Event type '{event_type}' is not processed by DeployGuard AI.",
                "delivery_id": delivery_id,
            },
        )

    # -----------------------------------------------------------------------
    # STEP 5: Deserialize payload
    # -----------------------------------------------------------------------
    try:
        payload_dict = json.loads(raw_body)
        payload = GitHubPullRequestPayload.model_validate(payload_dict)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("%s Failed to parse webhook payload: %s", log_prefix, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    # -----------------------------------------------------------------------
    # STEP 6: Actionability check (skip drafts, non-relevant actions)
    # -----------------------------------------------------------------------
    if not payload.is_actionable:
        logger.info(
            "%s Skipping PR #%d — action=%r, draft=%s.",
            log_prefix,
            payload.number,
            payload.action,
            payload.pull_request.draft,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "skipped",
                "reason": f"Action '{payload.action}' or draft status does not require analysis.",
                "pr_number": payload.number,
                "delivery_id": delivery_id,
            },
        )

    # -----------------------------------------------------------------------
    # STEP 7: Queue the analysis pipeline as a background task
    # -----------------------------------------------------------------------
    assessment_id = str(uuid.uuid4())
    logger.info(
        "%s PR #%d accepted for analysis. assessment_id=%s",
        log_prefix,
        payload.number,
        assessment_id,
    )

    background_tasks.add_task(
        _run_analysis_pipeline,
        payload=payload,
        assessment_id=assessment_id,
        delivery_id=delivery_id,
        db_client=getattr(request.app.state, "db", None),
        agent=getattr(request.app.state, "agent", None),
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "assessment_id": assessment_id,
            "pr_number": payload.number,
            "repo": payload.repository.full_name,
            "delivery_id": delivery_id,
            "message": "Analysis pipeline queued. Results will be posted to the PR.",
        },
    )


# ---------------------------------------------------------------------------
# Background Analysis Pipeline
# ---------------------------------------------------------------------------


async def _run_analysis_pipeline(
    payload: GitHubPullRequestPayload,
    assessment_id: str,
    delivery_id: str,
    db_client: MongoDBClient | None = None,
    agent: RiskAssessmentAgent | None = None,
) -> None:
    """
    Execute the full DeployGuard analysis pipeline for a pull request.

    This function runs asynchronously in a background task after the webhook
    endpoint has returned HTTP 202 to GitHub.

    Pipeline stages:
        1. Fetch the unified diff from GitHub.
        2. Parse the diff into ``FileDiff`` objects.
        3. For each Python file: fetch source, run AST analysis.
        4. Assemble the ``AnalysisResult``.
        5. Compute Blast Radius via MongoDB $graphLookup.
        6. Search Historical Incidents via Atlas Vector Search ($vectorSearch).
        7. Execute LLM Risk Assessment Agent (Structured Outputs).
        8. Persist assessment audit record into MongoDB.

    Args:
        payload: Validated ``GitHubPullRequestPayload`` from the webhook.
        assessment_id: Unique ID for this analysis run (UUID4 string).
        delivery_id: GitHub's delivery ID for correlation / idempotency.
        db_client: Optional ``MongoDBClient`` instance from application state.
        agent: Optional ``RiskAssessmentAgent`` instance from application state.
    """
    pr = payload.pull_request
    repo = payload.repository.full_name
    log_prefix = f"[assessment={assessment_id}] [PR #{pr.number}]"

    logger.info("%s Starting analysis pipeline for repo=%s, sha=%s", log_prefix, repo, pr.head_sha[:8])
    pipeline_start = time.monotonic()

    result = AnalysisResult(
        assessment_id=assessment_id,
        pr_number=pr.number,
        repo_full_name=repo,
        head_sha=pr.head_sha,
    )

    try:
        async with GitHubClient(repo_full_name=repo) as github:
            # -----------------------------------------------------------
            # Stage 1: Fetch unified diff
            # -----------------------------------------------------------
            logger.info("%s [Stage 1] Fetching PR diff...", log_prefix)
            raw_diff = await github.get_pull_request_diff(pr.number)

            # -----------------------------------------------------------
            # Stage 2: Parse diff into FileDiff objects
            # -----------------------------------------------------------
            logger.info("%s [Stage 2] Parsing diff...", log_prefix)
            diff_parser = DiffParser()
            file_diffs = diff_parser.parse(raw_diff)

            logger.info(
                "%s Diff parsed: %d files changed.",
                log_prefix,
                len(file_diffs),
            )

            # -----------------------------------------------------------
            # Stage 3: AST Analysis per Python file
            # -----------------------------------------------------------
            logger.info("%s [Stage 3] Running AST analysis...", log_prefix)
            ast_start = time.monotonic()
            ast_analyzer = ASTAnalyzer()
            file_analyses: list[FileAnalysis] = []

            for fd in file_diffs:
                file_analysis = await _analyze_single_file(
                    file_diff=fd,
                    github=github,
                    head_sha=pr.head_sha,
                    ast_analyzer=ast_analyzer,
                    log_prefix=log_prefix,
                )
                file_analyses.append(file_analysis)

            ast_duration_ms = (time.monotonic() - ast_start) * 1000

            # -----------------------------------------------------------
            # Stage 4: Assemble result
            # -----------------------------------------------------------
            total_symbols = sum(len(fa.affected_symbols) for fa in file_analyses)
            has_api_changes = any(fa.has_api_changes for fa in file_analyses)

            result.files_analysed = file_analyses
            result.total_affected_symbols = total_symbols
            result.has_api_surface_changes = has_api_changes
            result.analysis_duration_ms = ast_duration_ms
            result.risk_level = RiskLevel.UNKNOWN  # Will be set by the LLM agent stage

            # Build context bundle for the downstream LLM agent
            result.context_bundle = _build_context_bundle(result, payload)

            total_duration_ms = (time.monotonic() - pipeline_start) * 1000
            logger.info(
                "%s Pipeline complete. files=%d, affected_symbols=%d, "
                "api_changes=%s, duration=%.1fms",
                log_prefix,
                len(file_analyses),
                total_symbols,
                has_api_changes,
                total_duration_ms,
            )

            # -----------------------------------------------------------
            # Stage 5: Blast Radius Computation via MongoDB $graphLookup
            # -----------------------------------------------------------
            service_name = repo.split("/")[-1].lower()
            blast_radius = BlastRadiusResult(origin_service=service_name)

            if db_client is not None:
                try:
                    logger.info("%s [Stage 5] Computing blast radius for service=%s...", log_prefix, service_name)
                    blast_radius = await get_blast_radius(db_client, service_name=service_name)
                    result.blast_radius_summary = {
                        "origin_service": blast_radius.origin_service,
                        "total_affected": blast_radius.total_affected,
                        "has_p0_impact": blast_radius.has_p0_impact,
                        "has_p1_impact": blast_radius.has_p1_impact,
                        "critical_services": [
                            {"service": s.service_name, "sla_tier": s.sla_tier, "hops": s.hops, "team": s.owner_team}
                            for s in blast_radius.critical_services
                        ],
                    }
                except Exception as exc:
                    logger.warning("%s Blast radius query failed: %s", log_prefix, exc)
            else:
                logger.info("%s [Stage 5] MongoDB not connected; skipping graph blast radius.", log_prefix)

            # -----------------------------------------------------------
            # Stage 6: Semantic Incident Search via Atlas $vectorSearch
            # -----------------------------------------------------------
            similar_incidents = []
            if db_client is not None and agent is not None:
                try:
                    logger.info("%s [Stage 6] Querying historical incidents via vector search...", log_prefix)
                    symbols_desc = ", ".join(
                        s.qualified_name for fa in file_analyses for s in fa.affected_symbols
                    )
                    changeset_text = f"PR: {pr.title}. Service: {service_name}. Affected symbols: {symbols_desc}"
                    query_embedding = await agent.get_embedding(changeset_text)
                    similar_incidents = await find_similar_incidents(
                        db_client=db_client,
                        query_embedding=query_embedding,
                        affected_service=service_name,
                    )
                except Exception as exc:
                    logger.warning("%s Historical incident vector search failed: %s", log_prefix, exc)
            else:
                logger.info("%s [Stage 6] Vector search skipped (db or agent not configured).", log_prefix)

            # -----------------------------------------------------------
            # Stage 7: LLM Risk Assessment Agent (Structured Output)
            # -----------------------------------------------------------
            if agent is not None:
                try:
                    logger.info("%s [Stage 7] Invoking RiskAssessmentAgent...", log_prefix)
                    symbols_context = result.context_bundle.get("affected_symbols", [])
                    assessment: RiskAssessment = await agent.assess(
                        pr_title=pr.title,
                        pr_author=pr.user.login,
                        changed_symbols=symbols_context,
                        blast_radius=blast_radius,
                        similar_incidents=similar_incidents,
                    )
                    result.agent_assessment = assessment.model_dump()
                    result.risk_score = assessment.risk_score

                    if assessment.risk_level in (AgentRiskLevel.HIGH, AgentRiskLevel.CRITICAL):
                        result.risk_level = RiskLevel.BLOCK
                    elif assessment.risk_level == AgentRiskLevel.MEDIUM:
                        result.risk_level = RiskLevel.WARN
                    else:
                        result.risk_level = RiskLevel.PASS

                    logger.info(
                        "%s Agent evaluation: score=%d, decision=%s",
                        log_prefix,
                        result.risk_score,
                        result.risk_level,
                    )
                except Exception as exc:
                    logger.warning("%s Risk assessment agent failed: %s; applying deterministic AST fallback", log_prefix, exc)
                    base_score = 15
                    if blast_radius.has_p0_impact:
                        base_score += 45
                    elif blast_radius.has_p1_impact:
                        base_score += 25
                    if has_api_changes:
                        base_score += 20
                    if total_symbols > 5:
                        base_score += 15
                    elif total_symbols > 0:
                        base_score += 5

                    computed_score = min(95, base_score)
                    if computed_score >= 70:
                        fb_level = "HIGH"
                        result.risk_level = RiskLevel.BLOCK
                        strat = "ROLLBACK_READY"
                    elif computed_score >= 35:
                        fb_level = "MEDIUM"
                        result.risk_level = RiskLevel.WARN
                        strat = "CANARY"
                    else:
                        fb_level = "LOW"
                        result.risk_level = RiskLevel.PASS
                        strat = "STANDARD"

                    result.risk_score = computed_score
                    result.agent_assessment = {
                        "risk_score": computed_score,
                        "risk_level": fb_level,
                        "confidence": 0.88,
                        "rationale": (
                            f"Deterministic AST & blast radius engine evaluation: "
                            f"{total_symbols} symbol(s) modified across {len(file_analyses)} file(s). "
                            f"{'P0 critical downstream impact detected; ' if blast_radius.has_p0_impact else ''}"
                            f"{'API surface modification detected; ' if has_api_changes else ''}"
                            f"Automated CI/CD gate calculated risk score of {computed_score}/100."
                        ),
                        "affected_services": [
                            {"service_name": s.service_name, "reasoning": f"{s.sla_tier} SLA tier dependency ({s.hops} hops)"}
                            for s in blast_radius.critical_services
                        ],
                        "recommended_tests": [
                            "Integration test for modified symbol entry points",
                            "Contract validation test against downstream consumers",
                            "Canary deployment with 5% traffic monitoring" if computed_score >= 35 else "Standard regression test suite",
                        ],
                        "deployment_strategy": strat,
                        "escalation_required": blast_radius.has_p0_impact or computed_score >= 70,
                        "similar_incident_ids": [inc.incident_id for inc in similar_incidents[:3]],
                    }
                    logger.info("%s Fallback evaluation completed: score=%d, decision=%s", log_prefix, computed_score, result.risk_level)
            else:
                logger.info("%s [Stage 7] Agent not configured; setting risk_level to UNKNOWN.", log_prefix)

            # -----------------------------------------------------------
            # Stage 8: Persist to MongoDB Audit Log
            # -----------------------------------------------------------
            if db_client is not None:
                try:
                    logger.info("%s [Stage 8] Persisting assessment to MongoDB...", log_prefix)
                    await save_risk_assessment(db_client, result.model_dump())
                except Exception as exc:
                    logger.warning("%s Failed to persist assessment to MongoDB: %s", log_prefix, exc)

            # -----------------------------------------------------------
            # Stage 9: Post Status Check & PR Review Comment to GitHub
            # -----------------------------------------------------------
            try:
                state_map = {
                    RiskLevel.PASS: "success",
                    RiskLevel.WARN: "success",
                    RiskLevel.BLOCK: "failure",
                    RiskLevel.UNKNOWN: "error",
                }
                status_state = state_map.get(result.risk_level, "error")
                desc = f"Risk Score: {result.risk_score or 0}/100 — Decision: {result.risk_level.value}"

                logger.info("%s [Stage 9] Posting commit status and PR comment...", log_prefix)
                await github.create_commit_status(
                    sha=pr.head_sha,
                    state=status_state,
                    description=desc,
                )
                comment_markdown = render_pr_comment(result)
                await github.post_pr_comment(pr_number=pr.number, body=comment_markdown)
            except Exception as exc:
                logger.warning("%s Failed to write back to GitHub API: %s", log_prefix, exc)

    except GitHubAPIError as exc:
        logger.error("%s GitHub API error: %s (HTTP %s)", log_prefix, exc, exc.status_code)
        result.error = f"GitHub API error: {exc}"
        result.risk_level = RiskLevel.UNKNOWN

    except DeployGuardError as exc:
        logger.error("%s Pipeline error: %s", log_prefix, exc)
        result.error = str(exc)
        result.risk_level = RiskLevel.UNKNOWN

    except Exception as exc:
        logger.exception("%s Unexpected error in analysis pipeline: %s", log_prefix, exc)
        result.error = f"Unexpected error: {exc!r}"
        result.risk_level = RiskLevel.UNKNOWN


async def _analyze_single_file(
    file_diff,
    github: GitHubClient,
    head_sha: str,
    ast_analyzer: ASTAnalyzer,
    log_prefix: str,
) -> FileAnalysis:
    """
    Fetch and AST-analyze a single changed file.

    For non-Python files (or files in unsupported languages), a ``FileAnalysis``
    is still created but with ``is_ast_eligible=False``.  This ensures the
    diff surface area is fully represented in the result even when AST analysis
    is not applicable.

    Args:
        file_diff: ``FileDiff`` object from the diff parser.
        github: Authenticated ``GitHubClient`` for fetching file content.
        head_sha: Commit SHA of the PR head (to fetch correct file version).
        ast_analyzer: Reusable ``ASTAnalyzer`` instance.
        log_prefix: Log line prefix for tracing.

    Returns:
        A populated ``FileAnalysis`` model.
    """
    filename = file_diff.filename
    extension = f".{filename.rsplit('.', 1)[-1]}" if "." in filename else ""
    is_python = extension in _SUPPORTED_EXTENSIONS and not file_diff.is_deleted_file

    file_analysis = FileAnalysis(
        filename=filename,
        language="python" if is_python else extension.lstrip(".") or "unknown",
        is_ast_eligible=is_python,
        total_modified_lines=file_diff.total_modified_lines,
        modified_hunks=file_diff.hunks,
    )

    if not is_python:
        logger.debug("%s Skipping AST for non-Python file: %s", log_prefix, filename)
        return file_analysis

    # Fetch source content at the head SHA for full-file AST parsing
    try:
        source_code = await github.get_file_content(filename, head_sha)
    except GitHubAPIError as exc:
        logger.warning(
            "%s Could not fetch source for %s (HTTP %s): %s",
            log_prefix,
            filename,
            exc.status_code,
            exc,
        )
        file_analysis.is_ast_eligible = False
        file_analysis.parse_error = f"Could not fetch source: HTTP {exc.status_code}"
        return file_analysis

    # Run AST analysis
    try:
        affected_symbols = ast_analyzer.analyze(
            source_code=source_code,
            filename=filename,
            modified_lines=file_diff.all_modified_lines,
        )
        file_analysis.affected_symbols = affected_symbols
        logger.info(
            "%s %s → %d affected symbols from %d modified lines.",
            log_prefix,
            filename,
            len(affected_symbols),
            len(file_diff.all_modified_lines),
        )
    except ASTAnalysisError as exc:
        logger.warning("%s AST parse error in %s: %s", log_prefix, filename, exc)
        file_analysis.is_ast_eligible = False
        file_analysis.parse_error = str(exc)

    return file_analysis


def _build_context_bundle(result: AnalysisResult, payload: GitHubPullRequestPayload) -> dict:
    """
    Build the structured context bundle passed to the downstream LLM agent stage.

    The bundle contains a curated, serialized summary of the AST analysis
    results in a format optimised for LLM consumption (flat lists, human-
    readable symbol descriptions, explicit API surface change flags).

    Args:
        result: The assembled ``AnalysisResult`` from the AST stage.
        payload: Original webhook payload with PR metadata.

    Returns:
        A JSON-serializable dictionary.
    """
    pr = payload.pull_request

    affected_symbols_summary = []
    for fa in result.files_analysed:
        for sym in fa.affected_symbols:
            entry = {
                "file": fa.filename,
                "symbol": sym.qualified_name,
                "kind": sym.kind,
                "lines": f"{sym.start_line}-{sym.end_line}",
                "modified_line_count": len(sym.modified_lines_overlap),
            }
            if sym.route_path:
                entry["route"] = f"{','.join(sym.http_methods)} {sym.route_path}"
            affected_symbols_summary.append(entry)

    return {
        "pr": {
            "number": pr.number,
            "title": pr.title,
            "author": pr.user.login,
            "head_sha": pr.head_sha,
            "additions": pr.additions,
            "deletions": pr.deletions,
            "changed_files": pr.changed_files,
        },
        "analysis_summary": {
            "total_files": len(result.files_analysed),
            "ast_eligible_files": sum(1 for fa in result.files_analysed if fa.is_ast_eligible),
            "total_affected_symbols": result.total_affected_symbols,
            "has_api_surface_changes": result.has_api_surface_changes,
            "analysis_duration_ms": round(result.analysis_duration_ms, 2),
        },
        "affected_symbols": affected_symbols_summary,
    }

