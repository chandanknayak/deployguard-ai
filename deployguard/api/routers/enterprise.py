"""
deployguard/api/routers/enterprise.py — Multi-Tenant Governance, Verification & Live AST Sandbox.
"""

from __future__ import annotations

import datetime
import logging
import time
import uuid
from typing import Annotated, Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from deployguard.api.routers.auth import get_current_user, get_optional_current_user
from deployguard.api.routers.repos import _enrich_pr_item, _get_risk_for_pr
from deployguard.core.ast_analyzer import (
    ASTAnalyzer,
    build_cross_file_impact_graph,
    compare_ast_versions,
)
from deployguard.core.diff_parser import DiffParser
from deployguard.core.pipeline import persist_or_update_assessment, run_pr_analysis
from deployguard.core.risk_engine import RiskEvaluationInput, compute_risk_assessment
from deployguard.exceptions import ASTAnalysisError
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/enterprise",
    tags=["Enterprise Management"],
)


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------

class MergeRequest(BaseModel):
    merge_method: Literal["merge", "squash", "rebase"] = "squash"
    commit_title: str | None = None
    commit_message: str | None = None
    override: bool = False
    admin_override: bool = False
    override_reason: str | None = None
    operator: str = "Enterprise Admin"


class DeployRequest(BaseModel):
    environment: Literal["staging", "canary", "production"] = "staging"
    strategy: Literal["STANDARD", "CANARY", "BLUE_GREEN", "ROLLBACK_READY"] = "CANARY"
    traffic_percent: int = Field(default=5, ge=1, le=100)
    pr_number: int | None = None
    commit_sha: str | None = None
    operator: str = "DevOps Lead"
    health_check_url: str | None = None
    deploy_hook_url: str | None = None


class PolicySettings(BaseModel):
    organization_name: str = "DeployGuard Enterprise"
    max_auto_merge_score: int = Field(default=35, ge=0, le=100)
    block_on_p0_sla: bool = True
    block_on_api_changes: bool = False
    require_canary_for_medium_risk: bool = True
    enforce_branch_protection: bool = True
    staging_health_url: str = ""
    deploy_hook_url: str = ""


class SimulateAnalyzeRequest(BaseModel):
    repo: str = "sandbox-org/payments-api"
    pr_title: str = "Interactive AST Risk Simulation"
    filename: str = "services/payments.py"
    base_code: str = ""
    head_code: str = ""
    consumer_filename: str = "routes/checkout.py"
    consumer_code: str = ""
    has_tests: bool = False
    has_p0_impact: bool = False


_DEFAULT_POLICY = PolicySettings()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db(request: Request):
    return getattr(request.app.state, "db", None)


async def _load_tenant_policy(db, owner_email: str | None) -> dict[str, Any]:
    """Load policy scoped to tenant email, cleanly falling back to defaults."""
    defaults = _DEFAULT_POLICY.model_dump()
    if not db or not owner_email:
        return defaults
    try:
        doc = await db.db["enterprise_policy"].find_one({"owner_email": owner_email})
        if doc:
            doc.pop("_id", None)
            doc.pop("owner_email", None)
            return {**defaults, **doc}
    except Exception as exc:
        logger.warning("Could not load tenant policy for %s: %s", owner_email, exc)
    return defaults


def _validate_public_http_url(url: str | None) -> str | None:
    if not url:
        return None
    clean = url.strip()
    if clean.startswith(("http://", "https://")):
        return clean
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/policy", summary="Get tenant governance & release policy")
async def get_policy(
    request: Request,
    current_user: Annotated[dict | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    db = _get_db(request)
    owner = current_user["email"] if current_user else None
    policy = await _load_tenant_policy(db, owner)
    if current_user and policy.get("organization_name") == _DEFAULT_POLICY.organization_name:
        if current_user.get("company"):
            policy["organization_name"] = current_user["company"]
    return JSONResponse(jsonable_encoder(policy))


@router.post("/policy", summary="Update tenant governance policy")
async def update_policy(
    policy: PolicySettings,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    doc = policy.model_dump()
    doc["owner_email"] = current_user["email"]
    doc["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await db.db["enterprise_policy"].replace_one(
        {"owner_email": current_user["email"]},
        doc,
        upsert=True,
    )
    return JSONResponse({"status": "updated", "policy": jsonable_encoder(policy.model_dump())})


@router.get("/repos", summary="List repositories for authenticated tenant")
async def list_repositories(
    current_user: Annotated[dict, Depends(get_current_user)],
) -> JSONResponse:
    repos = current_user.get("connected_repos", [])
    return JSONResponse({"total": len(repos), "repositories": repos})


@router.get("/repos/{owner}/{repo}/pulls", summary="List pull requests with risk assessments")
async def list_repo_pulls(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    repo_full = f"{owner}/{repo}"
    db = _get_db(request)
    gh_token = current_user.get("github_access_token") if current_user else None

    headers = {"Accept": "application/vnd.github.v3+json"}
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    pulls: list[dict] = []
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"https://api.github.com/repos/{repo_full}/pulls?state=open&per_page=30",
                headers=headers,
                timeout=15,
            )
            if r.status_code == 200:
                pulls = r.json()
    except Exception as exc:
        logger.warning("Failed to list PRs for %s: %s", repo_full, exc)

    enriched = []
    for pr in pulls:
        risk = await _get_risk_for_pr(db.db, owner, repo, pr["number"]) if db else None
        enriched.append(_enrich_pr_item(pr, repo, risk))

    return JSONResponse(jsonable_encoder({
        "repo": repo_full,
        "total_open_prs": len(enriched),
        "pulls": enriched,
        "pull_requests": enriched,
    }))


@router.post("/repos/{owner}/{repo}/pulls/{pr_number}/analyze", summary="Run on-demand PR risk scan")
async def analyze_pull_request(
    owner: str,
    repo: str,
    pr_number: int,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> JSONResponse:
    repo_full = f"{owner}/{repo}"
    db = _get_db(request)
    agent = getattr(request.app.state, "agent", None)
    gh_token = current_user.get("github_access_token") or ""
    policy = await _load_tenant_policy(db, current_user["email"])

    result = await run_pr_analysis(
        repo_full_name=repo_full,
        pr_number=pr_number,
        source="MANUAL_SCAN",
        github_token=gh_token,
        db_client=db,
        agent=agent,
        owner_email=current_user["email"],
        policy=policy,
        post_to_github=bool(gh_token),
    )

    if result.status == "FAILED":
        raise HTTPException(status_code=502, detail=result.error or "Failed to scan PR")

    if db:
        try:
            await db.db["audit_log"].insert_one({
                "action": f"SCAN_{result.risk_level.value}",
                "repo": repo_full,
                "pr_number": pr_number,
                "operator": current_user["email"],
                "owner_email": current_user["email"],
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "source": "MANUAL_SCAN",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
        except Exception:
            pass

    return JSONResponse(jsonable_encoder(result.model_dump()))


@router.post("/repos/{owner}/{repo}/pulls/{pr_number}/merge", summary="Policy-gated PR merge")
async def merge_pull_request(
    owner: str,
    repo: str,
    pr_number: int,
    body: MergeRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> JSONResponse:
    gh_token = current_user.get("github_access_token")
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT with repo permissions to merge PRs.")

    repo_full = f"{owner}/{repo}"
    db = _get_db(request)
    policy = await _load_tenant_policy(db, current_user["email"])
    max_score = int(policy.get("max_auto_merge_score", 35))
    is_override = bool(body.override or body.admin_override)

    latest_assessment = None
    if db:
        latest_assessment = await db.assessments.find_one(
            {
                "repo_full_name": repo_full,
                "pr_number": pr_number,
                "source": {"$ne": "SIMULATION"},
            },
            sort=[("created_at", -1)],
        )

    risk_level = latest_assessment.get("risk_level", "PENDING") if latest_assessment else "PENDING"
    risk_score = int(latest_assessment.get("risk_score") or 0) if latest_assessment else 0

    is_blocked = risk_level in ("BLOCK", "PENDING", "UNKNOWN") or risk_score > max_score
    if is_blocked and not is_override:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "MERGE_BLOCKED",
                "reason": (
                    f"Merge blocked by Governance Policy: PR is {risk_level} "
                    f"(score {risk_score}/100 > threshold {max_score}). "
                    "Scan PR first or authorize Admin Override."
                ),
            },
        )

    async with httpx.AsyncClient() as client:
        gh_res = await client.put(
            f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/merge",
            headers={
                "Authorization": f"token {gh_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={
                "merge_method": body.merge_method,
                "commit_title": body.commit_title or f"[DeployGuard] Merge PR #{pr_number}",
                "commit_message": body.commit_message or (
                    f"Merged by {current_user['email']}. Risk: {risk_score}/100 ({risk_level}). "
                    f"{'Override: ' + (body.override_reason or 'Admin authorized') if is_override else 'Gate passed.'}"
                ),
            },
            timeout=20,
        )
        res_data = gh_res.json()

    if gh_res.is_error or not res_data.get("merged"):
        raise HTTPException(
            status_code=gh_res.status_code if gh_res.status_code >= 400 else 400,
            detail=res_data.get("message", "GitHub merge failed"),
        )

    if db:
        await db.db["audit_log"].insert_one({
            "action": "OVERRIDE_MERGE" if is_override else "PR_MERGED",
            "repo": repo_full,
            "pr_number": pr_number,
            "operator": current_user["email"],
            "owner_email": current_user["email"],
            "override": is_override,
            "override_reason": body.override_reason,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "source": "LIVE_MERGE",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

    return JSONResponse({
        "status": "merged",
        "merged": True,
        "sha": res_data.get("sha"),
        "message": res_data.get("message", "Pull Request merged on GitHub."),
        "operator": current_user["email"],
        "audit_logged": True,
    })


@router.post("/repos/{owner}/{repo}/deploy", summary="Trigger deployment hook & live health probe")
async def trigger_deployment(
    owner: str,
    repo: str,
    body: DeployRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> JSONResponse:
    """
    Trigger optional Render/CI deploy hook and run a real HTTP health probe
    when staging_health_url is configured. Otherwise executes an explicit DRY_RUN.
    """
    deployment_id = f"dep-{uuid.uuid4().hex[:8]}"
    repo_full = f"{owner}/{repo}"
    db = _get_db(request)
    policy = await _load_tenant_policy(db, current_user["email"])

    health_url = _validate_public_http_url(body.health_check_url or policy.get("staging_health_url"))
    hook_url = _validate_public_http_url(body.deploy_hook_url or policy.get("deploy_hook_url"))

    steps_completed: list[dict[str, Any]] = []
    hook_triggered = False

    if hook_url:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                hr = await client.post(hook_url, timeout=10)
            steps_completed.append({
                "step": "Deploy Hook Webhook Triggered",
                "status": f"HTTP {hr.status_code}" if hr.status_code < 400 else f"FAILED ({hr.status_code})",
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            })
            hook_triggered = hr.status_code < 400
        except Exception as exc:
            steps_completed.append({
                "step": "Deploy Hook Webhook",
                "status": f"ERROR ({exc})",
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            })

    probe_latency_ms: float | None = None
    probe_status = "DRY_RUN (No staging health URL set)"
    deploy_status = "SIMULATED_HEALTHY"

    if health_url:
        t1 = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                pr_resp = await client.get(health_url, timeout=10, follow_redirects=True)
            probe_latency_ms = round((time.monotonic() - t1) * 1000, 1)
            if 200 <= pr_resp.status_code < 400:
                probe_status = f"LIVE HTTP {pr_resp.status_code}"
                deploy_status = "HEALTHY"
            else:
                probe_status = f"UNHEALTHY HTTP {pr_resp.status_code}"
                deploy_status = "DEGRADED"
        except Exception as exc:
            probe_latency_ms = round((time.monotonic() - t1) * 1000, 1)
            probe_status = f"UNREACHABLE ({type(exc).__name__})"
            deploy_status = "FAILED"

    steps_completed.append({
        "step": f"{body.strategy} Rollout ({body.traffic_percent if body.strategy == 'CANARY' else 100}% traffic)",
        "status": "LIVE" if (health_url or hook_triggered) else "DRY_RUN",
        "duration_ms": probe_latency_ms or 0.0,
    })
    steps_completed.append({
        "step": "Health Probe Verification",
        "status": probe_status,
        "duration_ms": probe_latency_ms or 0.0,
    })

    deploy_record = {
        "deployment_id": deployment_id,
        "repo": repo_full,
        "environment": body.environment,
        "strategy": body.strategy,
        "traffic_percent": body.traffic_percent if body.strategy == "CANARY" else 100,
        "pr_number": body.pr_number,
        "commit_sha": body.commit_sha or "HEAD",
        "operator": current_user["email"],
        "owner_email": current_user["email"],
        "status": deploy_status,
        "verification_mode": "LIVE_HTTP_PROBE" if health_url else "DRY_RUN",
        "health_check": probe_status,
        "latency_ms": probe_latency_ms,
        "source": "LIVE_DEPLOY" if (health_url or hook_triggered) else "SIMULATION",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    if db:
        try:
            await db.db["deployments"].insert_one(dict(deploy_record))
        except Exception:
            pass

    return JSONResponse(jsonable_encoder({
        "status": "deployed" if deploy_status != "FAILED" else "failed",
        "deployment": deploy_record,
        "steps_completed": steps_completed,
    }))


@router.get("/audit", summary="Get tenant-scoped audit & deployment logs")
async def get_audit_logs(
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
    limit: int = 25,
) -> JSONResponse:
    """Return audit & deployment records scoped strictly to the authenticated user."""
    db = _get_db(request)
    logs: list[dict] = []
    if db:
        user_email = current_user["email"]
        user_repos = [r.get("full_name") for r in current_user.get("connected_repos", []) if r.get("full_name")]
        scope_filter: dict[str, Any] = (
            {"$or": [{"owner_email": user_email}, {"repo": {"$in": user_repos}}]}
            if user_repos
            else {"owner_email": user_email}
        )
        try:
            async for doc in db.db["audit_log"].find(scope_filter).sort("timestamp", -1).limit(limit):
                doc["_id"] = str(doc["_id"])
                logs.append(doc)
            async for doc in db.db["deployments"].find(scope_filter).sort("timestamp", -1).limit(limit):
                doc["_id"] = str(doc["_id"])
                doc.setdefault("action", f"deploy_{doc.get('strategy', 'CANARY').lower()}")
                logs.append(doc)
        except Exception as exc:
            logger.warning("Failed to fetch tenant audit logs: %s", exc)

    logs.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    return JSONResponse(jsonable_encoder({"logs": logs[:limit]}))


@router.post("/simulate-analyze", summary="Run real Python AST diff + 40/30/20/10 engine on live snippet")
async def simulate_analyze(
    body: SimulateAnalyzeRequest,
    request: Request,
    current_user: Annotated[dict | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    """
    Execute DeployGuard's actual AST structural comparator, cross-file call graph
    builder, and 40/30/20/10 deterministic risk engine on user-provided code snippets.
    """
    filename = body.filename.strip() or "module.py"
    head_lines = body.head_code.splitlines()
    base_lines = body.base_code.splitlines()

    # Determine modified lines roughly by diffing line by line
    modified_lines: set[int] = set()
    max_len = max(len(head_lines), len(base_lines))
    for i in range(max_len):
        h_line = head_lines[i] if i < len(head_lines) else None
        b_line = base_lines[i] if i < len(base_lines) else None
        if h_line != b_line and h_line is not None:
            modified_lines.add(i + 1)
    if not modified_lines and head_lines:
        modified_lines = set(range(1, min(len(head_lines) + 1, 50)))

    additions = sum(1 for l in head_lines if l not in base_lines)
    deletions = sum(1 for l in base_lines if l not in head_lines)

    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    is_py = ext in {".py", ".python"}

    file_analyses: list[FileAnalysis] = []
    breaking_changes: list[dict[str, Any]] = []
    dep_graph: dict[str, Any] = {"edges": [], "downstream_consumers": [], "affected_routes": []}

    fa = FileAnalysis(
        filename=filename,
        language="python" if is_py else ext.lstrip(".") or "text",
        is_ast_eligible=is_py and bool(body.head_code.strip()),
        total_modified_lines=len(modified_lines),
    )

    if is_py:
        analyzer = ASTAnalyzer()
        if body.head_code.strip():
            try:
                fa.affected_symbols = analyzer.analyze(body.head_code, filename, modified_lines)
            except ASTAnalysisError as exc:
                fa.is_ast_eligible = False
                fa.parse_error = str(exc)
        if body.base_code.strip():
            cmp_res = compare_ast_versions(body.base_code, body.head_code, filename)
            breaking_changes = cmp_res["breaking_changes"]

        sym_names = [s.qualified_name for s in fa.affected_symbols] + [
            bc["symbol"] for bc in breaking_changes if bc.get("symbol")
        ]
        if body.consumer_code.strip() and sym_names:
            sources = {
                filename: body.head_code or body.base_code,
                body.consumer_filename: body.consumer_code,
            }
            dep_graph = build_cross_file_impact_graph(sources, {filename: list(dict.fromkeys(sym_names))})

    changed_files = [filename] if (body.base_code.strip() or body.head_code.strip() or filename) else []
    if body.has_tests and "tests/test_sandbox.py" not in changed_files:
        changed_files.append("tests/test_sandbox.py")

    if fa.total_modified_lines > 0 or fa.affected_symbols or breaking_changes:
        file_analyses.append(fa)

    # Preview diff lines
    diff_preview: list[dict[str, str]] = []
    for l in base_lines:
        if l.strip() and l not in head_lines:
            diff_preview.append({"type": "del", "text": f"- {l[:110]}"})
    for l in head_lines:
        if l.strip() and l not in base_lines:
            diff_preview.append({"type": "add", "text": f"+ {l[:110]}"})
    diff_preview = diff_preview[:6]

    db = _get_db(request)
    policy = await _load_tenant_policy(db, current_user["email"] if current_user else None)

    graph_svcs = [
        {"service_name": c, "sla_tier": "P0" if body.has_p0_impact else "P1", "hops": 1, "team": "downstream"}
        for c in dep_graph["downstream_consumers"]
    ]

    det = compute_risk_assessment(
        RiskEvaluationInput(
            repo_full_name=body.repo,
            pr_title=body.pr_title,
            changed_filenames=changed_files,
            file_analyses=file_analyses,
            additions=additions,
            deletions=deletions,
            breaking_changes=breaking_changes,
            dependency_edges=dep_graph["edges"],
            downstream_consumers=dep_graph["downstream_consumers"],
            graph_services=graph_svcs,
            has_p0_impact=body.has_p0_impact,
            policy=policy,
            diff_preview=diff_preview,
        )
    )

    # Tag as SIMULATION cleanly if DB connected and tenant logged in
    assessment_id = str(uuid.uuid4())
    if db and current_user:
        sim_doc = AnalysisResult(
            assessment_id=assessment_id,
            pr_number=999,
            repo_full_name=body.repo,
            head_sha="simulation",
            risk_level=RiskLevel(det["risk_level"]),
            risk_score=det["risk_score"],
            source="SIMULATION",
            status="COMPLETED",
            owner_email=current_user["email"],
            is_docs_or_config_only=det["is_docs_or_config_only"],
            signal_breakdown=det["signals"],
            breaking_changes=breaking_changes,
            dependency_edges=dep_graph["edges"],
            diff_preview=det["diff_preview"],
            agent_assessment={
                "risk_score": det["risk_score"],
                "risk_level": det["risk_level"],
                "executive_summary": det["plain_explanation"],
                "rationale": det["rationale"],
                "deployment_strategy": det["deployment_strategy"],
                "recommended_tests": det["recommended_tests"],
                "signals": det["signals"],
            },
        ).model_dump()
        await persist_or_update_assessment(db, sim_doc)

    return JSONResponse(jsonable_encoder({
        "assessment_id": assessment_id,
        "source": "SIMULATION",
        "pr_number": int(time.time()) % 900 + 100,
        "title": body.pr_title,
        "author": current_user["email"].split("@")[0] if current_user else "sandbox-user",
        "branch": "sandbox/ast-test",
        "base_branch": "main",
        "additions": additions,
        "deletions": deletions,
        "changed_files": len(changed_files),
        "risk_level": det["risk_level"],
        "risk_score": det["risk_score"],
        "decision": det["decision"],
        "is_docs_or_config_only": det["is_docs_or_config_only"],
        "signals": det["signals"],
        "breaking_changes": breaking_changes,
        "dependency_edges": dep_graph["edges"],
        "diff_preview": det["diff_preview"],
        "plain_explanation": det["plain_explanation"],
        "rationale": det["rationale"],
        "recommended_tests": det["recommended_tests"],
        "blast_radius": {
            "affected_services": det["affected_services"],
            "max_sla_tier": "P0" if body.has_p0_impact else "P1",
            "total_downstream": len(det["affected_services"]),
        },
        "ast_summary": {
            "breaking_changes": len(breaking_changes),
            "affected_symbols": [s.qualified_name for s in fa.affected_symbols],
        },
    }))
