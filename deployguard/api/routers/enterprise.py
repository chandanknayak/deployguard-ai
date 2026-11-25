"""
deployguard/api/routers/enterprise.py — Workspace Team RBAC, Governance Policy,
SSRF-Protected Deployment Verification, Audit Logs, Live AST Sandbox & Public PR Analyzer.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import re
import socket
import time
import uuid
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from deployguard.api.routers.auth import (
    ROLE_PERMISSIONS,
    VALID_ROLES,
    get_current_user,
    get_optional_current_user,
    hash_password,
    require_roles,
)
from deployguard.core.ast_analyzer import (
    ASTAnalyzer,
    build_cross_file_impact_graph,
    compare_ast_versions,
)
from deployguard.core.pipeline import persist_or_update_assessment, run_pr_analysis
from deployguard.core.risk_engine import RiskEvaluationInput, compute_risk_assessment
from deployguard.exceptions import ASTAnalysisError
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/enterprise",
    tags=["Enterprise Management"],
)

_GITHUB_PR_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/pull/(?P<pr>\d+)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------


class DeployRequest(BaseModel):
    environment: Literal["staging", "canary", "production"] = "staging"
    strategy: Literal["STANDARD", "CANARY", "BLUE_GREEN", "ROLLBACK_READY"] = "CANARY"
    traffic_percent: int = Field(default=5, ge=1, le=100)
    pr_number: int | None = None
    commit_sha: str | None = None
    operator: str = "DevOps Admin"
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


class AddTeamMemberRequest(BaseModel):
    full_name: str = Field(min_length=2)
    email: str
    password: str = Field(min_length=8)
    role: Literal["developer", "reviewer", "devops_admin"] = "developer"
    github_username: str = ""


class UpdateTeamRoleRequest(BaseModel):
    role: Literal["developer", "reviewer", "devops_admin"]


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


class PublicPRAnalyzeRequest(BaseModel):
    pr_url: str = ""
    repo: str = ""
    pr_number: int | None = None


_DEFAULT_POLICY = PolicySettings()


# ---------------------------------------------------------------------------
# Helpers & SSRF Validation
# ---------------------------------------------------------------------------


def _get_db(request: Request):
    return getattr(request.app.state, "db", None)


async def _load_tenant_policy(db, workspace_id: str | None, owner_email: str | None) -> dict[str, Any]:
    """Load policy scoped to workspace_id (or legacy owner_email)."""
    defaults = _DEFAULT_POLICY.model_dump()
    if not db:
        return defaults
    try:
        query = {"workspace_id": workspace_id} if workspace_id else ({"owner_email": owner_email} if owner_email else None)
        if query:
            doc = await db.db["enterprise_policy"].find_one(query)
            if not doc and owner_email and workspace_id:
                doc = await db.db["enterprise_policy"].find_one({"owner_email": owner_email})
            if doc:
                doc.pop("_id", None)
                doc.pop("owner_email", None)
                doc.pop("workspace_id", None)
                return {**defaults, **doc}
    except Exception as exc:
        logger.warning("Could not load workspace policy: %s", exc)
    return defaults


def _validate_public_http_url(url: str | None, *, strict: bool = False) -> str | None:
    """Validate URL is public http/https and block private/loopback/link-local SSRF targets."""
    if not url or not url.strip():
        return None
    clean = url.strip()
    parsed = urlparse(clean)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        if strict:
            raise HTTPException(status_code=400, detail=f"Invalid HTTP(S) URL: {clean}")
        return None

    host = parsed.hostname.lower()
    if host in ("localhost", "ip6-localhost") or host.endswith(".local") or host.endswith(".internal"):
        raise HTTPException(status_code=400, detail=f"Private/local hostname '{host}' is blocked for security (SSRF protection).")

    try:
        ip_obj = ipaddress.ip_address(host)
        addrs = [ip_obj]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
        except Exception:
            if strict:
                raise HTTPException(status_code=400, detail=f"Could not resolve hostname '{host}'.")
            return None

    for ip in addrs:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise HTTPException(
                status_code=400,
                detail=f"Target IP {ip} is inside a restricted private/metadata range (SSRF protection).",
            )
    return clean


# ---------------------------------------------------------------------------
# Team & Workspace RBAC Endpoints
# ---------------------------------------------------------------------------


@router.get("/team", summary="List workspace members & role permissions")
async def list_team_members(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    ws_id = current_user.get("workspace_id")
    cursor = db.db["users"].find(
        {"workspace_id": ws_id},
        {"_id": 0, "password_hash": 0, "github_access_token": 0},
    )
    members = await cursor.to_list(length=100)
    return JSONResponse(jsonable_encoder({
        "workspace_id": ws_id,
        "workspace_name": current_user.get("workspace_name", ""),
        "members": members,
        "roles": VALID_ROLES,
        "role_permissions": ROLE_PERMISSIONS,
    }))


@router.post("/team/members", summary="Add a team member with RBAC role (DevOps Admin only)")
async def add_team_member(
    body: AddTeamMemberRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    email = body.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid member email address")

    existing = await db.db["users"].find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered in DeployGuard")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ws_id = current_user["workspace_id"]
    company = current_user.get("workspace_name") or current_user.get("company", "Workspace")

    member_doc = {
        "email": email,
        "password_hash": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "company": company,
        "workspace_id": ws_id,
        "role": body.role,
        "github_username": body.github_username.strip() or None,
        "github_access_token": None,
        "github_connected": False,
        "connected_repos": current_user.get("connected_repos", []),
        "plan": "enterprise",
        "created_at": now,
        "updated_at": now,
    }
    await db.db["users"].insert_one(member_doc)
    await db.db["audit_log"].insert_one({
        "action": "TEAM_MEMBER_ADDED",
        "repo": "-",
        "operator": current_user["email"],
        "actor_role": current_user.get("role"),
        "target_email": email,
        "assigned_role": body.role,
        "owner_email": current_user["email"],
        "workspace_id": ws_id,
        "source": "RBAC_TEAM",
        "timestamp": now,
    })

    member_out = {k: v for k, v in member_doc.items() if k not in ("password_hash", "github_access_token", "_id")}
    return JSONResponse(jsonable_encoder({"status": "added", "member": member_out}))


@router.patch("/team/members/{member_email}", summary="Change workspace member role (DevOps Admin only)")
async def update_team_member_role(
    member_email: str,
    body: UpdateTeamRoleRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    target_email = member_email.strip().lower()
    ws_id = current_user["workspace_id"]
    target = await db.db["users"].find_one({"email": target_email, "workspace_id": ws_id})
    if not target:
        raise HTTPException(status_code=404, detail="Team member not found in your workspace")

    if target.get("role") == "devops_admin" and body.role != "devops_admin":
        admin_count = await db.db["users"].count_documents({"workspace_id": ws_id, "role": "devops_admin"})
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the only remaining DevOps Admin in this workspace.")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await db.db["users"].update_one(
        {"email": target_email, "workspace_id": ws_id},
        {"$set": {"role": body.role, "updated_at": now}},
    )
    await db.db["audit_log"].insert_one({
        "action": "ROLE_UPDATED",
        "repo": "-",
        "operator": current_user["email"],
        "actor_role": current_user.get("role"),
        "target_email": target_email,
        "assigned_role": body.role,
        "owner_email": current_user["email"],
        "workspace_id": ws_id,
        "source": "RBAC_TEAM",
        "timestamp": now,
    })
    return JSONResponse({"status": "updated", "email": target_email, "role": body.role})


@router.delete("/team/members/{member_email}", summary="Remove team member (DevOps Admin only)")
async def delete_team_member(
    member_email: str,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    target_email = member_email.strip().lower()
    if target_email == current_user["email"]:
        raise HTTPException(status_code=400, detail="You cannot remove yourself from the workspace")

    res = await db.db["users"].delete_one({"email": target_email, "workspace_id": current_user["workspace_id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Member not found in your workspace")

    await db.db["audit_log"].insert_one({
        "action": "TEAM_MEMBER_REMOVED",
        "repo": "-",
        "operator": current_user["email"],
        "actor_role": current_user.get("role"),
        "target_email": target_email,
        "owner_email": current_user["email"],
        "workspace_id": current_user["workspace_id"],
        "source": "RBAC_TEAM",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    return JSONResponse({"status": "removed", "email": target_email})


# ---------------------------------------------------------------------------
# Policy Settings
# ---------------------------------------------------------------------------


@router.get("/policy", summary="Get workspace governance & release policy")
async def get_policy(
    request: Request,
    current_user: Annotated[dict[str, Any] | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    db = _get_db(request)
    ws_id = current_user.get("workspace_id") if current_user else None
    owner = current_user["email"] if current_user else None
    policy = await _load_tenant_policy(db, ws_id, owner)
    if current_user and policy.get("organization_name") == _DEFAULT_POLICY.organization_name:
        if current_user.get("workspace_name") or current_user.get("company"):
            policy["organization_name"] = current_user.get("workspace_name") or current_user["company"]
    return JSONResponse(jsonable_encoder(policy))


@router.post("/policy", summary="Update workspace governance policy (DevOps Admin only)")
async def update_policy(
    policy: PolicySettings,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
) -> JSONResponse:
    db = _get_db(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if policy.staging_health_url.strip():
        _validate_public_http_url(policy.staging_health_url, strict=True)
    if policy.deploy_hook_url.strip():
        _validate_public_http_url(policy.deploy_hook_url, strict=True)

    ws_id = current_user["workspace_id"]
    doc = policy.model_dump()
    doc["workspace_id"] = ws_id
    doc["owner_email"] = current_user["email"]
    doc["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await db.db["enterprise_policy"].replace_one(
        {"workspace_id": ws_id},
        doc,
        upsert=True,
    )
    await db.db["audit_log"].insert_one({
        "action": "POLICY_UPDATED",
        "repo": "-",
        "operator": current_user["email"],
        "actor_role": current_user.get("role"),
        "owner_email": current_user["email"],
        "workspace_id": ws_id,
        "source": "GOVERNANCE",
        "timestamp": doc["updated_at"],
    })
    return JSONResponse({"status": "updated", "policy": jsonable_encoder(policy.model_dump())})


# ---------------------------------------------------------------------------
# Deployments & Audit Trail
# ---------------------------------------------------------------------------


@router.post("/repos/{owner}/{repo}/deploy", summary="Trigger deployment hook & live health probe (DevOps Admin)")
async def trigger_deployment(
    owner: str,
    repo: str,
    body: DeployRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
) -> JSONResponse:
    """
    Trigger optional Render/CI deploy hook and run a real SSRF-validated HTTP health probe
    when staging_health_url is configured. Otherwise executes an explicit DRY_RUN.
    """
    deployment_id = f"dep-{uuid.uuid4().hex[:8]}"
    repo_full = f"{owner}/{repo}"
    db = _get_db(request)
    ws_id = current_user["workspace_id"]
    policy = await _load_tenant_policy(db, ws_id, current_user["email"])

    raw_health = body.health_check_url or policy.get("staging_health_url")
    raw_hook = body.deploy_hook_url or policy.get("deploy_hook_url")
    health_url = _validate_public_http_url(raw_health, strict=bool(raw_health and raw_health.strip()))
    hook_url = _validate_public_http_url(raw_hook, strict=bool(raw_hook and raw_hook.strip()))

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
    probe_status = "DRY_RUN (No external staging health URL set)"
    deploy_status = "DRY_RUN_HEALTHY"

    if health_url:
        t1 = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                pr_resp = await client.get(health_url, timeout=10, follow_redirects=False)
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
        "actor_role": current_user.get("role"),
        "owner_email": current_user["email"],
        "workspace_id": ws_id,
        "status": deploy_status,
        "verification_mode": "LIVE_HTTP_PROBE" if health_url else "DRY_RUN",
        "health_check": probe_status,
        "latency_ms": probe_latency_ms,
        "source": "LIVE_DEPLOY" if (health_url or hook_triggered) else "DRY_RUN",
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


@router.get("/audit", summary="Get workspace-scoped audit & deployment logs")
async def get_audit_logs(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    limit: int = 35,
) -> JSONResponse:
    db = _get_db(request)
    logs: list[dict[str, Any]] = []
    if db:
        ws_id = current_user.get("workspace_id")
        user_email = current_user["email"]
        user_repos = [r.get("full_name") for r in current_user.get("connected_repos", []) if r.get("full_name")]
        clauses: list[dict[str, Any]] = [{"workspace_id": ws_id}, {"owner_email": user_email}]
        if user_repos:
            clauses.append({"repo": {"$in": user_repos}})
        scope_filter = {"$or": clauses}
        try:
            async for doc in db.db["audit_log"].find(scope_filter).sort("timestamp", -1).limit(limit):
                doc["_id"] = str(doc["_id"])
                logs.append(doc)
            async for doc in db.db["deployments"].find(scope_filter).sort("timestamp", -1).limit(limit):
                doc["_id"] = str(doc["_id"])
                doc.setdefault("action", f"deploy_{doc.get('strategy', 'CANARY').lower()}")
                logs.append(doc)
        except Exception as exc:
            logger.warning("Failed to fetch workspace audit logs: %s", exc)

    logs.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    return JSONResponse(jsonable_encoder({"logs": logs[:limit]}))


# ---------------------------------------------------------------------------
# Public Zero-Fake Evaluators (AST Sandbox + Real Public GitHub PR Analyzer)
# ---------------------------------------------------------------------------


@router.post("/simulate-analyze", summary="Run real Python AST diff + 40/30/20/10 engine on live snippet")
async def simulate_analyze(
    body: SimulateAnalyzeRequest,
    request: Request,
    current_user: Annotated[dict[str, Any] | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    filename = body.filename.strip() or "module.py"
    head_lines = body.head_code.splitlines()
    base_lines = body.base_code.splitlines()

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

    diff_preview: list[dict[str, str]] = []
    for l in base_lines:
        if l.strip() and l not in head_lines:
            diff_preview.append({"type": "del", "text": f"- {l[:110]}"})
    for l in head_lines:
        if l.strip() and l not in base_lines:
            diff_preview.append({"type": "add", "text": f"+ {l[:110]}"})
    diff_preview = diff_preview[:6]

    db = _get_db(request)
    policy = await _load_tenant_policy(
        db,
        current_user.get("workspace_id") if current_user else None,
        current_user["email"] if current_user else None,
    )

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
            workspace_id=current_user.get("workspace_id"),
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


@router.post("/analyze-public-pr", summary="Inspect & risk-score any public GitHub Pull Request URL live")
async def analyze_public_pr(
    body: PublicPRAnalyzeRequest,
    request: Request,
    current_user: Annotated[dict[str, Any] | None, Depends(get_optional_current_user)] = None,
) -> JSONResponse:
    """Parse any public GitHub PR URL (or owner/repo + pr_number) and run real read-only AST analysis."""
    repo_full = body.repo.strip()
    pr_number = body.pr_number

    if body.pr_url.strip():
        m = _GITHUB_PR_URL_RE.search(body.pr_url.strip())
        if not m:
            raise HTTPException(
                status_code=400,
                detail="Enter a valid GitHub PR URL like https://github.com/owner/repo/pull/1",
            )
        repo_full = f"{m.group('owner')}/{m.group('repo')}"
        pr_number = int(m.group("pr"))

    if not repo_full or "/" not in repo_full or not pr_number or pr_number < 1:
        raise HTTPException(status_code=400, detail="Provide a valid public GitHub PR URL or owner/repo + PR number.")

    db = _get_db(request)
    agent = getattr(request.app.state, "agent", None)
    gh_token = current_user.get("github_access_token") if current_user else None

    result = await run_pr_analysis(
        repo_full_name=repo_full,
        pr_number=pr_number,
        source="PUBLIC_SANDBOX",
        github_token=gh_token,
        db_client=db,
        agent=agent,
        owner_email=current_user["email"] if current_user else None,
        workspace_id=current_user.get("workspace_id") if current_user else None,
        post_to_github=False,
    )
    if result.status == "FAILED":
        raise HTTPException(status_code=502, detail=result.error or f"Could not inspect {repo_full}#{pr_number}")

    agent_out = result.agent_assessment or {}
    blast = result.blast_radius_summary or {}
    ctx_pr = (result.context_bundle or {}).get("pr", {})
    svcs = blast.get("affected_services") or [repo_full.split("/")[-1]]

    return JSONResponse(jsonable_encoder({
        "assessment_id": result.assessment_id,
        "repo": repo_full,
        "pr_number": result.pr_number,
        "title": ctx_pr.get("title") or f"{repo_full} PR #{result.pr_number}",
        "author": ctx_pr.get("author") or "github-user",
        "branch": "pr-head",
        "base_branch": "main",
        "additions": ctx_pr.get("additions", 0),
        "deletions": ctx_pr.get("deletions", 0),
        "changed_files": ctx_pr.get("changed_files", len(result.files_analysed)),
        "risk_level": result.risk_level.value,
        "risk_score": result.risk_score or 0,
        "decision": result.risk_level.value,
        "source": "PUBLIC_SANDBOX",
        "is_docs_or_config_only": result.is_docs_or_config_only,
        "signals": result.signal_breakdown,
        "breaking_changes": result.breaking_changes,
        "dependency_edges": result.dependency_edges,
        "diff_preview": result.diff_preview,
        "plain_explanation": agent_out.get("executive_summary", ""),
        "rationale": agent_out.get("rationale", ""),
        "recommended_tests": agent_out.get("recommended_tests", []),
        "blast_radius": {
            "affected_services": svcs,
            "max_sla_tier": blast.get("max_sla_tier", "P1"),
            "total_downstream": len(svcs),
        },
    }))
