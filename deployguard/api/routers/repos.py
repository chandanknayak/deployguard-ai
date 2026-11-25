"""
api/routers/repos.py — Workspace Repositories, GitHub Collaborators, Real PR Workflow,
RBAC-Gated Code Reviews & Merges.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from deployguard.api.routers.auth import (
    effective_github_token,
    get_current_user,
    require_roles,
)
from deployguard.config import settings
from deployguard.core.github_client import GitHubClient
from deployguard.core.pipeline import run_pr_analysis
from deployguard.db.db_operations import seed_repo_graph_nodes
from deployguard.exceptions import GitHubAPIError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/repos", tags=["Repositories & PR Workflow"])


# ---------------------------------------------------------------------------
# Starter Microservice Templates for Real GitHub Demo Repo & Real Demo PRs
# ---------------------------------------------------------------------------

_STARTER_PAYMENTS_PY = '''\
from fastapi import APIRouter

router = APIRouter()


@router.post("/v1/payments/charge")
def process_charge_v1(order_id: str, amount: int) -> dict:
    """Process a card charge for an order."""
    return {"status": "charged", "order_id": order_id, "amount": amount}


def compute_fee(amount: int) -> int:
    return max(1, int(amount * 0.029) + 30)
'''

_STARTER_AUTH_PY = '''\
def refresh_token(user_id: str, ttl: int = 3600) -> dict:
    """Refresh OAuth session token with fixed TTL."""
    return {"user_id": user_id, "ttl": ttl}
'''

_STARTER_CHECKOUT_PY = '''\
from fastapi import APIRouter
from services.payments import process_charge_v1

router = APIRouter()


@router.post("/checkout/pay")
def checkout_pay(order_id: str, amount: int) -> dict:
    """Checkout endpoint calling payments service."""
    return process_charge_v1(order_id=order_id, amount=amount)
'''

_STARTER_TEST_PY = '''\
from services.payments import compute_fee


def test_compute_fee():
    assert compute_fee(1000) == 59
'''

_STARTER_README_MD = '''\
# DeployGuard Demo Microservice (Payments & Checkout)

Sandbox repository managed by **DeployGuard AI** for testing real AST diffs,
cross-file call graphs, RBAC code reviews, gated merges, and canary deployments.
'''


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ConnectRepoRequest(BaseModel):
    owner: str
    repo: str
    sla_tier: str = Field(default="P0", pattern="^(P0|P1|P2|P3)$")


class CreateDemoRepoRequest(BaseModel):
    repo_name: str = Field(default="deployguard-demo-payments", min_length=2, max_length=64)
    description: str = "DeployGuard AI Sandbox Microservice (Payments & Checkout)"
    private: bool = False
    sla_tier: str = Field(default="P0", pattern="^(P0|P1|P2|P3)$")


class CollaboratorRequest(BaseModel):
    github_username: str = Field(min_length=1, max_length=64)
    role: Literal["developer", "reviewer", "devops_admin", "read_only"] = "developer"


class CreateDemoPRRequest(BaseModel):
    scenario: Literal["safe", "warn", "block", "custom"] = "block"
    title: str | None = None
    custom_filename: str | None = None
    custom_code: str | None = None


class PRReviewRequest(BaseModel):
    event: Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"] = "APPROVE"
    body: str = Field(min_length=2, max_length=2000)


class MergeRequest(BaseModel):
    merge_method: Literal["merge", "squash", "rebase"] = "squash"
    commit_title: str | None = None
    commit_message: str | None = None
    admin_override: bool = False
    override: bool = False
    override_reason: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db(request: Request):
    db_client = getattr(request.app.state, "db", None)
    if db_client is None or getattr(db_client, "db", None) is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return db_client.db


def _gh_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


async def _gh_get(url: str, token: str | None) -> dict | list:
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=_gh_headers(token), timeout=15)
        r.raise_for_status()
        return r.json()


async def _gh_put(url: str, token: str, body: dict) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.put(url, json=body, headers=_gh_headers(token), timeout=15)


async def _record_audit(
    db,
    *,
    action: str,
    repo: str,
    current_user: dict[str, Any],
    pr_number: int | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    doc: dict[str, Any] = {
        "action": action,
        "repo": repo,
        "pr_number": pr_number,
        "operator": current_user["email"],
        "actor_role": current_user.get("role", "developer"),
        "owner_email": current_user["email"],
        "workspace_id": current_user.get("workspace_id"),
        "source": "LIVE_WORKFLOW",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        doc.update(extra)
    try:
        await db["audit_log"].insert_one(doc)
    except Exception:
        pass


async def _get_risk_for_pr(db, owner: str, repo: str, pr_number: int) -> Optional[dict]:
    """Fetch latest completed live/manual assessment from MongoDB for this PR."""
    doc = await db["risk_assessments"].find_one(
        {
            "repo_full_name": f"{owner}/{repo}",
            "pr_number": pr_number,
            "source": {"$ne": "SIMULATION"},
        },
        sort=[("created_at", -1)],
    )
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc


async def _get_reviews_for_pr(db, repo_full: str, pr_number: int) -> list[dict[str, Any]]:
    docs = (
        await db["pr_reviews"]
        .find({"repo_full_name": repo_full, "pr_number": pr_number}, {"_id": 0})
        .sort("timestamp", -1)
        .to_list(length=20)
    )
    return docs


def _enrich_pr_item(
    pr: dict,
    repo_name: str,
    risk: dict | None,
    reviews: list[dict[str, Any]] | None = None,
) -> dict:
    """Map raw GitHub PR + MongoDB assessment + Reviews to normalized UI payload."""
    agent = (risk or {}).get("agent_assessment") or {}
    blast = (risk or {}).get("blast_radius") or (risk or {}).get("blast_radius_summary") or {}
    risk_level = (risk or {}).get("risk_level") or "PENDING"
    if risk_level == "UNKNOWN":
        risk_level = "PENDING"
    score = (risk or {}).get("risk_score")
    if score is None:
        score = agent.get("risk_score", 0)

    svcs = blast.get("affected_services") or [
        s.get("service") for s in blast.get("critical_services", []) if s.get("service")
    ] or [repo_name]

    review_list = reviews or []
    latest_review = review_list[0] if review_list else None

    return {
        "pr_number": pr["number"],
        "title": pr["title"],
        "author": (pr.get("user") or {}).get("login", "dev"),
        "author_avatar": (pr.get("user") or {}).get("avatar_url"),
        "branch": (pr.get("head") or {}).get("ref", "feature"),
        "base_branch": (pr.get("base") or {}).get("ref", "main"),
        "head_sha": (pr.get("head") or {}).get("sha", ""),
        "state": pr.get("state", "open"),
        "created_at": pr.get("created_at"),
        "updated_at": pr.get("updated_at"),
        "url": pr.get("html_url"),
        "draft": pr.get("draft", False),
        "mergeable": pr.get("mergeable"),
        "additions": pr.get("additions", 0),
        "deletions": pr.get("deletions", 0),
        "changed_files": pr.get("changed_files", 0),
        "labels": [l["name"] for l in pr.get("labels", [])],
        "risk_level": risk_level,
        "risk_score": score,
        "decision": risk.get("decision", risk_level) if risk else "PENDING",
        "source": risk.get("source") if risk else None,
        "status": risk.get("status", "COMPLETED") if risk else "PENDING",
        "is_docs_or_config_only": bool(risk.get("is_docs_or_config_only")) if risk else False,
        "signals": risk.get("signal_breakdown") or agent.get("signals") or {},
        "breaking_changes": risk.get("breaking_changes", []) if risk else [],
        "dependency_edges": risk.get("dependency_edges", []) if risk else [],
        "diff_preview": risk.get("diff_preview", []) if risk else [],
        "plain_explanation": agent.get("executive_summary") or "",
        "rationale": agent.get("rationale") or agent.get("detailed_rationale") or "",
        "recommended_tests": agent.get("recommended_tests", []),
        "blast_radius": {
            "affected_services": svcs,
            "max_sla_tier": blast.get("max_sla_tier") or ("P0" if blast.get("has_p0_impact") else "P1"),
            "total_downstream": len(svcs),
        },
        "reviews": review_list,
        "review_status": latest_review.get("decision") if latest_review else "UNREVIEWED",
        "analyzed_at": risk.get("created_at") if risk else None,
        "assessment_id": risk.get("assessment_id") if risk else None,
    }


async def _upsert_workspace_repo(db, current_user: dict[str, Any], repo_entry: dict[str, Any]) -> None:
    full_name = repo_entry["full_name"]
    ws_id = current_user.get("workspace_id")
    if ws_id:
        await db["workspaces"].update_one(
            {"workspace_id": ws_id},
            {"$pull": {"connected_repos": {"full_name": full_name}}},
        )
        await db["workspaces"].update_one(
            {"workspace_id": ws_id},
            {"$push": {"connected_repos": repo_entry}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}},
        )
    await db["users"].update_one(
        {"email": current_user["email"]},
        {"$pull": {"connected_repos": {"full_name": full_name}}},
    )
    await db["users"].update_one(
        {"email": current_user["email"]},
        {"$push": {"connected_repos": repo_entry}},
    )


# ---------------------------------------------------------------------------
# Repository & Sandbox Setup Endpoints
# ---------------------------------------------------------------------------


@router.get("", summary="List connected repos for workspace")
async def list_repos(current_user: Annotated[dict[str, Any], Depends(get_current_user)]):
    return {"repos": current_user.get("connected_repos", [])}


@router.get("/available", summary="List user's GitHub repositories available to connect")
async def list_available_github_repos(current_user: Annotated[dict[str, Any], Depends(get_current_user)]):
    gh_token = effective_github_token(current_user)
    if not gh_token:
        return {"repos": [], "github_connected": False}
    try:
        items = await _gh_get("https://api.github.com/user/repos?sort=updated&per_page=30", gh_token)
        return {
            "github_connected": True,
            "repos": [
                {
                    "full_name": rp["full_name"],
                    "owner": rp["owner"]["login"],
                    "repo": rp["name"],
                    "private": rp.get("private", False),
                    "description": rp.get("description") or "",
                    "language": rp.get("language") or "",
                }
                for rp in items
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")


@router.post("/connect", summary="Connect a GitHub repository (DevOps Admin only)")
async def connect_repo(
    body: ConnectRepoRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
):
    gh_token = effective_github_token(current_user)
    owner = body.owner.strip()
    repo = body.repo.strip()
    full_name = f"{owner}/{repo}"

    try:
        repo_data = await _gh_get(f"https://api.github.com/repos/{full_name}", gh_token)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403, 404) and not gh_token:
            raise HTTPException(
                status_code=400,
                detail="Repo not accessible publicly. Link your GitHub PAT to add private repos.",
            )
        raise HTTPException(status_code=404, detail=f"Repo {full_name} not found or inaccessible")

    repo_entry = {
        "owner": owner,
        "repo": repo,
        "full_name": full_name,
        "sla_tier": body.sla_tier,
        "description": repo_data.get("description") or "",
        "private": repo_data.get("private", False),
        "default_branch": repo_data.get("default_branch", "main"),
        "language": repo_data.get("language") or "",
        "stars": repo_data.get("stargazers_count", 0),
    }

    db_client = getattr(request.app.state, "db", None)
    db = _db(request)
    await _upsert_workspace_repo(db, current_user, repo_entry)
    await seed_repo_graph_nodes(db_client, full_name)
    await _record_audit(db, action="REPO_CONNECTED", repo=full_name, current_user=current_user)
    return {"message": f"Repo {full_name} connected!", "repo": repo_entry}


@router.post("/create-demo-repo", summary="Create & seed a real GitHub sandbox microservice repo (DevOps Admin)")
async def create_demo_repo(
    body: CreateDemoRepoRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
):
    """
    Create a real repository under the user's GitHub account, commit starter Python
    microservice files (payments, auth, checkout, unit tests), seed MongoDB code_graph,
    and register webhook if PUBLIC_URL is HTTPS.
    """
    gh_token = effective_github_token(current_user)
    if not gh_token:
        raise HTTPException(
            status_code=400,
            detail="Link a GitHub PAT (with 'repo' scope) first to create a real demo repository.",
        )

    clean_name = body.repo_name.strip().replace(" ", "-")
    try:
        user_info = await _gh_get("https://api.github.com/user", gh_token)
        gh_login = user_info.get("login")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not resolve GitHub identity: {exc}")

    full_name = f"{gh_login}/{clean_name}"
    created_fresh = False

    async with GitHubClient(repo_full_name=full_name, token=gh_token) as gh:
        try:
            repo_data = await gh.create_repository(
                name=clean_name,
                description=body.description,
                private=body.private,
                auto_init=True,
            )
            created_fresh = True
        except GitHubAPIError as exc:
            if exc.status_code == 422:
                # Repo already exists on user's GitHub — reuse cleanly
                repo_data = await _gh_get(f"https://api.github.com/repos/{full_name}", gh_token)
            else:
                raise HTTPException(status_code=502, detail=f"GitHub create repo failed: {exc}")

        default_branch = repo_data.get("default_branch", "main")
        # GitHub takes a brief moment to initialize the first commit after auto_init=True
        for _ in range(4):
            try:
                await gh.get_branch_sha(default_branch)
                break
            except GitHubAPIError:
                await asyncio.sleep(0.6)

        starter_files = [
            ("README.md", _STARTER_README_MD, "chore: initialize DeployGuard demo README"),
            ("services/__init__.py", "", "chore: add services package"),
            ("services/payments.py", _STARTER_PAYMENTS_PY, "feat: add payments v1 charge endpoint"),
            ("services/auth_tokens.py", _STARTER_AUTH_PY, "feat: add OAuth refresh helper"),
            ("routes/__init__.py", "", "chore: add routes package"),
            ("routes/checkout.py", _STARTER_CHECKOUT_PY, "feat: wire checkout endpoint to payments v1"),
            ("tests/test_payments.py", _STARTER_TEST_PY, "test: add unit test for compute_fee"),
        ]
        seeded_files: list[str] = []
        for path, content, msg in starter_files:
            existing_sha = await gh.get_file_sha(path, default_branch)
            if existing_sha is None:
                await gh.create_or_update_file(
                    file_path=path,
                    content=content,
                    message=msg,
                    branch=default_branch,
                )
                seeded_files.append(path)

        webhook_status = "manual"
        pub = settings.public_url.rstrip("/")
        if pub.startswith("https://") and "your-deployguard" not in pub and "localhost" not in pub:
            try:
                await gh.ensure_webhook(
                    webhook_url=f"{pub}/webhook/github",
                    secret=settings.github_webhook_secret.get_secret_value(),
                )
                webhook_status = "configured"
            except Exception as exc:
                logger.debug("Optional webhook setup skipped for %s: %s", full_name, exc)

    repo_entry = {
        "owner": gh_login,
        "repo": clean_name,
        "full_name": full_name,
        "sla_tier": body.sla_tier,
        "description": repo_data.get("description") or body.description,
        "private": repo_data.get("private", body.private),
        "default_branch": default_branch,
        "language": "Python",
        "stars": repo_data.get("stargazers_count", 0),
    }

    db_client = getattr(request.app.state, "db", None)
    db = _db(request)
    await _upsert_workspace_repo(db, current_user, repo_entry)
    await seed_repo_graph_nodes(db_client, full_name)
    await _record_audit(
        db,
        action="DEMO_REPO_CREATED" if created_fresh else "DEMO_REPO_CONNECTED",
        repo=full_name,
        current_user=current_user,
        extra={"seeded_files": seeded_files, "webhook": webhook_status},
    )
    return {
        "created_fresh": created_fresh,
        "repo": repo_entry,
        "seeded_files": seeded_files,
        "webhook_status": webhook_status,
        "html_url": f"https://github.com/{full_name}",
    }


@router.delete("/{owner}/{repo}", summary="Disconnect a repository (DevOps Admin only)")
async def disconnect_repo(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
):
    db = _db(request)
    full_name = f"{owner}/{repo}"
    if current_user.get("workspace_id"):
        await db["workspaces"].update_one(
            {"workspace_id": current_user["workspace_id"]},
            {"$pull": {"connected_repos": {"full_name": full_name}}},
        )
    await db["users"].update_one(
        {"email": current_user["email"]},
        {"$pull": {"connected_repos": {"full_name": full_name}}},
    )
    await _record_audit(db, action="REPO_DISCONNECTED", repo=full_name, current_user=current_user)
    return {"message": f"Repo {full_name} disconnected"}


# ---------------------------------------------------------------------------
# GitHub Collaborator Endpoints
# ---------------------------------------------------------------------------


@router.get("/{owner}/{repo}/collaborators", summary="List GitHub repository collaborators")
async def list_repo_collaborators(
    owner: str,
    repo: str,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
):
    gh_token = effective_github_token(current_user)
    if not gh_token:
        return {"collaborators": [], "github_connected": False}
    repo_full = f"{owner}/{repo}"
    try:
        async with GitHubClient(repo_full_name=repo_full, token=gh_token) as gh:
            items = await gh.list_collaborators()
        return {
            "github_connected": True,
            "collaborators": [
                {
                    "login": c.get("login"),
                    "avatar_url": c.get("avatar_url"),
                    "role_name": c.get("role_name", "collaborator"),
                    "permissions": c.get("permissions", {}),
                }
                for c in items
            ],
        }
    except GitHubAPIError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub collaborators error: {exc}")


@router.post("/{owner}/{repo}/collaborators", summary="Invite collaborator to GitHub repo with role (DevOps Admin)")
async def add_repo_collaborator(
    owner: str,
    repo: str,
    body: CollaboratorRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
):
    gh_token = effective_github_token(current_user)
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT with admin repo rights first.")

    perm_map = {
        "read_only": "pull",
        "developer": "push",
        "reviewer": "maintain",
        "devops_admin": "admin",
    }
    permission = perm_map[body.role]
    gh_user_clean = body.github_username.strip().lstrip("@")
    if not gh_user_clean:
        raise HTTPException(status_code=400, detail="Enter a valid GitHub username")
    repo_full = f"{owner}/{repo}"
    try:
        async with GitHubClient(repo_full_name=repo_full, token=gh_token) as gh:
            res = await gh.add_collaborator(gh_user_clean, permission=permission)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=400, detail=f"Could not invite @{gh_user_clean}: {exc}")

    db = _db(request)
    await _record_audit(
        db,
        action="GITHUB_COLLABORATOR_INVITED",
        repo=repo_full,
        current_user=current_user,
        extra={"target_github_user": gh_user_clean, "assigned_role": body.role, "github_permission": permission},
    )
    return {
        "invited": gh_user_clean,
        "role": body.role,
        "github_permission": permission,
        "github_response": res,
    }


@router.delete("/{owner}/{repo}/collaborators/{username}", summary="Remove GitHub collaborator (DevOps Admin)")
async def delete_repo_collaborator(
    owner: str,
    repo: str,
    username: str,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("devops_admin"))],
):
    gh_token = effective_github_token(current_user)
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT first.")
    repo_full = f"{owner}/{repo}"
    try:
        async with GitHubClient(repo_full_name=repo_full, token=gh_token) as gh:
            await gh.remove_collaborator(username)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=400, detail=f"Could not remove @{username}: {exc}")
    db = _db(request)
    await _record_audit(
        db,
        action="GITHUB_COLLABORATOR_REMOVED",
        repo=repo_full,
        current_user=current_user,
        extra={"target_github_user": username},
    )
    return {"removed": username}


# ---------------------------------------------------------------------------
# Real Pull Requests, Demo PR Creation, Scan, Review & Merge
# ---------------------------------------------------------------------------


@router.get("/{owner}/{repo}/pulls", summary="List PRs with enriched risk & review data")
async def list_pulls(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    state: str = "open",
):
    gh_token = effective_github_token(current_user)
    try:
        prs = await _gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls?state={state}&per_page=30",
            gh_token,
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error ({e.response.status_code})")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")

    db = _db(request)
    repo_full = f"{owner}/{repo}"
    enriched = []
    for pr in prs:
        risk = await _get_risk_for_pr(db, owner, repo, pr["number"])
        reviews = await _get_reviews_for_pr(db, repo_full, pr["number"])
        enriched.append(_enrich_pr_item(pr, repo, risk, reviews))

    return jsonable_encoder({
        "owner": owner,
        "repo": repo,
        "total": len(enriched),
        "pulls": enriched,
    })


@router.post("/{owner}/{repo}/demo-pr", summary="Create a real branch & Pull Request on GitHub and scan it")
async def create_real_demo_pr(
    owner: str,
    repo: str,
    body: CreateDemoPRRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
):
    """
    Create a genuine branch, commit real Python changes, open a real Pull Request
    on GitHub, and run DeployGuard's full AST + Cross-File Risk Scan immediately.
    """
    gh_token = effective_github_token(current_user)
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT with repo write scope to open PRs.")

    repo_full = f"{owner}/{repo}"
    db_client = getattr(request.app.state, "db", None)
    db = _db(request)
    agent = getattr(request.app.state, "agent", None)

    async with GitHubClient(repo_full_name=repo_full, token=gh_token) as gh:
        repo_meta = await _gh_get(f"https://api.github.com/repos/{repo_full}", gh_token)
        base_branch = repo_meta.get("default_branch", "main")
        try:
            base_sha = await gh.get_branch_sha(base_branch)
        except GitHubAPIError:
            # Auto-initialize completely empty repository (e.g. brand-new test repo without README)
            await gh.create_or_update_file(
                "README.md", _STARTER_README_MD, "chore: initialize DeployGuard test repository", base_branch
            )
            base_sha = await gh.get_branch_sha(base_branch)

        suffix = uuid.uuid4().hex[:4]
        branch_name = f"dg-{body.scenario}-{suffix}"

        # Ensure baseline files exist on base_branch when scenario == "block" or "warn" on empty/external repos
        if body.scenario == "block":
            if await gh.get_file_sha("services/payments.py", base_branch) is None:
                await gh.create_or_update_file(
                    "services/payments.py", _STARTER_PAYMENTS_PY, "chore: seed payments v1 endpoint", base_branch
                )
            if await gh.get_file_sha("routes/checkout.py", base_branch) is None:
                await gh.create_or_update_file(
                    "routes/checkout.py", _STARTER_CHECKOUT_PY, "chore: seed checkout consumer", base_branch
                )
            base_sha = await gh.get_branch_sha(base_branch)
        elif body.scenario == "warn":
            if await gh.get_file_sha("services/auth_tokens.py", base_branch) is None:
                await gh.create_or_update_file(
                    "services/auth_tokens.py", _STARTER_AUTH_PY, "chore: seed auth token baseline", base_branch
                )
                base_sha = await gh.get_branch_sha(base_branch)

        await gh.create_branch(branch_name, base_sha)

        if body.scenario == "safe":
            pr_title = body.title or f"feat(retry): add idempotent backoff helper [{suffix}]"
            pr_body = "Additive utility with unit test coverage (expected PASS verdict)."
            await gh.create_or_update_file(
                file_path=f"services/retry_helper_{suffix}.py",
                content="def retry_backoff(attempt: int = 1, base: float = 0.5) -> float:\n    return round(base * (2 ** attempt), 3)\n",
                message=f"feat: add retry_helper_{suffix}",
                branch=branch_name,
            )
            await gh.create_or_update_file(
                file_path=f"tests/test_retry_{suffix}.py",
                content=f"from services.retry_helper_{suffix} import retry_backoff\n\ndef test_backoff():\n    assert retry_backoff(2) == 2.0\n",
                message=f"test: cover retry_helper_{suffix}",
                branch=branch_name,
            )
        elif body.scenario == "warn":
            pr_title = body.title or f"refactor(auth): adjust OAuth token jitter TTL [{suffix}]"
            pr_body = "Modifies authentication critical path without tests (expected WARN verdict)."
            await gh.create_or_update_file(
                file_path="services/auth_tokens.py",
                content=(
                    f"def refresh_token(user_id: str, ttl: int = 3600) -> dict:\n"
                    f"    # Jitter adjustment {suffix}\n"
                    f"    adaptive_ttl = ttl + 45\n"
                    f"    return {{'user_id': user_id, 'ttl': adaptive_ttl}}\n"
                ),
                message=f"refactor(auth): adaptive token TTL {suffix}",
                branch=branch_name,
            )
        elif body.scenario == "block":
            pr_title = body.title or f"refactor(payments): drop legacy v1 charge route [{suffix}]"
            pr_body = "Removes POST /v1/payments/charge still imported by routes/checkout.py (expected BLOCK verdict)."
            await gh.create_or_update_file(
                file_path="services/payments.py",
                content=(
                    "from fastapi import APIRouter\n\n"
                    "router = APIRouter()\n\n"
                    "@router.post('/v2/payments/charge')\n"
                    "def process_charge_v2(order_id: str, amount_cents: int, currency: str) -> dict:\n"
                    "    return {'status': 'charged', 'order_id': order_id, 'amount_cents': amount_cents, 'currency': currency}\n"
                ),
                message=f"refactor(payments): remove v1 charge endpoint {suffix}",
                branch=branch_name,
            )
        else:
            fname = (body.custom_filename or f"services/custom_{suffix}.py").strip()
            code = body.custom_code or "def custom_handler(x: int) -> int:\n    return x * 2\n"
            pr_title = body.title or f"feat(custom): update {fname}"
            pr_body = "Created via DeployGuard Workspace live PR workflow."
            await gh.create_or_update_file(
                file_path=fname,
                content=code,
                message=pr_title,
                branch=branch_name,
            )

        pr = await gh.create_pull_request(
            title=pr_title,
            head=branch_name,
            base=base_branch,
            body=pr_body,
        )

    pr_number = pr["number"]
    policy_doc = await db["enterprise_policy"].find_one({"workspace_id": current_user.get("workspace_id")}) or {}
    await seed_repo_graph_nodes(db_client, repo_full)
    analysis = await run_pr_analysis(
        repo_full_name=repo_full,
        pr_number=pr_number,
        source="MANUAL_SCAN",
        github_token=gh_token,
        db_client=db_client,
        agent=agent,
        owner_email=current_user["email"],
        workspace_id=current_user.get("workspace_id"),
        policy=policy_doc,
        post_to_github=True,
    )

    await _record_audit(
        db,
        action=f"PR_CREATED_{body.scenario.upper()}",
        repo=repo_full,
        pr_number=pr_number,
        current_user=current_user,
        extra={"branch": branch_name, "risk_level": analysis.risk_level.value, "risk_score": analysis.risk_score},
    )

    return jsonable_encoder({
        "pr_number": pr_number,
        "html_url": pr.get("html_url"),
        "branch": branch_name,
        "title": pr_title,
        "analysis": analysis.model_dump(),
    })


@router.post("/{owner}/{repo}/pulls/{pr_number}/analyze", summary="Run PR risk analysis")
@router.post("/{owner}/{repo}/pulls/{pr_number}/resync", summary="Re-sync & analyze PR on demand")
async def analyze_pr(
    owner: str,
    repo: str,
    pr_number: int,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
):
    """Run full AST diff, cross-file impact, and weighted 40/30/20/10 scan for PR."""
    gh_token = effective_github_token(current_user)
    repo_full = f"{owner}/{repo}"
    db_client = getattr(request.app.state, "db", None)
    db = _db(request)
    agent = getattr(request.app.state, "agent", None)
    policy_doc = await db["enterprise_policy"].find_one({"workspace_id": current_user.get("workspace_id")}) or {}

    result = await run_pr_analysis(
        repo_full_name=repo_full,
        pr_number=pr_number,
        source="MANUAL_SCAN",
        github_token=gh_token or "",
        db_client=db_client,
        agent=agent,
        owner_email=current_user["email"],
        workspace_id=current_user.get("workspace_id"),
        policy=policy_doc,
        post_to_github=bool(gh_token),
    )

    if result.status == "FAILED":
        raise HTTPException(status_code=502, detail=result.error or "PR analysis failed")

    await _record_audit(
        db,
        action=f"SCAN_{result.risk_level.value}",
        repo=repo_full,
        pr_number=pr_number,
        current_user=current_user,
        extra={"risk_score": result.risk_score, "risk_level": result.risk_level.value, "source": "MANUAL_SCAN"},
    )
    return jsonable_encoder(result.model_dump())


@router.post("/{owner}/{repo}/pulls/{pr_number}/reviews", summary="Submit PR review (Reviewer or DevOps Admin only)")
async def submit_pr_review(
    owner: str,
    repo: str,
    pr_number: int,
    body: PRReviewRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("reviewer", "devops_admin"))],
):
    """
    Submit a formal review decision (APPROVE / REQUEST_CHANGES / COMMENT) on GitHub
    and store the workspace RBAC review trail in MongoDB.
    """
    gh_token = effective_github_token(current_user)
    repo_full = f"{owner}/{repo}"
    db = _db(request)
    now = datetime.now(timezone.utc).isoformat()
    github_review_id: int | None = None
    github_note = "posted_to_github"

    formatted_body = (
        f"**[DeployGuard Review · {body.event}]** by `{current_user['email']}` "
        f"(Role: `{current_user.get('role')}`)\n\n{body.body.strip()}"
    )

    if gh_token:
        async with GitHubClient(repo_full_name=repo_full, token=gh_token) as gh:
            try:
                gh_resp = await gh.create_pr_review(pr_number=pr_number, event=body.event, body=formatted_body)
                github_review_id = gh_resp.get("id")
            except GitHubAPIError as exc:
                # GitHub blocks self-approval on the same GitHub user; record as COMMENT review on GitHub cleanly
                if exc.status_code == 422 and body.event in ("APPROVE", "REQUEST_CHANGES"):
                    gh_resp = await gh.create_pr_review(pr_number=pr_number, event="COMMENT", body=formatted_body)
                    github_review_id = gh_resp.get("id")
                    github_note = "posted_as_comment_self_pr_rule"
                else:
                    raise HTTPException(status_code=502, detail=f"GitHub review failed: {exc}")

    review_record = {
        "repo_full_name": repo_full,
        "pr_number": pr_number,
        "workspace_id": current_user.get("workspace_id"),
        "reviewer_email": current_user["email"],
        "reviewer_name": current_user.get("full_name", ""),
        "reviewer_role": current_user.get("role"),
        "decision": body.event,
        "body": body.body.strip(),
        "github_review_id": github_review_id,
        "github_note": github_note,
        "timestamp": now,
    }
    await db["pr_reviews"].insert_one(dict(review_record))
    await _record_audit(
        db,
        action=f"PR_REVIEW_{body.event}",
        repo=repo_full,
        pr_number=pr_number,
        current_user=current_user,
        extra={"review_body": body.body.strip()},
    )
    return jsonable_encoder({"status": "submitted", "review": review_record})


@router.post("/{owner}/{repo}/pulls/{pr_number}/merge", summary="RBAC & Policy-gated PR merge")
async def merge_pr(
    owner: str,
    repo: str,
    pr_number: int,
    body: MergeRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(require_roles("reviewer", "devops_admin"))],
):
    gh_token = effective_github_token(current_user)
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT with write access to merge PRs.")

    role = current_user.get("role", "developer")
    is_override = bool(body.admin_override or body.override)
    if is_override and role != "devops_admin":
        raise HTTPException(
            status_code=403,
            detail="Only DevOps Admin ('devops_admin') can authorize Admin Override on blocked PRs.",
        )
    if is_override and not body.override_reason.strip():
        raise HTTPException(status_code=400, detail="Override reason is required for Admin Override merge.")

    db = _db(request)
    repo_full = f"{owner}/{repo}"
    risk = await _get_risk_for_pr(db, owner, repo, pr_number)
    policy_doc = await db["enterprise_policy"].find_one({"workspace_id": current_user.get("workspace_id")}) or {}
    max_score = int(policy_doc.get("max_auto_merge_score", 35))

    if risk:
        decision = risk.get("decision") or risk.get("risk_level", "PASS")
        risk_score = int(risk.get("risk_score") or 0)
        if (decision == "BLOCK" or risk_score > max_score) and not is_override:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "MERGE_BLOCKED",
                    "reason": (
                        f"Risk score ({risk_score}/100, verdict {decision}) exceeds policy limit ({max_score}). "
                        "Requires DevOps Admin Override to merge."
                    ),
                    "risk_level": risk.get("risk_level"),
                    "risk_score": risk_score,
                },
            )
    elif not is_override:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "UNSCANNED_PR",
                "reason": "PR has not been scanned yet. Click 'Scan PR' before merging or use DevOps Admin Override.",
            },
        )

    merge_resp = await _gh_put(
        f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/merge",
        gh_token,
        {
            "merge_method": body.merge_method,
            "commit_title": body.commit_title or f"[DeployGuard] Merge PR #{pr_number}",
            "commit_message": body.commit_message or (
                f"Merged by {current_user['email']} (role={role}) via DeployGuard AI. "
                f"Score: {risk.get('risk_score', 'N/A') if risk else 'N/A'}/100. "
                f"{'Override: ' + body.override_reason if is_override else 'Gate passed.'}"
            ),
        },
    )
    merge_result = merge_resp.json()

    if merge_resp.is_error or not merge_result.get("merged"):
        raise HTTPException(
            status_code=merge_resp.status_code if merge_resp.status_code >= 400 else 400,
            detail=merge_result.get("message", "GitHub merge failed"),
        )

    await _record_audit(
        db,
        action="OVERRIDE_MERGE" if is_override else "PR_MERGED",
        repo=repo_full,
        pr_number=pr_number,
        current_user=current_user,
        extra={
            "merged_by": current_user["email"],
            "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
            "risk_score": risk.get("risk_score") if risk else None,
            "admin_override": is_override,
            "override_reason": body.override_reason,
            "source": "LIVE_MERGE",
        },
    )

    return {
        "merged": True,
        "sha": merge_result.get("sha"),
        "message": merge_result.get("message"),
        "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
        "actor_role": role,
    }
