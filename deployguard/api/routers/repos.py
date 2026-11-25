"""
api/routers/repos.py — Per-user repository management, PR scanning, re-sync, and gated merge.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from deployguard.api.routers.auth import get_current_user
from deployguard.core.pipeline import run_pr_analysis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/repos", tags=["Repositories"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ConnectRepoRequest(BaseModel):
    owner: str
    repo: str
    sla_tier: str = Field(default="P0", pattern="^(P0|P1|P2|P3)$")


class MergeRequest(BaseModel):
    merge_method: str = "merge"   # merge | squash | rebase
    admin_override: bool = False
    override: bool = False        # Alias accepted for API compatibility
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


async def _get_risk_for_pr(db, owner: str, repo: str, pr_number: int) -> Optional[dict]:
    """Fetch latest completed live/manual assessment from MongoDB for this PR."""
    col = db["risk_assessments"]
    doc = await col.find_one(
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


def _enrich_pr_item(pr: dict, repo_name: str, risk: dict | None) -> dict:
    """Map raw GitHub PR + MongoDB assessment to normalized UI payload."""
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

    return {
        "pr_number": pr["number"],
        "title": pr["title"],
        "author": (pr.get("user") or {}).get("login", "dev"),
        "author_avatar": (pr.get("user") or {}).get("avatar_url"),
        "branch": (pr.get("head") or {}).get("ref", "feature"),
        "base_branch": (pr.get("base") or {}).get("ref", "main"),
        "head_sha": (pr.get("head") or {}).get("sha", ""),
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
        "analyzed_at": risk.get("created_at") if risk else None,
        "assessment_id": risk.get("assessment_id") if risk else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", summary="List connected repos for current user")
async def list_repos(current_user: Annotated[dict, Depends(get_current_user)]):
    return {"repos": current_user.get("connected_repos", [])}


@router.get("/available", summary="List user's GitHub repositories available to connect")
async def list_available_github_repos(current_user: Annotated[dict, Depends(get_current_user)]):
    gh_token = current_user.get("github_access_token")
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


@router.post("/connect", summary="Connect a GitHub repository (supports PAT or public repos)")
async def connect_repo(
    body: ConnectRepoRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    gh_token = current_user.get("github_access_token")
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

    db = _db(request)
    col = db["users"]
    await col.update_one(
        {"email": current_user["email"]},
        {"$pull": {"connected_repos": {"full_name": full_name}}},
    )
    await col.update_one(
        {"email": current_user["email"]},
        {"$push": {"connected_repos": repo_entry}},
    )
    return {"message": f"Repo {full_name} connected!", "repo": repo_entry}


@router.delete("/{owner}/{repo}", summary="Disconnect a repository")
async def disconnect_repo(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    db = _db(request)
    col = db["users"]
    await col.update_one(
        {"email": current_user["email"]},
        {"$pull": {"connected_repos": {"full_name": f"{owner}/{repo}"}}},
    )
    return {"message": f"Repo {owner}/{repo} disconnected"}


@router.get("/{owner}/{repo}/pulls", summary="List open PRs with enriched risk analysis")
async def list_pulls(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
    state: str = "open",
):
    gh_token = current_user.get("github_access_token")
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
    enriched = []
    for pr in prs:
        risk = await _get_risk_for_pr(db, owner, repo, pr["number"])
        enriched.append(_enrich_pr_item(pr, repo, risk))

    return jsonable_encoder({
        "owner": owner,
        "repo": repo,
        "total": len(enriched),
        "pulls": enriched,
    })


@router.post("/{owner}/{repo}/pulls/{pr_number}/analyze", summary="Run PR risk analysis using user's token")
@router.post("/{owner}/{repo}/pulls/{pr_number}/resync", summary="Re-sync & analyze PR on demand")
async def analyze_pr(
    owner: str,
    repo: str,
    pr_number: int,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """Run full AST diff, cross-file impact, and weighted 40/30/20/10 scan for PR."""
    gh_token = current_user.get("github_access_token")
    repo_full = f"{owner}/{repo}"
    db_client = getattr(request.app.state, "db", None)
    agent = getattr(request.app.state, "agent", None)

    result = await run_pr_analysis(
        repo_full_name=repo_full,
        pr_number=pr_number,
        source="MANUAL_SCAN",
        github_token=gh_token or "",
        db_client=db_client,
        agent=agent,
        owner_email=current_user["email"],
        post_to_github=bool(gh_token),
    )

    if result.status == "FAILED":
        raise HTTPException(status_code=502, detail=result.error or "PR analysis failed")

    # Log scan in tenant audit log
    if db_client is not None:
        try:
            await db_client.db["audit_log"].insert_one({
                "action": f"SCAN_{result.risk_level.value}",
                "repo": repo_full,
                "pr_number": pr_number,
                "operator": current_user["email"],
                "owner_email": current_user["email"],
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "source": "MANUAL_SCAN",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass

    return jsonable_encoder(result.model_dump())


@router.post("/{owner}/{repo}/pulls/{pr_number}/merge", summary="Merge PR after policy gate enforcement")
async def merge_pr(
    owner: str,
    repo: str,
    pr_number: int,
    body: MergeRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    gh_token = current_user.get("github_access_token")
    if not gh_token:
        raise HTTPException(status_code=400, detail="Link a GitHub PAT with write access to merge PRs.")

    db = _db(request)
    repo_full = f"{owner}/{repo}"
    risk = await _get_risk_for_pr(db, owner, repo, pr_number)
    policy_doc = await db["enterprise_policy"].find_one({"owner_email": current_user["email"]}) or {}
    max_score = int(policy_doc.get("max_auto_merge_score", 35))
    is_override = bool(body.admin_override or body.override)

    if risk:
        decision = risk.get("decision") or risk.get("risk_level", "PASS")
        risk_score = int(risk.get("risk_score") or 0)
        if (decision == "BLOCK" or risk_score > max_score) and not is_override:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "MERGE_BLOCKED",
                    "reason": f"Risk score ({risk_score}/100, verdict {decision}) exceeds policy limit ({max_score}). Provide Admin Override to merge.",
                    "risk_level": risk.get("risk_level"),
                    "risk_score": risk_score,
                },
            )
    elif not is_override:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "UNSCANNED_PR",
                "reason": "PR has not been scanned yet. Click 'Scan PR' before merging or use Admin Override.",
            },
        )

    merge_resp = await _gh_put(
        f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/merge",
        gh_token,
        {
            "merge_method": body.merge_method,
            "commit_title": f"[DeployGuard] Merge PR #{pr_number}",
            "commit_message": (
                f"Merged by {current_user['email']} via DeployGuard AI. "
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

    await db["audit_log"].insert_one({
        "action": "OVERRIDE_MERGE" if is_override else "PR_MERGED",
        "repo": repo_full,
        "pr_number": pr_number,
        "merged_by": current_user["email"],
        "operator": current_user["email"],
        "owner_email": current_user["email"],
        "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
        "risk_score": risk.get("risk_score") if risk else None,
        "admin_override": is_override,
        "override_reason": body.override_reason,
        "source": "LIVE_MERGE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {
        "merged": True,
        "sha": merge_result.get("sha"),
        "message": merge_result.get("message"),
        "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
    }
