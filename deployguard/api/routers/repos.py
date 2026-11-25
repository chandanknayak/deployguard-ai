"""
api/routers/repos.py — Per-user repository management & PR analysis

Endpoints:
  GET  /repos                      — list user's connected repos
  POST /repos/connect              — connect a GitHub repo
  DELETE /repos/{owner}/{repo}     — disconnect a repo
  GET  /repos/{owner}/{repo}/pulls — list open PRs with risk data
  POST /repos/{owner}/{repo}/pulls/{pr}/analyze — trigger analysis
  POST /repos/{owner}/{repo}/pulls/{pr}/merge   — merge after gate check
"""

from __future__ import annotations

import logging
from typing import Annotated, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from deployguard.api.routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/repos", tags=["Repositories"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ConnectRepoRequest(BaseModel):
    owner: str
    repo: str


class MergeRequest(BaseModel):
    merge_method: str = "merge"   # merge | squash | rebase
    admin_override: bool = False
    override_reason: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db(request: Request):
    return request.app.state.db.db


async def _gh_get(url: str, token: str) -> dict | list:
    async with httpx.AsyncClient() as client:
        r = await client.get(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()


async def _gh_post(url: str, token: str, body: dict) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            json=body,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        return r.json()


async def _get_risk_for_pr(db, owner: str, repo: str, pr_number: int) -> Optional[dict]:
    """Fetch latest risk assessment from MongoDB for this PR."""
    col = db["risk_assessments"]
    doc = await col.find_one(
        {"repo_full_name": f"{owner}/{repo}", "pr_number": pr_number},
        sort=[("created_at", -1)],
    )
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", summary="List connected repos")
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


@router.post("/connect", summary="Connect a GitHub repository")
async def connect_repo(
    body: ConnectRepoRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    gh_token = current_user.get("github_access_token")
    if not gh_token:
        raise HTTPException(status_code=400, detail="GitHub not connected. Connect GitHub first.")

    # Verify repo exists and user has access
    try:
        repo_data = await _gh_get(
            f"https://api.github.com/repos/{body.owner}/{body.repo}",
            gh_token,
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=404, detail=f"Repo {body.owner}/{body.repo} not found or no access")

    repo_entry = {
        "owner": body.owner,
        "repo": body.repo,
        "full_name": f"{body.owner}/{body.repo}",
        "description": repo_data.get("description", ""),
        "private": repo_data.get("private", False),
        "default_branch": repo_data.get("default_branch", "main"),
        "language": repo_data.get("language", ""),
        "stars": repo_data.get("stargazers_count", 0),
    }

    db = _db(request)
    col = db["users"]
    # Avoid duplicates
    await col.update_one(
        {"email": current_user["email"]},
        {"$addToSet": {"connected_repos": repo_entry}},
    )
    return {"message": f"Repo {body.owner}/{body.repo} connected!", "repo": repo_entry}


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


@router.get("/{owner}/{repo}/pulls", summary="List open PRs with risk analysis")
async def list_pulls(
    owner: str,
    repo: str,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
    state: str = "open",
):
    gh_token = current_user.get("github_access_token")
    if not gh_token:
        raise HTTPException(status_code=400, detail="GitHub not connected")

    try:
        prs = await _gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls?state={state}&per_page=30",
            gh_token,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")

    db = _db(request)
    enriched = []
    for pr in prs:
        risk = await _get_risk_for_pr(db, owner, repo, pr["number"])
        enriched.append({
            "pr_number": pr["number"],
            "title": pr["title"],
            "author": pr["user"]["login"],
            "author_avatar": pr["user"]["avatar_url"],
            "branch": pr["head"]["ref"],
            "base_branch": pr["base"]["ref"],
            "created_at": pr["created_at"],
            "updated_at": pr["updated_at"],
            "url": pr["html_url"],
            "draft": pr.get("draft", False),
            "mergeable": pr.get("mergeable"),
            "additions": pr.get("additions", 0),
            "deletions": pr.get("deletions", 0),
            "changed_files": pr.get("changed_files", 0),
            "labels": [l["name"] for l in pr.get("labels", [])],
            # Risk data from DeployGuard
            "risk_level": risk["risk_level"] if risk else "PENDING",
            "risk_score": risk.get("risk_score", 0) if risk else None,
            "decision": risk.get("decision", "PENDING") if risk else "PENDING",
            "blast_radius": risk.get("blast_radius", {}) if risk else {},
            "analyzed_at": risk.get("created_at") if risk else None,
            "assessment_id": risk.get("_id") if risk else None,
        })

    return {
        "owner": owner,
        "repo": repo,
        "total": len(enriched),
        "pulls": enriched,
    }


@router.post("/{owner}/{repo}/pulls/{pr_number}/analyze", summary="Trigger manual PR analysis")
async def analyze_pr(
    owner: str,
    repo: str,
    pr_number: int,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """
    Manually trigger DeployGuard risk analysis for a PR.
    This calls the internal webhook processor logic.
    """
    gh_token = current_user.get("github_access_token")
    if not gh_token:
        raise HTTPException(status_code=400, detail="GitHub not connected")

    # Fetch PR data
    try:
        pr_data = await _gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}",
            gh_token,
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"PR not found: {e}")

    # Trigger analysis via the app's risk agent
    agent = getattr(request.app.state, "agent", None)
    if not agent:
        raise HTTPException(status_code=503, detail="Risk agent not available")

    db = _db(request)

    from deployguard.api.routers.enterprise import analyze_pull_request
    response = await analyze_pull_request(owner=owner, repo=repo, pr_number=pr_number, request=request)
    import json
    return json.loads(response.body.decode())


@router.post("/{owner}/{repo}/pulls/{pr_number}/merge", summary="Merge PR after gate check")
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
        raise HTTPException(status_code=400, detail="GitHub not connected")

    db = _db(request)
    risk = await _get_risk_for_pr(db, owner, repo, pr_number)

    # Gate check
    if risk:
        decision = risk.get("decision", "PASS")
        risk_score = risk.get("risk_score", 0)
        if decision == "BLOCK" and not body.admin_override:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "MERGE_BLOCKED",
                    "reason": f"Risk score {risk_score} exceeds safe threshold. Use admin_override=true to force.",
                    "risk_level": risk.get("risk_level"),
                    "risk_score": risk_score,
                },
            )

    # Perform merge via GitHub API
    merge_result = await _gh_post(
        f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/merge",
        gh_token,
        {
            "merge_method": body.merge_method,
            "commit_title": f"[DeployGuard] Merge PR #{pr_number}",
            "commit_message": f"Merged by DeployGuard AI. Risk: {risk.get('risk_level', 'UNKNOWN') if risk else 'UNANALYZED'}. Override: {body.admin_override}",
        },
    )

    if not merge_result.get("merged"):
        raise HTTPException(
            status_code=400,
            detail=merge_result.get("message", "Merge failed"),
        )

    # Log to audit
    from datetime import datetime, timezone
    await db["audit_log"].insert_one({
        "action": "pr_merged",
        "repo": f"{owner}/{repo}",
        "pr_number": pr_number,
        "merged_by": current_user["email"],
        "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
        "admin_override": body.admin_override,
        "override_reason": body.override_reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {
        "merged": True,
        "sha": merge_result.get("sha"),
        "message": merge_result.get("message"),
        "risk_level": risk.get("risk_level") if risk else "UNANALYZED",
    }
