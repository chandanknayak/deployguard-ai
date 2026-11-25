"""
api/routers/auth.py — User authentication, Workspace RBAC & GitHub integration for DeployGuard AI.

Roles:
  - devops_admin : Workspace owner / DevOps Lead — full control (policy, team, deploy, override merge)
  - reviewer     : Tech Lead / Code Reviewer — PR review & safe merge (cannot override BLOCK or deploy)
  - developer    : Software Engineer — scan PRs, open test PRs, run AST sandbox (cannot merge/deploy)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json as _json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorCollection
from pydantic import BaseModel, Field

from deployguard.config import settings
from deployguard.core.crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Config & RBAC Matrix
# ---------------------------------------------------------------------------
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
JWT_EXPIRE_HOURS = 72
_OAUTH_STATE_TTL_SEC = 300

VALID_ROLES = ("devops_admin", "reviewer", "developer")

ROLE_PERMISSIONS: dict[str, dict[str, Any]] = {
    "devops_admin": {
        "label": "DevOps / Admin",
        "can_scan_pr": True,
        "can_run_sandbox": True,
        "can_open_pr": True,
        "can_review_pr": True,
        "can_merge_safe": True,
        "can_override_block": True,
        "can_deploy": True,
        "can_edit_policy": True,
        "can_manage_team": True,
        "can_manage_repos": True,
    },
    "reviewer": {
        "label": "Reviewer / Tech Lead",
        "can_scan_pr": True,
        "can_run_sandbox": True,
        "can_open_pr": True,
        "can_review_pr": True,
        "can_merge_safe": True,
        "can_override_block": False,
        "can_deploy": False,
        "can_edit_policy": False,
        "can_manage_team": False,
        "can_manage_repos": False,
    },
    "developer": {
        "label": "Developer",
        "can_scan_pr": True,
        "can_run_sandbox": True,
        "can_open_pr": True,
        "can_review_pr": False,
        "can_merge_safe": False,
        "can_override_block": False,
        "can_deploy": False,
        "can_edit_policy": False,
        "can_manage_team": False,
        "can_manage_repos": False,
    },
}

_bearer = HTTPBearer(auto_error=False)


def _jwt_secret() -> str:
    return (
        os.environ.get("JWT_SECRET_KEY")
        or settings.jwt_secret_key.get_secret_value()
        or "deployguard-secret-change-in-prod-32chars"
    )


def _public_url(request: Request | None = None) -> str:
    env_pub = os.environ.get("PUBLIC_URL") or settings.public_url
    if env_pub and "your-deployguard" not in env_pub:
        return env_pub.rstrip("/")
    if request is not None:
        return str(request.base_url).rstrip("/")
    return "https://deployguard-ai.onrender.com"


# ---------------------------------------------------------------------------
# Minimal Stateless JWT (HS256) & Password Hashing (PBKDF2-SHA256)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_jwt(payload: dict[str, Any]) -> str:
    claims = dict(payload)
    header = _b64url_encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims["iat"] = int(time.time())
    claims["exp"] = int(time.time()) + JWT_EXPIRE_HOURS * 3600
    body = _b64url_encode(_json.dumps(claims).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(_jwt_secret().encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


def verify_jwt(token: str) -> dict[str, Any] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected_sig = hmac.new(
            _jwt_secret().encode(), f"{header}.{body}".encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected_sig):
            return None
        payload = _json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _create_oauth_state() -> str:
    """Stateless HMAC-signed OAuth state safe across multi-worker uvicorn."""
    nonce = secrets.token_urlsafe(12)
    payload = _b64url_encode(_json.dumps({"n": nonce, "ts": int(time.time())}).encode())
    sig = hmac.new(_jwt_secret().encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64url_encode(sig)}"


def _verify_oauth_state(state: str) -> bool:
    try:
        payload_b64, sig_b64 = state.split(".", 1)
        expected = hmac.new(_jwt_secret().encode(), payload_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
            return False
        data = _json.loads(_b64url_decode(payload_b64))
        return (time.time() - int(data.get("ts", 0))) <= _OAUTH_STATE_TTL_SEC
    except Exception:
        return False


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
        return hmac.compare_digest(expected.hex(), h)
    except Exception:
        return False


def make_workspace_id(seed_email: str) -> str:
    return f"ws_{hashlib.sha256(seed_email.strip().lower().encode()).hexdigest()[:12]}"


# ---------------------------------------------------------------------------
# DB Helpers & Workspace Token Resolution
# ---------------------------------------------------------------------------


def _get_db(request: Request):
    db_client = getattr(request.app.state, "db", None)
    if db_client is None or getattr(db_client, "db", None) is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable. Check MongoDB connection.",
        )
    return db_client.db


def _users_col(request: Request) -> AsyncIOMotorCollection:
    return _get_db(request)["users"]


async def ensure_user_workspace(db, user: dict[str, Any]) -> dict[str, Any]:
    """Lazily migrate legacy user docs to have workspace_id & role + synced workspace doc."""
    email = str(user.get("email", "")).strip().lower()
    role = user.get("role")
    if role not in VALID_ROLES:
        role = "devops_admin"
    ws_id = user.get("workspace_id") or make_workspace_id(email)
    company = user.get("company") or f"{user.get('full_name', 'Team')}'s Workspace"

    updates: dict[str, Any] = {}
    if user.get("role") != role:
        updates["role"] = role
        user["role"] = role
    if user.get("workspace_id") != ws_id:
        updates["workspace_id"] = ws_id
        user["workspace_id"] = ws_id

    if updates:
        try:
            await db["users"].update_one({"email": email}, {"$set": updates})
        except Exception:
            pass

    try:
        ws = await db["workspaces"].find_one({"workspace_id": ws_id})
        if not ws:
            now = datetime.now(timezone.utc).isoformat()
            ws_doc = {
                "workspace_id": ws_id,
                "name": company,
                "owner_email": email,
                "connected_repos": user.get("connected_repos", []),
                "github_username": user.get("github_username"),
                "github_access_token": user.get("github_access_token"),
                "created_at": now,
                "updated_at": now,
            }
            await db["workspaces"].update_one(
                {"workspace_id": ws_id},
                {"$setOnInsert": ws_doc},
                upsert=True,
            )
            ws = ws_doc

        # Merge workspace repos + shared workspace GitHub connection transparently
        ws_repos = ws.get("connected_repos") or []
        if ws_repos:
            user["connected_repos"] = ws_repos
        elif user.get("connected_repos"):
            await db["workspaces"].update_one(
                {"workspace_id": ws_id},
                {"$set": {"connected_repos": user["connected_repos"]}},
            )

        user["workspace_name"] = ws.get("name") or company
        if not user.get("github_access_token") and ws.get("github_access_token"):
            user["_workspace_github_token"] = ws.get("github_access_token")
            user["_workspace_github_username"] = ws.get("github_username")
    except Exception as exc:
        logger.debug("Workspace resolution fallback for %s: %s", email, exc)
        user["workspace_name"] = company

    return user


def _decrypt_user_tokens(user: dict[str, Any]) -> dict[str, Any]:
    for field in ("github_access_token", "_workspace_github_token"):
        raw = user.get(field)
        if raw:
            try:
                user[field] = decrypt_secret(raw)
            except Exception:
                logger.warning("Could not decrypt stored GitHub token for %s", user.get("email"))
                user[field] = None
    return user


def effective_github_token(user: dict[str, Any]) -> str | None:
    """Prefer the user's own PAT (preserving GitHub author attribution), else workspace PAT."""
    return user.get("github_access_token") or user.get("_workspace_github_token")


# ---------------------------------------------------------------------------
# Auth & RBAC Dependencies
# ---------------------------------------------------------------------------


def _extract_bearer(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)] = None,
) -> str | None:
    if creds:
        return creds.credentials
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        return auth_hdr[7:].strip()
    return None


async def _load_user_from_token(request: Request, token: str) -> dict[str, Any]:
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    db = _get_db(request)
    email = str(payload.get("email", "")).strip().lower()
    user = await db["users"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["_id"] = str(user["_id"])
    user = await ensure_user_workspace(db, user)
    return _decrypt_user_tokens(user)


async def get_current_user(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)] = None,
) -> dict[str, Any]:
    token = _extract_bearer(request, creds)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return await _load_user_from_token(request, token)


async def get_optional_current_user(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)] = None,
) -> dict[str, Any] | None:
    token = _extract_bearer(request, creds)
    if not token:
        return None
    return await _load_user_from_token(request, token)


def require_roles(*allowed_roles: str):
    """FastAPI dependency factory enforcing workspace RBAC."""
    async def _role_guard(
        current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    ) -> dict[str, Any]:
        role = current_user.get("role", "developer")
        if role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied for role '{role}'. Required role: {', '.join(allowed_roles)}.",
            )
        return current_user

    return _role_guard


def _format_user_response(user: dict[str, Any]) -> dict[str, Any]:
    role = user.get("role", "devops_admin")
    gh_user = user.get("github_username") or user.get("_workspace_github_username")
    has_token = bool(user.get("github_access_token") or user.get("_workspace_github_token"))
    return {
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "company": user.get("workspace_name") or user.get("company", ""),
        "workspace_id": user.get("workspace_id", ""),
        "role": role,
        "role_label": ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["developer"])["label"],
        "permissions": ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["developer"]),
        "github_connected": bool(user.get("github_connected") or has_token),
        "github_username": gh_user,
        "personal_github_connected": bool(user.get("github_connected") and user.get("github_access_token")),
        "connected_repos": user.get("connected_repos", []),
        "plan": user.get("plan", "free"),
        "created_at": user.get("created_at", ""),
    }


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2)
    company: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class ConnectGitHubRequest(BaseModel):
    github_token: str = Field(min_length=10)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/register", summary="Register new workspace owner (DevOps Admin)")
async def register(body: RegisterRequest, request: Request):
    db = _get_db(request)
    col = db["users"]
    email = body.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid work email address")

    existing = await col.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    now = datetime.now(timezone.utc).isoformat()
    ws_id = make_workspace_id(email)
    company = body.company.strip() or f"{body.full_name.strip()}'s Workspace"

    await db["workspaces"].insert_one({
        "workspace_id": ws_id,
        "name": company,
        "owner_email": email,
        "connected_repos": [],
        "github_username": None,
        "github_access_token": None,
        "created_at": now,
        "updated_at": now,
    })

    user_doc = {
        "email": email,
        "password_hash": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "company": company,
        "workspace_id": ws_id,
        "role": "devops_admin",
        "github_username": None,
        "github_access_token": None,
        "github_connected": False,
        "connected_repos": [],
        "plan": "enterprise",
        "created_at": now,
        "updated_at": now,
    }
    await col.insert_one(user_doc)
    user_doc["workspace_name"] = company

    token = create_jwt({
        "email": email,
        "full_name": user_doc["full_name"],
        "role": "devops_admin",
        "workspace_id": ws_id,
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _format_user_response(user_doc),
    }


@router.post("/login", summary="Login with email + password")
async def login(body: LoginRequest, request: Request):
    db = _get_db(request)
    email = body.email.strip().lower()
    user = await db["users"].find_one({"email": email})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = await ensure_user_workspace(db, user)
    user = _decrypt_user_tokens(user)

    token = create_jwt({
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "workspace_id": user["workspace_id"],
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _format_user_response(user),
    }


@router.post("/logout", summary="Acknowledge client-side JWT logout")
async def logout():
    return {"logged_out": True}


@router.get("/github", summary="Start GitHub OAuth flow")
async def github_oauth_start(request: Request):
    """Redirect browser to GitHub OAuth consent page."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=503, detail="GitHub OAuth not configured")

    state = _create_oauth_state()
    base = _public_url(request)
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": "read:user user:email repo",
        "state": state,
        "redirect_uri": f"{base}/auth/github/callback",
    }
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{urlencode(params)}")


@router.get("/github/callback", summary="GitHub OAuth callback")
async def github_oauth_callback(
    code: str,
    state: str,
    request: Request,
    token: Optional[str] = None,
):
    if not _verify_oauth_state(state):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        gh_token_data = resp.json()

    gh_access_token = gh_token_data.get("access_token")
    if not gh_access_token:
        raise HTTPException(status_code=400, detail="GitHub OAuth failed")

    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {gh_access_token}"},
            timeout=15,
        )
        gh_user = r.json()

        if not gh_user.get("email"):
            er = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {gh_access_token}"},
                timeout=15,
            )
            emails = er.json() if er.status_code == 200 else []
            primary = next((e["email"] for e in emails if e.get("primary")), None)
            gh_user["email"] = primary

    username = gh_user.get("login") or "github-user"
    email = (gh_user.get("email") or f"{username}@users.noreply.github.com").strip().lower()
    encrypted_gh_token = encrypt_secret(gh_access_token)

    db = _get_db(request)
    col = db["users"]
    now = datetime.now(timezone.utc).isoformat()

    if token:
        payload = verify_jwt(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid JWT")
        target_email = payload["email"].strip().lower()
        await col.update_one(
            {"email": target_email},
            {"$set": {
                "github_username": username,
                "github_access_token": encrypted_gh_token,
                "github_connected": True,
                "updated_at": now,
            }},
        )
        ws_id = payload.get("workspace_id")
        if ws_id and payload.get("role") == "devops_admin":
            await db["workspaces"].update_one(
                {"workspace_id": ws_id},
                {"$set": {
                    "github_username": username,
                    "github_access_token": encrypted_gh_token,
                    "updated_at": now,
                }},
            )
        return {"message": "GitHub connected successfully", "github_username": username}

    user = await col.find_one({"email": email})
    if not user:
        ws_id = make_workspace_id(email)
        company = gh_user.get("company") or f"{username}'s Workspace"
        await db["workspaces"].update_one(
            {"workspace_id": ws_id},
            {"$setOnInsert": {
                "workspace_id": ws_id,
                "name": company,
                "owner_email": email,
                "connected_repos": [],
                "github_username": username,
                "github_access_token": encrypted_gh_token,
                "created_at": now,
                "updated_at": now,
            }},
            upsert=True,
        )
        user_doc = {
            "email": email,
            "password_hash": "",
            "full_name": gh_user.get("name") or username,
            "company": company,
            "workspace_id": ws_id,
            "role": "devops_admin",
            "github_username": username,
            "github_access_token": encrypted_gh_token,
            "github_connected": True,
            "connected_repos": [],
            "plan": "enterprise",
            "created_at": now,
            "updated_at": now,
        }
        await col.insert_one(user_doc)
        user = user_doc
    else:
        await col.update_one(
            {"email": email},
            {"$set": {
                "github_username": username,
                "github_access_token": encrypted_gh_token,
                "github_connected": True,
                "updated_at": now,
            }},
        )
        user["github_username"] = username
        user["github_connected"] = True

    user = await ensure_user_workspace(db, user)
    jwt_tok = create_jwt({
        "email": user["email"],
        "full_name": user.get("full_name", username),
        "role": user["role"],
        "workspace_id": user["workspace_id"],
    })
    if "application/json" in request.headers.get("accept", ""):
        return {
            "access_token": jwt_tok,
            "token_type": "bearer",
            "user": _format_user_response(user),
        }
    return RedirectResponse(f"/?oauth_token={jwt_tok}")


@router.get("/me", summary="Get current user profile & RBAC permissions")
async def get_me(current_user: Annotated[dict[str, Any], Depends(get_current_user)]):
    return _format_user_response(current_user)


@router.post("/connect-github", summary="Link GitHub account via Personal Access Token")
async def connect_github_pat(
    body: ConnectGitHubRequest,
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
):
    """Validate a GitHub PAT, encrypt it at rest, and link to user + workspace."""
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {body.github_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid GitHub token or insufficient permissions")
        gh_user = r.json()

        repos_resp = await client.get(
            "https://api.github.com/user/repos?sort=updated&per_page=25",
            headers={
                "Authorization": f"token {body.github_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        available_repos = []
        if repos_resp.status_code == 200:
            for rp in repos_resp.json():
                available_repos.append({
                    "full_name": rp["full_name"],
                    "owner": rp["owner"]["login"],
                    "repo": rp["name"],
                    "private": rp.get("private", False),
                    "description": rp.get("description") or "",
                    "language": rp.get("language") or "",
                })

    username = gh_user.get("login")
    now = datetime.now(timezone.utc).isoformat()
    enc_tok = encrypt_secret(body.github_token)
    db = _get_db(request)

    await db["users"].update_one(
        {"email": current_user["email"]},
        {"$set": {
            "github_username": username,
            "github_access_token": enc_tok,
            "github_connected": True,
            "updated_at": now,
        }},
    )
    if current_user.get("role") == "devops_admin" and current_user.get("workspace_id"):
        await db["workspaces"].update_one(
            {"workspace_id": current_user["workspace_id"]},
            {"$set": {
                "github_username": username,
                "github_access_token": enc_tok,
                "updated_at": now,
            }},
        )

    return {
        "github_connected": True,
        "github_username": username,
        "available_repos": available_repos,
        "encrypted_at_rest": True,
    }


@router.post("/disconnect-github", summary="Unlink GitHub account from user profile")
async def disconnect_github(
    request: Request,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
):
    db = _get_db(request)
    now = datetime.now(timezone.utc).isoformat()
    await db["users"].update_one(
        {"email": current_user["email"]},
        {"$set": {
            "github_username": None,
            "github_access_token": None,
            "github_connected": False,
            "updated_at": now,
        }},
    )
    if current_user.get("role") == "devops_admin" and current_user.get("workspace_id"):
        await db["workspaces"].update_one(
            {"workspace_id": current_user["workspace_id"]},
            {"$set": {
                "github_username": None,
                "github_access_token": None,
                "updated_at": now,
            }},
        )
    return {"github_connected": False, "github_username": None}
