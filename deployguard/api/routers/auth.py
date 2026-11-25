"""
api/routers/auth.py — User authentication & GitHub OAuth for DeployGuard AI SaaS

Endpoints:
  POST /auth/register        — email + password signup
  POST /auth/login           — email + password login → JWT
  GET  /auth/github          — redirect to GitHub OAuth
  GET  /auth/github/callback — GitHub OAuth callback → JWT
  GET  /auth/me              — get current user profile
  POST /auth/logout          — invalidate session (client-side JWT drop)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorCollection
from pydantic import BaseModel, Field

from deployguard.core.crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "deployguard-secret-change-in-prod-32chars")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", os.environ.get("FRONTEND_URL", "https://deployguard-ai.onrender.com"))
JWT_EXPIRE_HOURS = 72

_bearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Minimal JWT (no extra libs needed — base64 + HMAC-SHA256)
# ---------------------------------------------------------------------------
import base64
import json as _json


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_jwt(payload: dict) -> str:
    header = _b64url_encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload["iat"] = int(time.time())
    payload["exp"] = int(time.time()) + JWT_EXPIRE_HOURS * 3600
    body = _b64url_encode(_json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


def verify_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected_sig = hmac.new(
            SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(
            _b64url_decode(sig), expected_sig
        ):
            return None
        payload = _json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


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


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------

def _users_col(request: Request) -> AsyncIOMotorCollection:
    db_client = getattr(request.app.state, "db", None)
    if db_client is None or getattr(db_client, "db", None) is None:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable. Check MongoDB connection.",
        )
    return db_client.db["users"]


# ---------------------------------------------------------------------------
# Auth dependencies
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


async def get_current_user(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)] = None,
) -> dict:
    token = _extract_bearer(request, creds)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    col = _users_col(request)
    email = str(payload.get("email", "")).strip().lower()
    user = await col.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    user["_id"] = str(user["_id"])
    # Decrypt GitHub PAT transparently for authenticated downstream API handlers
    if user.get("github_access_token"):
        try:
            user["github_access_token"] = decrypt_secret(user["github_access_token"])
        except Exception:
            logger.warning("Could not decrypt stored GitHub token for %s", email)
            user["github_access_token"] = None
    return user


async def get_optional_current_user(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)] = None,
) -> dict | None:
    """Return authenticated user dict if valid Bearer token is present, else None."""
    token = _extract_bearer(request, creds)
    if not token:
        return None
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    col = _users_col(request)
    email = str(payload.get("email", "")).strip().lower()
    user = await col.find_one({"email": email})
    if not user:
        return None
    user["_id"] = str(user["_id"])
    if user.get("github_access_token"):
        try:
            user["github_access_token"] = decrypt_secret(user["github_access_token"])
        except Exception:
            user["github_access_token"] = None
    return user


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


class UserOut(BaseModel):
    email: str
    full_name: str
    company: str
    github_username: Optional[str] = None
    github_connected: bool = False
    plan: str = "free"
    created_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register", summary="Register with email + password")
async def register(body: RegisterRequest, request: Request):
    col = _users_col(request)
    email = body.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid work email address")

    existing = await col.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    now = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "email": email,
        "password_hash": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "company": body.company.strip(),
        "github_username": None,
        "github_access_token": None,
        "github_connected": False,
        "connected_repos": [],
        "plan": "free",
        "created_at": now,
        "updated_at": now,
    }
    await col.insert_one(user_doc)

    token = create_jwt({"email": email, "full_name": user_doc["full_name"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": email,
            "full_name": user_doc["full_name"],
            "company": user_doc["company"],
            "github_connected": False,
            "plan": "free",
            "created_at": now,
        },
    }


@router.post("/login", summary="Login with email + password")
async def login(body: LoginRequest, request: Request):
    col = _users_col(request)
    email = body.email.strip().lower()
    user = await col.find_one({"email": email})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_jwt({"email": user["email"], "full_name": user["full_name"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "company": user.get("company", ""),
            "github_connected": user.get("github_connected", False),
            "github_username": user.get("github_username"),
            "plan": user.get("plan", "free"),
            "created_at": user.get("created_at", ""),
        },
    }


@router.get("/github", summary="Start GitHub OAuth flow")
async def github_oauth_start(request: Request):
    """Redirect browser to GitHub OAuth consent page."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=503, detail="GitHub OAuth not configured")

    state = secrets.token_urlsafe(16)
    _oauth_states[state] = time.time()
    base = str(request.base_url).rstrip("/") if request else PUBLIC_URL.rstrip("/")

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": "read:user user:email repo",
        "state": state,
        "redirect_uri": f"{base}/auth/github/callback",
    }
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{urlencode(params)}")


_oauth_states: dict[str, float] = {}


@router.get("/github/callback", summary="GitHub OAuth callback")
async def github_oauth_callback(
    code: str,
    state: str,
    request: Request,
    token: Optional[str] = None,
):
    """
    Exchange GitHub code for access token.
    If `token` query param present (user JWT), connect GitHub to existing account.
    Otherwise create/login a new user via GitHub identity.
    """
    # Validate state (CSRF protection)
    ts = _oauth_states.pop(state, None)
    if ts is None or time.time() - ts > 300:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    # Exchange code for GitHub token
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        gh_token_data = resp.json()

    gh_access_token = gh_token_data.get("access_token")
    if not gh_access_token:
        raise HTTPException(status_code=400, detail="GitHub OAuth failed")

    # Fetch GitHub user info
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {gh_access_token}"},
        )
        gh_user = r.json()

        # Get primary email if not public
        if not gh_user.get("email"):
            er = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {gh_access_token}"},
            )
            emails = er.json()
            primary = next((e["email"] for e in emails if e.get("primary")), None)
            gh_user["email"] = primary

    email = (gh_user.get("email") or f"{username}@github.com").strip().lower()
    username = gh_user.get("login")
    encrypted_gh_token = encrypt_secret(gh_access_token)

    col = _users_col(request)
    now = datetime.now(timezone.utc).isoformat()

    if token:
        payload = verify_jwt(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid JWT")
        await col.update_one(
            {"email": payload["email"].strip().lower()},
            {"$set": {
                "github_username": username,
                "github_access_token": encrypted_gh_token,
                "github_connected": True,
                "updated_at": now,
            }},
        )
        return {"message": "GitHub connected successfully", "github_username": username}

    user = await col.find_one({"email": email})
    if not user:
        user_doc = {
            "email": email,
            "password_hash": "",
            "full_name": gh_user.get("name") or username,
            "company": gh_user.get("company") or "",
            "github_username": username,
            "github_access_token": encrypted_gh_token,
            "github_connected": True,
            "connected_repos": [],
            "plan": "free",
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

    jwt_tok = create_jwt({"email": user["email"], "full_name": user.get("full_name", username)})
    if "application/json" in request.headers.get("accept", ""):
        return {
            "access_token": jwt_tok,
            "token_type": "bearer",
            "user": {
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "company": user.get("company", ""),
                "github_connected": True,
                "github_username": username,
                "plan": user.get("plan", "free"),
                "created_at": user.get("created_at", now),
            },
        }
    return RedirectResponse(f"/?oauth_token={jwt_tok}")


@router.get("/me", summary="Get current user profile")
async def get_me(current_user: Annotated[dict, Depends(get_current_user)]):
    return {
        "email": current_user["email"],
        "full_name": current_user.get("full_name", ""),
        "company": current_user.get("company", ""),
        "github_connected": current_user.get("github_connected", False),
        "github_username": current_user.get("github_username"),
        "connected_repos": current_user.get("connected_repos", []),
        "plan": current_user.get("plan", "free"),
        "created_at": current_user.get("created_at", ""),
    }


class ConnectGitHubRequest(BaseModel):
    github_token: str = Field(min_length=10)


@router.post("/connect-github", summary="Link GitHub account via Personal Access Token")
async def connect_github_pat(
    body: ConnectGitHubRequest,
    request: Request,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """Validate a GitHub PAT, fetch the GitHub username & repos, and link to user account."""
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
    col = _users_col(request)
    await col.update_one(
        {"email": current_user["email"]},
        {"$set": {
            "github_username": username,
            "github_access_token": encrypt_secret(body.github_token),
            "github_connected": True,
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
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """Remove stored GitHub token and unlink username."""
    col = _users_col(request)
    await col.update_one(
        {"email": current_user["email"]},
        {"$set": {
            "github_username": None,
            "github_access_token": None,
            "github_connected": False,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }},
    )
    return {"github_connected": False, "github_username": None}
