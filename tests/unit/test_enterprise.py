"""
tests/unit/test_enterprise.py — Enterprise RBAC, SSRF, Multi-Tenant Isolation,
Live AST Sandbox, Public PR Validation, OAuth Regression, and Webhook Tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from deployguard.api.main import app, create_app
from deployguard.api.routers.enterprise import (
    DeployRequest,
    PolicySettings,
    _validate_public_http_url,
)
from deployguard.api.routers.repos import MergeRequest
from deployguard.config import settings


# ---------------------------------------------------------------------------
# Minimal In-Memory Async Fake MongoDB for Full RBAC Integration Tests
# ---------------------------------------------------------------------------


class FakeCursor:
    def __init__(self, docs: list[dict]):
        self._docs = list(docs)

    def sort(self, key: str, direction: int = 1):
        self._docs.sort(key=lambda d: str(d.get(key, "")), reverse=(direction < 0))
        return self

    def skip(self, n: int):
        self._docs = self._docs[n:]
        return self

    def limit(self, n: int):
        self._docs = self._docs[:n]
        return self

    async def to_list(self, length: int = 100):
        return [dict(d) for d in self._docs[:length]]

    def __aiter__(self):
        self._idx = 0
        return self

    async def __anext__(self):
        if self._idx >= len(self._docs):
            raise StopAsyncIteration
        item = dict(self._docs[self._idx])
        self._idx += 1
        return item


class FakeCollection:
    def __init__(self, docs: list[dict] | None = None):
        self.docs: list[dict] = docs if docs is not None else []

    @staticmethod
    def _matches(doc: dict, filt: dict | None) -> bool:
        if not filt:
            return True
        for k, v in filt.items():
            if k == "$or":
                if not any(FakeCollection._matches(doc, sub) for sub in v):
                    return False
            elif k == "$and":
                if not all(FakeCollection._matches(doc, sub) for sub in v):
                    return False
            elif isinstance(v, dict):
                val = doc.get(k)
                if "$ne" in v and val == v["$ne"]:
                    return False
                if "$in" in v and val not in v["$in"]:
                    return False
            else:
                if "." in k:
                    parent, child = k.split(".", 1)
                    arr = doc.get(parent)
                    if isinstance(arr, list):
                        if not any(isinstance(el, dict) and el.get(child) == v for el in arr):
                            return False
                        continue
                if doc.get(k) != v:
                    return False
        return True

    @staticmethod
    def _project(doc: dict, proj: dict | None) -> dict:
        out = dict(doc)
        if proj and proj.get("_id") == 0:
            out.pop("_id", None)
        elif "_id" not in out:
            out["_id"] = f"id-{abs(hash(str(out))) % 100000}"
        return out

    async def find_one(self, filt: dict | None = None, proj: dict | None = None, sort: list | None = None):
        matches = [d for d in self.docs if self._matches(d, filt)]
        if sort:
            key, direction = sort[0]
            matches.sort(key=lambda d: str(d.get(key, "")), reverse=(direction < 0))
        return self._project(matches[0], proj) if matches else None

    def find(self, filt: dict | None = None, proj: dict | None = None):
        matches = [self._project(d, proj) for d in self.docs if self._matches(d, filt)]
        return FakeCursor(matches)

    async def count_documents(self, filt: dict | None = None) -> int:
        return sum(1 for d in self.docs if self._matches(d, filt))

    async def insert_one(self, doc: dict):
        copy_doc = dict(doc)
        copy_doc.setdefault("_id", f"id-{len(self.docs) + 1}")
        self.docs.append(copy_doc)
        return SimpleNamespace(inserted_id=copy_doc["_id"])

    async def update_one(self, filt: dict, update: dict, upsert: bool = False):
        target = next((d for d in self.docs if self._matches(d, filt)), None)
        if not target:
            if not upsert:
                return SimpleNamespace(matched_count=0, modified_count=0)
            target = dict(filt)
            target.setdefault("_id", f"id-{len(self.docs) + 1}")
            self.docs.append(target)
        if "$setOnInsert" in update and len(target) <= len(filt) + 1:
            target.update(update["$setOnInsert"])
        if "$set" in update:
            target.update(update["$set"])
        if "$pull" in update:
            for field, cond in update["$pull"].items():
                if isinstance(target.get(field), list) and isinstance(cond, dict):
                    target[field] = [
                        item for item in target[field]
                        if not all(item.get(ck) == cv for ck, cv in cond.items())
                    ]
        if "$push" in update:
            for field, item in update["$push"].items():
                target.setdefault(field, []).append(item)
        return SimpleNamespace(matched_count=1, modified_count=1)

    async def replace_one(self, filt: dict, replacement: dict, upsert: bool = False):
        idx = next((i for i, d in enumerate(self.docs) if self._matches(d, filt)), None)
        copy_doc = dict(replacement)
        if idx is not None:
            copy_doc.setdefault("_id", self.docs[idx].get("_id"))
            self.docs[idx] = copy_doc
        elif upsert:
            copy_doc.setdefault("_id", f"id-{len(self.docs) + 1}")
            self.docs.append(copy_doc)

    async def delete_one(self, filt: dict):
        for i, d in enumerate(self.docs):
            if self._matches(d, filt):
                self.docs.pop(i)
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)


class FakeDBClient:
    def __init__(self):
        self.cols: dict[str, FakeCollection] = {
            "users": FakeCollection(),
            "workspaces": FakeCollection(),
            "enterprise_policy": FakeCollection(),
            "audit_log": FakeCollection(),
            "deployments": FakeCollection(),
            "risk_assessments": FakeCollection(),
            "pr_reviews": FakeCollection(),
            "code_graph": FakeCollection(),
        }
        self.db = self

    def __getitem__(self, name: str) -> FakeCollection:
        return self.cols.setdefault(name, FakeCollection())

    @property
    def assessments(self) -> FakeCollection:
        return self["risk_assessments"]

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Schema Defaults
# ---------------------------------------------------------------------------


def test_policy_defaults():
    policy = PolicySettings()
    assert policy.organization_name == "DeployGuard Enterprise"
    assert policy.max_auto_merge_score == 35
    assert policy.block_on_p0_sla is True
    assert policy.require_canary_for_medium_risk is True


def test_merge_and_deploy_models():
    override_req = MergeRequest(
        merge_method="rebase",
        override=True,
        override_reason="Hotfix approved by VP",
    )
    assert override_req.override is True
    deploy = DeployRequest(environment="canary", strategy="CANARY", traffic_percent=10)
    assert deploy.traffic_percent == 10


# ---------------------------------------------------------------------------
# Security Guards: Auth, RBAC, SSRF, Tenant Isolation
# ---------------------------------------------------------------------------


class TestMultiTenantAuthGuards:
    client = TestClient(app)

    def test_protected_routes_reject_anonymous(self):
        assert self.client.post("/enterprise/policy", json={}).status_code == 401
        assert self.client.get("/enterprise/audit").status_code == 401
        assert self.client.get("/enterprise/team").status_code == 401
        assert self.client.post("/enterprise/team/members", json={}).status_code == 401
        assert self.client.post("/enterprise/repos/acme/api/deploy", json={}).status_code == 401
        assert self.client.post("/repos/acme/api/pulls/1/merge", json={}).status_code == 401
        assert self.client.post("/repos/acme/api/pulls/1/reviews", json={"event": "APPROVE", "body": "ok"}).status_code == 401
        assert self.client.get("/assessments/").status_code == 401


class TestSSRFProtection:
    def test_rejects_loopback_and_metadata_urls(self):
        import pytest
        from fastapi import HTTPException

        for bad in (
            "http://127.0.0.1:8080/healthz",
            "http://localhost:8080/healthz",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal",
            "ftp://example.com/file",
        ):
            with pytest.raises(HTTPException) as exc:
                _validate_public_http_url(bad, strict=True)
            assert exc.value.status_code == 400


class TestRBACWorkflowIntegration:
    """Verify full Admin -> Developer -> Reviewer -> DevOps Admin RBAC enforcement."""

    def test_workspace_rbac_and_tenant_isolation(self):
        test_app = create_app()
        fake_db = FakeDBClient()
        test_app.state.db = fake_db
        test_app.state.agent = None
        client = TestClient(test_app)

        # 1. Register DevOps Admin (Workspace Founder)
        reg = client.post("/auth/register", json={
            "email": "admin@acme.com",
            "password": "StrongPassword123",
            "full_name": "Alice Admin",
            "company": "Acme Corp",
        })
        assert reg.status_code == 200
        reg_data = reg.json()
        admin_tok = reg_data["access_token"]
        assert reg_data["user"]["role"] == "devops_admin"
        ws_id = reg_data["user"]["workspace_id"]

        # 2. Admin invites Developer and Reviewer into same workspace
        dev_res = client.post(
            "/enterprise/team/members",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={
                "full_name": "Bob Dev",
                "email": "dev@acme.com",
                "password": "DevPassword123",
                "role": "developer",
            },
        )
        assert dev_res.status_code == 200
        assert dev_res.json()["member"]["workspace_id"] == ws_id

        rev_res = client.post(
            "/enterprise/team/members",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={
                "full_name": "Carol Reviewer",
                "email": "reviewer@acme.com",
                "password": "RevPassword123",
                "role": "reviewer",
            },
        )
        assert rev_res.status_code == 200

        dev_tok = client.post("/auth/login", json={"email": "dev@acme.com", "password": "DevPassword123"}).json()["access_token"]
        rev_tok = client.post("/auth/login", json={"email": "reviewer@acme.com", "password": "RevPassword123"}).json()["access_token"]

        # 3. Link encrypted GitHub PAT on workspace via Admin
        fake_db["workspaces"].docs[0]["github_access_token"] = "ghp_fakeWorkspaceTokenForTesting123"
        fake_db["workspaces"].docs[0]["github_username"] = "alice-gh"

        # Seed two PR risk assessments: PR #10 PASS, PR #11 BLOCK
        fake_db["risk_assessments"].docs.extend([
            {
                "assessment_id": "a-pass-10",
                "repo_full_name": "acme/payments",
                "pr_number": 10,
                "risk_level": "PASS",
                "risk_score": 15,
                "decision": "PASS",
                "source": "MANUAL_SCAN",
                "workspace_id": ws_id,
                "owner_email": "admin@acme.com",
                "created_at": "2026-11-25T10:00:00Z",
            },
            {
                "assessment_id": "a-block-11",
                "repo_full_name": "acme/payments",
                "pr_number": 11,
                "risk_level": "BLOCK",
                "risk_score": 88,
                "decision": "BLOCK",
                "source": "MANUAL_SCAN",
                "workspace_id": ws_id,
                "owner_email": "admin@acme.com",
                "created_at": "2026-11-25T10:05:00Z",
            },
            {
                "assessment_id": "other-tenant-secret",
                "repo_full_name": "rival/secret-repo",
                "pr_number": 1,
                "risk_level": "BLOCK",
                "risk_score": 95,
                "source": "MANUAL_SCAN",
                "workspace_id": "ws_other_tenant",
                "owner_email": "ceo@rival.com",
                "created_at": "2026-11-25T10:06:00Z",
            },
        ])

        # 4. Verify strict tenant isolation on /assessments/
        list_resp = client.get("/assessments/", headers={"Authorization": f"Bearer {dev_tok}"})
        assert list_resp.status_code == 200
        aids = {r["assessment_id"] for r in list_resp.json()["results"]}
        assert "a-pass-10" in aids
        assert "other-tenant-secret" not in aids

        # 5. Verify Developer CANNOT review, merge, deploy, edit policy, or manage team (all 403)
        assert client.post(
            "/repos/acme/payments/pulls/10/reviews",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"event": "APPROVE", "body": "LGTM"},
        ).status_code == 403
        assert client.post(
            "/repos/acme/payments/pulls/10/merge",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"merge_method": "squash"},
        ).status_code == 403
        assert client.post(
            "/enterprise/repos/acme/payments/deploy",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"environment": "production"},
        ).status_code == 403
        assert client.post(
            "/enterprise/policy",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"max_auto_merge_score": 90},
        ).status_code == 403

        # 6. Reviewer CAN review and CAN merge PASS PR #10, but CANNOT Override BLOCK PR #11 or Deploy
        with patch("deployguard.api.routers.repos.GitHubClient") as mock_gh_cls:
            mock_gh = MagicMock()
            mock_gh.__aenter__ = AsyncMock(return_value=mock_gh)
            mock_gh.__aexit__ = AsyncMock(return_value=None)
            mock_gh.create_pr_review = AsyncMock(return_value={"id": 991})
            mock_gh_cls.return_value = mock_gh

            rv_resp = client.post(
                "/repos/acme/payments/pulls/10/reviews",
                headers={"Authorization": f"Bearer {rev_tok}"},
                json={"event": "APPROVE", "body": "AST verified clean"},
            )
            assert rv_resp.status_code == 200
            assert rv_resp.json()["review"]["reviewer_role"] == "reviewer"

        with patch("deployguard.api.routers.repos._gh_put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = MagicMock(is_error=False, status_code=200, json=lambda: {"merged": True, "sha": "abc123", "message": "Merged"})
            m_safe = client.post(
                "/repos/acme/payments/pulls/10/merge",
                headers={"Authorization": f"Bearer {rev_tok}"},
                json={"merge_method": "squash"},
            )
            assert m_safe.status_code == 200
            assert m_safe.json()["actor_role"] == "reviewer"

        # Reviewer blocked from override on PR #11 and deploy
        assert client.post(
            "/repos/acme/payments/pulls/11/merge",
            headers={"Authorization": f"Bearer {rev_tok}"},
            json={"merge_method": "squash", "override": True, "override_reason": "Emergency"},
        ).status_code == 403
        assert client.post(
            "/enterprise/repos/acme/payments/deploy",
            headers={"Authorization": f"Bearer {rev_tok}"},
            json={"environment": "canary"},
        ).status_code == 403

        # 7. DevOps Admin CAN Override Merge BLOCK PR #11 AND Trigger Deploy
        with patch("deployguard.api.routers.repos._gh_put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = MagicMock(is_error=False, status_code=200, json=lambda: {"merged": True, "sha": "def456", "message": "Merged"})
            m_over = client.post(
                "/repos/acme/payments/pulls/11/merge",
                headers={"Authorization": f"Bearer {admin_tok}"},
                json={"merge_method": "squash", "override": True, "override_reason": "Hotfix INC-209"},
            )
            assert m_over.status_code == 200
            assert m_over.json()["merged"] is True

        dep_res = client.post(
            "/enterprise/repos/acme/payments/deploy",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={"environment": "canary", "strategy": "CANARY", "traffic_percent": 10, "pr_number": 11},
        )
        assert dep_res.status_code == 200
        assert dep_res.json()["deployment"]["actor_role"] == "devops_admin"

        # 8. Audit log captures the entire chain for the workspace
        audit = client.get("/enterprise/audit", headers={"Authorization": f"Bearer {admin_tok}"})
        assert audit.status_code == 200
        actions = [l.get("action") for l in audit.json()["logs"]]
        assert "TEAM_MEMBER_ADDED" in actions
        assert "PR_REVIEW_APPROVE" in actions
        assert "PR_MERGED" in actions
        assert "OVERRIDE_MERGE" in actions


# ---------------------------------------------------------------------------
# Live Sandbox & Public PR Analyzer Tests
# ---------------------------------------------------------------------------


class TestSimulateAnalyzeSandbox:
    client = TestClient(app)

    def test_sandbox_docs_only_returns_zero_pass(self):
        res = self.client.post(
            "/enterprise/simulate-analyze",
            json={
                "pr_title": "docs: update README",
                "filename": "README.md",
                "base_code": "# old",
                "head_code": "# new",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["risk_score"] == 0
        assert data["risk_level"] == "PASS"
        assert data["is_docs_or_config_only"] is True
        assert data["source"] == "SIMULATION"

    def test_sandbox_breaking_route_returns_block_and_edges(self):
        res = self.client.post(
            "/enterprise/simulate-analyze",
            json={
                "pr_title": "drop v1 charge endpoint",
                "filename": "services/payments.py",
                "base_code": (
                    "from fastapi import APIRouter\n"
                    "router = APIRouter()\n"
                    "@router.post('/v1/charge')\n"
                    "def charge_v1(order_id: str):\n"
                    "    return {}\n"
                ),
                "head_code": "def noop():\n    return None\n",
                "consumer_filename": "routes/checkout.py",
                "consumer_code": (
                    "from fastapi import APIRouter\n"
                    "from services.payments import charge_v1\n"
                    "router = APIRouter()\n"
                    "@router.post('/pay')\n"
                    "def pay():\n"
                    "    return charge_v1('123')\n"
                ),
                "has_p0_impact": True,
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["risk_level"] == "BLOCK"
        assert data["risk_score"] >= 70
        assert len(data["breaking_changes"]) >= 1
        assert len(data["dependency_edges"]) == 1
        assert data["dependency_edges"][0]["consumer_file"] == "routes/checkout.py"

    def test_public_pr_url_validation_rejects_garbage(self):
        res = self.client.post("/enterprise/analyze-public-pr", json={"pr_url": "not-a-github-url"})
        assert res.status_code == 400


# ---------------------------------------------------------------------------
# OAuth UnboundLocalError Regression & Webhook Tests
# ---------------------------------------------------------------------------


def test_github_oauth_callback_private_email_no_unbound_error():
    from deployguard.api.routers.auth import _create_oauth_state

    test_app = create_app()
    fake_db = FakeDBClient()
    test_app.state.db = fake_db
    client = TestClient(test_app)

    state = _create_oauth_state()

    mock_token_resp = MagicMock(json=lambda: {"access_token": "gho_test123"})
    mock_user_resp = MagicMock(status_code=200, json=lambda: {"login": "dev-octocat", "email": None, "name": "Dev Octocat"})
    mock_emails_resp = MagicMock(status_code=200, json=lambda: [])

    mock_http = MagicMock()
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)
    mock_http.post = AsyncMock(return_value=mock_token_resp)
    mock_http.get = AsyncMock(side_effect=[mock_user_resp, mock_emails_resp])

    with patch("deployguard.api.routers.auth.httpx.AsyncClient", return_value=mock_http):
        res = client.get(
            f"/auth/github/callback?code=abc&state={state}",
            headers={"Accept": "application/json"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["user"]["github_username"] == "dev-octocat"
        assert body["user"]["email"] == "dev-octocat@users.noreply.github.com"


def test_github_oauth_providers_link_and_teammate_match():
    from deployguard.api.routers.auth import _create_oauth_state, _verify_oauth_state

    test_app = create_app()
    fake_db = FakeDBClient()
    test_app.state.db = fake_db
    client = TestClient(test_app)

    prov = client.get("/auth/providers")
    assert prov.status_code == 200
    assert "github_oauth_enabled" in prov.json()

    # Register DevOps Admin and invite a passwordless Developer by GitHub username
    reg = client.post("/auth/register", json={
        "email": "lead@acme.com",
        "password": "StrongPassword123",
        "full_name": "Lead Admin",
        "company": "Acme",
    })
    assert reg.status_code == 200
    admin_tok = reg.json()["access_token"]
    ws_id = reg.json()["user"]["workspace_id"]

    inv = client.post(
        "/enterprise/team/members",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={
            "full_name": "Dost Dev",
            "email": "dost@team-alias.com",
            "password": "",
            "role": "developer",
            "github_username": "@DostHandle",
        },
    )
    assert inv.status_code == 200
    assert inv.json()["member"]["github_username"] == "DostHandle"

    # Simulate Dost logging in directly via GitHub OAuth with a DIFFERENT personal GitHub email
    state = _create_oauth_state()
    mock_http = MagicMock()
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)
    mock_http.post = AsyncMock(return_value=MagicMock(json=lambda: {"access_token": "gho_dost_token"}))
    mock_http.get = AsyncMock(return_value=MagicMock(
        status_code=200,
        json=lambda: {"login": "dosthandle", "email": "dost.personal@gmail.com", "name": "Dost"},
    ))

    with patch("deployguard.api.routers.auth.httpx.AsyncClient", return_value=mock_http):
        cb = client.get(
            f"/auth/github/callback?code=oauthcode&state={state}",
            headers={"Accept": "application/json"},
        )
        assert cb.status_code == 200
        body = cb.json()
        assert body["user"]["workspace_id"] == ws_id
        assert body["user"]["role"] == "developer"
        assert body["user"]["github_username"] == "dosthandle"

    # Also test link_email signed state flow for linking OAuth onto existing account
    with patch.dict("os.environ", {"GITHUB_CLIENT_ID": "cid_123", "GITHUB_CLIENT_SECRET": "csec_456"}):
        link_resp = client.post("/auth/github/link-url", headers={"Authorization": f"Bearer {admin_tok}"})
        assert link_resp.status_code == 200
        assert "github.com/login/oauth/authorize" in link_resp.json()["url"]

    link_state = _create_oauth_state(link_email="lead@acme.com")
    verified = _verify_oauth_state(link_state)
    assert verified is not None and verified["link_email"] == "lead@acme.com"

    mock_http2 = MagicMock()
    mock_http2.__aenter__ = AsyncMock(return_value=mock_http2)
    mock_http2.__aexit__ = AsyncMock(return_value=None)
    mock_http2.post = AsyncMock(return_value=MagicMock(json=lambda: {"access_token": "gho_admin_token"}))
    mock_http2.get = AsyncMock(return_value=MagicMock(
        status_code=200,
        json=lambda: {"login": "chandan-admin", "email": "lead@acme.com", "name": "Lead"},
    ))
    with patch("deployguard.api.routers.auth.httpx.AsyncClient", return_value=mock_http2):
        linked = client.get(
            f"/auth/github/callback?code=c2&state={link_state}",
            headers={"Accept": "application/json"},
        )
        assert linked.status_code == 200
        assert linked.json()["github_username"] == "chandan-admin"


class TestWebhookIngestion:
    client = TestClient(app)

    def test_webhook_queues_valid_pr_even_without_agent(self):
        payload = {
            "action": "opened",
            "number": 42,
            "pull_request": {
                "number": 42,
                "title": "feat: minor update",
                "state": "open",
                "draft": False,
                "html_url": "https://github.com/acme/api/pull/42",
                "user": {"login": "alice", "id": 1, "html_url": "https://github.com/alice"},
                "head": {
                    "label": "acme:feat",
                    "ref": "feat",
                    "sha": "abc123def456",
                    "repo": {"id": 1, "full_name": "acme/api", "private": False, "html_url": "https://github.com/acme/api"},
                },
                "base": {
                    "label": "acme:main",
                    "ref": "main",
                    "sha": "000111222333",
                    "repo": {"id": 1, "full_name": "acme/api", "private": False, "html_url": "https://github.com/acme/api"},
                },
                "commits": 1,
                "additions": 2,
                "deletions": 0,
                "changed_files": 1,
                "diff_url": "https://github.com/acme/api/pull/42.diff",
                "patch_url": "https://github.com/acme/api/pull/42.patch",
            },
            "repository": {"id": 1, "full_name": "acme/api", "private": False, "html_url": "https://github.com/acme/api"},
            "sender": {"login": "alice", "id": 1, "html_url": "https://github.com/alice"},
        }
        raw = json.dumps(payload).encode("utf-8")
        secret = settings.github_webhook_secret.get_secret_value()
        sig = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()

        with patch("deployguard.api.routers.webhook._run_analysis_pipeline") as mock_bg:
            res = self.client.post(
                "/webhook/github",
                content=raw,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "deliv-42",
                    "Content-Type": "application/json",
                },
            )
            assert res.status_code == 202
            body = res.json()
            assert body["status"] == "accepted"
            assert body["job_status"] == "QUEUED"
            mock_bg.assert_called_once()

    def test_webhook_rejects_bad_signature(self):
        res = self.client.post(
            "/webhook/github",
            content=b'{"action":"opened"}',
            headers={
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
                "X-GitHub-Event": "pull_request",
            },
        )
        assert res.status_code == 403
