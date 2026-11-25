"""
tests/unit/test_enterprise.py — Unit & API integration tests for enterprise policies,
multi-tenant isolation, webhook safety, auth encryption, and live AST sandbox.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import patch

from starlette.testclient import TestClient

from deployguard.api.main import app
from deployguard.api.routers.auth import create_jwt
from deployguard.api.routers.enterprise import (
    DeployRequest,
    MergeRequest,
    PolicySettings,
)
from deployguard.config import settings


def test_policy_defaults():
    policy = PolicySettings()
    assert policy.organization_name == "DeployGuard Enterprise"
    assert policy.max_auto_merge_score == 35
    assert policy.block_on_p0_sla is True
    assert policy.require_canary_for_medium_risk is True


def test_policy_custom_thresholds():
    custom = PolicySettings(
        organization_name="Acme Global Platform",
        max_auto_merge_score=50,
        block_on_p0_sla=False,
    )
    assert custom.organization_name == "Acme Global Platform"
    assert custom.max_auto_merge_score == 50
    assert custom.block_on_p0_sla is False


def test_merge_request_model():
    req = MergeRequest(merge_method="squash", operator="Sarah Lead")
    assert req.merge_method == "squash"
    assert req.override is False
    assert req.operator == "Sarah Lead"

    override_req = MergeRequest(
        merge_method="rebase",
        override=True,
        override_reason="Hotfix approved by VP",
    )
    assert override_req.override is True
    assert override_req.override_reason == "Hotfix approved by VP"


def test_deploy_request_model():
    deploy = DeployRequest(environment="canary", strategy="CANARY", traffic_percent=10)
    assert deploy.environment == "canary"
    assert deploy.strategy == "CANARY"
    assert deploy.traffic_percent == 10


class TestMultiTenantAuthGuards:
    """Verify destructive/tenant routes enforce JWT auth rather than exposing global state."""

    client = TestClient(app)

    def test_protected_enterprise_routes_reject_anonymous(self):
        assert self.client.post("/enterprise/policy", json={}).status_code == 401
        assert self.client.get("/enterprise/audit").status_code == 401
        assert self.client.get("/enterprise/repos").status_code == 401
        assert self.client.post("/enterprise/repos/acme/api/pulls/1/merge", json={}).status_code == 401
        assert self.client.post("/enterprise/repos/acme/api/deploy", json={}).status_code == 401


class TestSimulateAnalyzeSandbox:
    """Verify live AST sandbox endpoint returns deterministic verdicts & cross-file edges."""

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


class TestWebhookIngestion:
    """Verify webhook returns 202 Accepted cleanly and validates HMAC."""

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
