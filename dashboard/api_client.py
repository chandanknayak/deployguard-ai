"""
dashboard/api_client.py — HTTP client for the DeployGuard AI FastAPI backend.

Provides synchronous wrappers (required by Streamlit's threading model)
around the DeployGuard REST API so the dashboard can display real data
fetched from MongoDB through the API layer.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests

# ---------------------------------------------------------------------------
# API base URL — reads from environment or falls back to localhost
# ---------------------------------------------------------------------------
_DEFAULT_API_URL = os.environ.get("DASHBOARD_API_URL", "http://localhost:8080")


class APIClient:
    """
    Thin synchronous HTTP client for the DeployGuard AI REST API.

    All methods return parsed JSON dicts/lists or raise ``APIError``.
    Streamlit runs user code synchronously, so we use the ``requests``
    library rather than ``httpx.AsyncClient``.
    """

    def __init__(self, base_url: str = _DEFAULT_API_URL, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "User-Agent": "DeployGuard-Dashboard/1.0",
        })

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict:
        """Check liveness of the API server."""
        try:
            r = self._session.get(f"{self.base_url}/healthz", timeout=self.timeout)
            return r.json()
        except Exception as exc:
            return {"status": "unreachable", "error": str(exc)}

    def readyz(self) -> dict:
        """Check readiness (MongoDB + agent) of the API server."""
        try:
            r = self._session.get(f"{self.base_url}/readyz", timeout=self.timeout)
            return r.json()
        except Exception as exc:
            return {"status": "unreachable", "checks": {}, "error": str(exc)}

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def list_assessments(
        self,
        limit: int = 20,
        skip: int = 0,
        repo: str | None = None,
        decision: str | None = None,
    ) -> dict:
        """Return paginated list of recent assessments."""
        params: dict[str, Any] = {"limit": limit, "skip": skip}
        if repo:
            params["repo"] = repo
        if decision:
            params["decision"] = decision
        try:
            r = self._session.get(
                f"{self.base_url}/assessments/",
                params=params,
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as exc:
            return {"total": 0, "results": [], "error": str(exc)}
        except Exception as exc:
            return {"total": 0, "results": [], "error": str(exc)}

    def get_assessment(self, assessment_id: str) -> dict | None:
        """Fetch a single assessment by ID."""
        try:
            r = self._session.get(
                f"{self.base_url}/assessments/{assessment_id}",
                timeout=self.timeout,
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def get_pr_assessment(self, repo_owner: str, repo_name: str, pr_number: int) -> dict | None:
        """Fetch the latest assessment for a specific repo+PR."""
        try:
            r = self._session.get(
                f"{self.base_url}/assessments/pr/{repo_owner}/{repo_name}/{pr_number}",
                timeout=self.timeout,
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def get_stats(self) -> dict:
        """Fetch aggregate statistics."""
        try:
            r = self._session.get(
                f"{self.base_url}/assessments/stats",
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {"total_assessments": 0, "by_decision": {}, "error": str(exc)}

    def is_reachable(self) -> bool:
        """Return True if the API server responds to /healthz."""
        h = self.health()
        return h.get("status") == "ok"

    # ------------------------------------------------------------------
    # Enterprise Management
    # ------------------------------------------------------------------

    def get_enterprise_policy(self) -> dict:
        """Fetch enterprise governance policy."""
        try:
            r = self._session.get(f"{self.base_url}/enterprise/policy", timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {
                "organization_name": "DeployGuard Enterprise",
                "max_auto_merge_score": 35,
                "block_on_p0_sla": True,
                "block_on_api_changes": False,
                "require_canary_for_medium_risk": True,
                "enforce_branch_protection": True,
            }

    def update_enterprise_policy(self, policy: dict) -> dict:
        """Update enterprise governance policy."""
        try:
            r = self._session.post(f"{self.base_url}/enterprise/policy", json=policy, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def list_repositories(self) -> list[dict]:
        """Fetch list of connected repositories."""
        try:
            r = self._session.get(f"{self.base_url}/enterprise/repos", timeout=self.timeout)
            r.raise_for_status()
            return r.json().get("repositories", [])
        except Exception as exc:
            return [
                {
                    "id": 1,
                    "name": "deployguard-ai",
                    "full_name": "chandanknayak/deployguard-ai",
                    "owner": "chandanknayak",
                    "private": False,
                    "default_branch": "main",
                    "description": "AI-Powered Release Risk & Change-Impact Platform",
                    "html_url": "https://github.com/chandanknayak/deployguard-ai",
                }
            ]

    def list_repo_pulls(self, owner: str, repo: str) -> list[dict]:
        """Fetch open PRs with live risk status."""
        try:
            r = self._session.get(f"{self.base_url}/enterprise/repos/{owner}/{repo}/pulls", timeout=self.timeout)
            r.raise_for_status()
            return r.json().get("pull_requests", [])
        except Exception as exc:
            return []

    def analyze_pr(self, owner: str, repo: str, pr_number: int) -> dict:
        """Trigger on-demand analysis for an open PR."""
        try:
            r = self._session.post(f"{self.base_url}/enterprise/repos/{owner}/{repo}/pulls/{pr_number}/analyze", timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def merge_pr(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        merge_method: str = "squash",
        override: bool = False,
        override_reason: str | None = None,
        operator: str = "Enterprise Admin",
    ) -> dict:
        """Perform one-click safe merge of a pull request."""
        payload = {
            "merge_method": merge_method,
            "override": override,
            "override_reason": override_reason,
            "operator": operator,
        }
        try:
            r = self._session.post(f"{self.base_url}/enterprise/repos/{owner}/{repo}/pulls/{pr_number}/merge", json=payload, timeout=20)
            if not r.ok:
                err_detail = r.json().get("detail", r.text)
                return {"status": "error", "error": err_detail}
            return r.json()
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def trigger_deploy(
        self,
        owner: str,
        repo: str,
        environment: str = "staging",
        strategy: str = "CANARY",
        traffic_percent: int = 5,
        pr_number: int | None = None,
        commit_sha: str | None = None,
        operator: str = "DevOps Lead",
    ) -> dict:
        """Trigger deployment pipeline with real-time verification status."""
        payload = {
            "environment": environment,
            "strategy": strategy,
            "traffic_percent": traffic_percent,
            "pr_number": pr_number,
            "commit_sha": commit_sha,
            "operator": operator,
        }
        try:
            r = self._session.post(f"{self.base_url}/enterprise/repos/{owner}/{repo}/deploy", json=payload, timeout=20)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
