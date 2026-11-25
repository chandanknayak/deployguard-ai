"""
core/github_client.py — Async GitHub REST API client.

Provides an authenticated wrapper around ``httpx.AsyncClient`` for the
GitHub API operations DeployGuard AI requires:

    - Fetching the unified diff for a pull request.
    - Fetching raw file contents at a given commit SHA (for AST parsing).
    - Writing commit status checks (PASS / WARN / BLOCK).
    - Posting detailed Markdown risk review comments on the PR.

Design decisions:
    - ``httpx`` is used to remain async-compatible with FastAPI's event loop.
    - Rate limit headers are inspected on every response.
    - Status checks map:
        PASS  → state: "success"
        WARN  → state: "success" (with advisory description)
        BLOCK → state: "failure" (blocks branch protection rule)
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Final

import httpx

from deployguard.config import settings
from deployguard.exceptions import GitHubAPIError, GitHubRateLimitError

logger = logging.getLogger(__name__)

# GitHub API Accept headers for specific response formats
_ACCEPT_DIFF: Final[str] = "application/vnd.github.v3.diff"
_ACCEPT_RAW: Final[str] = "application/vnd.github.v3.raw"
_ACCEPT_JSON: Final[str] = "application/vnd.github+json"
_RATE_LIMIT_REMAINING_HEADER: Final[str] = "X-RateLimit-Remaining"
_RATE_LIMIT_LOW_THRESHOLD: Final[int] = 10  # Warn when fewer than 10 requests remain


class GitHubClient:
    """
    Async GitHub REST API client scoped to a single repository.

    Intended to be used as an async context manager:

        async with GitHubClient(repo_full_name="acme/payments") as client:
            diff = await client.get_pull_request_diff(pr_number=42)
            await client.create_commit_status(sha="abc", state="success", description="Risk: 12/100")
    """

    def __init__(
        self,
        repo_full_name: str,
        timeout_seconds: float = 30.0,
        token: str | None = None,
    ) -> None:
        self._repo = repo_full_name
        self._base_url = str(settings.github_api_base_url).rstrip("/")
        self._timeout = httpx.Timeout(timeout=timeout_seconds)
        self._token = token if token is not None else settings.github_api_token.get_secret_value()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "GitHubClient":
        self._client = httpx.AsyncClient(
            headers=self._build_headers(),
            timeout=self._timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def get_pull_request_diff(self, pr_number: int) -> str:
        """Fetch the full unified diff for a pull request."""
        url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}"
        logger.info("Fetching unified diff for PR #%d from %s", pr_number, self._repo)
        response = await self._get(url, accept=_ACCEPT_DIFF)
        return response.text

    async def get_file_content(self, file_path: str, ref: str) -> str:
        """Fetch the raw source content of a file at a specific commit ref."""
        url = f"{self._base_url}/repos/{self._repo}/contents/{file_path}"
        logger.debug("Fetching file content: %s@%s", file_path, ref[:8])
        response = await self._get(url, accept=_ACCEPT_RAW, params={"ref": ref})
        return response.text

    async def get_pull_request_files(self, pr_number: int) -> list[dict]:
        """Fetch list of files changed in a PR with pagination."""
        files: list[dict] = []
        page = 1
        per_page = 100

        while True:
            url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}/files"
            response = await self._get(
                url,
                accept=_ACCEPT_JSON,
                params={"per_page": per_page, "page": page},
            )
            batch: list[dict] = response.json()

            if not batch:
                break

            files.extend(batch)
            if len(files) >= settings.max_diff_files:
                files = files[: settings.max_diff_files]
                break

            if len(batch) < per_page:
                break

            page += 1

        return files

    async def create_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = "DeployGuard AI / Risk Gate",
        target_url: str | None = None,
    ) -> dict:
        """
        Create or update a commit status check on a PR's head commit.

        Args:
            sha: Full commit SHA of the PR head.
            state: Status check state: 'pending', 'success', 'failure', or 'error'.
            description: 1-sentence explanation displayed in the GitHub UI (max 140 chars).
            context: Status check label.
            target_url: Optional URL pointing to a detailed audit report.
        """
        url = f"{self._base_url}/repos/{self._repo}/statuses/{sha}"
        payload = {
            "state": state,
            "description": description[:140],
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url

        logger.info("Posting commit status '%s' for sha=%s: %s", state, sha[:8], description[:60])
        response = await self._post(url, json_data=payload)
        return response.json()

    async def try_get_file_content(self, file_path: str, ref: str) -> str | None:
        """Fetch raw source content of a file at ref, returning None if missing (e.g. new/deleted)."""
        try:
            return await self.get_file_content(file_path, ref)
        except GitHubAPIError as exc:
            if exc.status_code in (404, 422):
                return None
            raise

    async def get_repo_python_files(self, ref: str, max_files: int = 25) -> list[str]:
        """List up to ``max_files`` Python source paths from the repo tree at ``ref``."""
        try:
            url = f"{self._base_url}/repos/{self._repo}/git/trees/{ref}"
            response = await self._get(url, accept=_ACCEPT_JSON, params={"recursive": "1"})
            tree = response.json().get("tree", [])
            py_paths = [
                item["path"]
                for item in tree
                if item.get("type") == "blob"
                and str(item.get("path", "")).endswith(".py")
                and "/tests/" not in f"/{item.get('path', '')}"
                and not str(item.get("path", "")).startswith("tests/")
            ]
            return py_paths[:max_files]
        except Exception as exc:
            logger.debug("Could not list repo tree for %s@%s: %s", self._repo, ref[:8], exc)
            return []

    async def create_repository(
        self,
        name: str,
        description: str = "DeployGuard AI Sandbox Microservice",
        private: bool = False,
        auto_init: bool = True,
    ) -> dict[str, Any]:
        """Create a repository under the authenticated GitHub user."""
        url = f"{self._base_url}/user/repos"
        response = await self._post(
            url,
            json_data={
                "name": name,
                "description": description,
                "private": private,
                "auto_init": auto_init,
            },
        )
        return response.json()

    async def get_branch_sha(self, branch: str = "main") -> str:
        """Return head commit SHA for a branch."""
        url = f"{self._base_url}/repos/{self._repo}/git/ref/heads/{branch}"
        response = await self._get(url, accept=_ACCEPT_JSON)
        return response.json()["object"]["sha"]

    async def create_branch(self, branch_name: str, from_sha: str) -> dict[str, Any]:
        """Create a new git branch ref from a base SHA."""
        url = f"{self._base_url}/repos/{self._repo}/git/refs"
        response = await self._post(
            url,
            json_data={"ref": f"refs/heads/{branch_name}", "sha": from_sha},
        )
        return response.json()

    async def get_file_sha(self, file_path: str, ref: str) -> str | None:
        """Return blob SHA for a file at ``ref``, or None if missing."""
        try:
            url = f"{self._base_url}/repos/{self._repo}/contents/{file_path}"
            response = await self._get(url, accept=_ACCEPT_JSON, params={"ref": ref})
            data = response.json()
            return data.get("sha") if isinstance(data, dict) else None
        except GitHubAPIError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def create_or_update_file(
        self,
        file_path: str,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a file directly on a branch via GitHub Contents API."""
        url = f"{self._base_url}/repos/{self._repo}/contents/{file_path}"
        if sha is None:
            sha = await self.get_file_sha(file_path, branch)
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        response = await self._put(url, json_data=payload)
        return response.json()

    async def create_pull_request(
        self,
        title: str,
        head: str,
        base: str = "main",
        body: str = "",
    ) -> dict[str, Any]:
        """Open a real Pull Request on GitHub."""
        url = f"{self._base_url}/repos/{self._repo}/pulls"
        response = await self._post(
            url,
            json_data={"title": title, "head": head, "base": base, "body": body},
        )
        return response.json()

    async def create_pr_review(
        self,
        pr_number: int,
        event: str,
        body: str = "",
    ) -> dict[str, Any]:
        """Submit a real GitHub PR Review (APPROVE | REQUEST_CHANGES | COMMENT)."""
        url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}/reviews"
        payload: dict[str, str] = {"event": event.upper()}
        if body:
            payload["body"] = body
        response = await self._post(url, json_data=payload)
        return response.json()

    async def list_pr_reviews(self, pr_number: int) -> list[dict[str, Any]]:
        """List reviews submitted on a Pull Request."""
        url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}/reviews"
        response = await self._get(url, accept=_ACCEPT_JSON, params={"per_page": 30})
        data = response.json()
        return data if isinstance(data, list) else []

    async def list_collaborators(self) -> list[dict[str, Any]]:
        """List repository collaborators and their GitHub permissions."""
        url = f"{self._base_url}/repos/{self._repo}/collaborators"
        response = await self._get(url, accept=_ACCEPT_JSON, params={"per_page": 50})
        data = response.json()
        return data if isinstance(data, list) else []

    async def add_collaborator(self, username: str, permission: str = "push") -> dict[str, Any]:
        """Invite a GitHub collaborator with permission: pull | push | maintain | admin."""
        url = f"{self._base_url}/repos/{self._repo}/collaborators/{username}"
        response = await self._put(url, json_data={"permission": permission})
        if response.status_code == 204 or not response.text.strip():
            return {"username": username, "permission": permission, "status": "already_collaborator"}
        return response.json()

    async def remove_collaborator(self, username: str) -> None:
        """Remove a collaborator from the GitHub repository."""
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager.")
        url = f"{self._base_url}/repos/{self._repo}/collaborators/{username}"
        response = await self._client.delete(url, headers={"Accept": _ACCEPT_JSON})
        self._check_rate_limit(response)
        if response.is_error:
            self._handle_error(response, url)

    async def ensure_webhook(self, webhook_url: str, secret: str) -> dict[str, Any]:
        """Create or update the DeployGuard pull_request webhook on the repository."""
        hooks_url = f"{self._base_url}/repos/{self._repo}/hooks"
        existing_resp = await self._get(hooks_url, accept=_ACCEPT_JSON)
        hooks = existing_resp.json() if isinstance(existing_resp.json(), list) else []
        existing = next(
            (h for h in hooks if "/webhook/github" in str((h.get("config") or {}).get("url", ""))),
            None,
        )
        cfg = {
            "url": webhook_url,
            "content_type": "json",
            "secret": secret,
            "insecure_ssl": "0",
        }
        payload = {"name": "web", "active": True, "events": ["pull_request"], "config": cfg}
        if existing and existing.get("id"):
            resp = await self._patch(f"{hooks_url}/{existing['id']}", json_data={"active": True, "events": ["pull_request"], "config": cfg})
            return resp.json()
        resp = await self._post(hooks_url, json_data=payload)
        return resp.json()

    async def create_check_run(
        self,
        sha: str,
        conclusion: str,
        title: str,
        summary: str,
        name: str = "DeployGuard AI Risk Gate",
        details_url: str | None = None,
        annotations: list[dict] | None = None,
    ) -> dict:
        """
        Create a GitHub Check Run on the PR head commit.

        Automatically falls back to ``create_commit_status`` if the token does
        not carry ``checks:write`` permission (HTTP 403/404).
        """
        url = f"{self._base_url}/repos/{self._repo}/check-runs"
        output: dict[str, object] = {
            "title": title[:250],
            "summary": summary[:65000],
        }
        if annotations:
            output["annotations"] = annotations[:20]

        payload: dict[str, object] = {
            "name": name,
            "head_sha": sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": output,
        }
        if details_url:
            payload["details_url"] = details_url

        try:
            response = await self._post(url, json_data=payload)
            return response.json()
        except GitHubAPIError as exc:
            if exc.status_code in (403, 404, 422):
                logger.info(
                    "Check Runs API unavailable (%s); falling back to Commit Status.",
                    exc.status_code,
                )
                status_map = {
                    "success": "success",
                    "neutral": "success",
                    "action_required": "success",
                    "failure": "failure",
                }
                return await self.create_commit_status(
                    sha=sha,
                    state=status_map.get(conclusion, "success"),
                    description=title[:140],
                    target_url=details_url,
                )
            raise

    async def post_pr_comment(self, pr_number: int, body: str) -> dict:
        """Post a Markdown review comment on a Pull Request."""
        url = f"{self._base_url}/repos/{self._repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        logger.info("Posting review comment on PR #%d (chars=%d)...", pr_number, len(body))
        response = await self._post(url, json_data=payload)
        return response.json()

    async def upsert_pr_comment(
        self,
        pr_number: int,
        body: str,
        marker: str = "<!-- deployguard-ai-report -->",
    ) -> dict:
        """Create or update the existing DeployGuard bot summary comment on a PR."""
        marked_body = body if marker in body else f"{marker}\n{body}"
        try:
            list_url = f"{self._base_url}/repos/{self._repo}/issues/{pr_number}/comments"
            resp = await self._get(list_url, accept=_ACCEPT_JSON, params={"per_page": 50})
            comments = resp.json() if isinstance(resp.json(), list) else []
            existing = next(
                (c for c in comments if marker in (c.get("body") or "")),
                None,
            )
            if existing and existing.get("id"):
                patch_url = f"{self._base_url}/repos/{self._repo}/issues/comments/{existing['id']}"
                updated = await self._patch(patch_url, json_data={"body": marked_body})
                return updated.json()
        except Exception as exc:
            logger.debug("Upsert comment lookup fallback to post: %s", exc)
        return await self.post_pr_comment(pr_number=pr_number, body=marked_body)

    async def list_pull_requests(self, state: str = "open") -> list[dict]:
        """Fetch list of pull requests for the repository."""
        url = f"{self._base_url}/repos/{self._repo}/pulls"
        response = await self._get(url, accept=_ACCEPT_JSON, params={"state": state, "per_page": 30})
        return response.json()

    async def get_pull_request(self, pr_number: int) -> dict:
        """Fetch detailed information for a single pull request."""
        url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}"
        response = await self._get(url, accept=_ACCEPT_JSON)
        return response.json()

    async def merge_pull_request(
        self,
        pr_number: int,
        commit_title: str | None = None,
        commit_message: str | None = None,
        merge_method: str = "squash",
    ) -> dict:
        """
        Merge a pull request via GitHub REST API.

        Args:
            pr_number: Number of the pull request to merge.
            commit_title: Title for the merge commit (optional).
            commit_message: Extra detail for the merge commit (optional).
            merge_method: Merge method: 'merge', 'squash', or 'rebase'.
        """
        url = f"{self._base_url}/repos/{self._repo}/pulls/{pr_number}/merge"
        payload: dict[str, str] = {"merge_method": merge_method}
        if commit_title:
            payload["commit_title"] = commit_title
        if commit_message:
            payload["commit_message"] = commit_message

        logger.info("Merging PR #%d on %s via method=%s...", pr_number, self._repo, merge_method)
        response = await self._put(url, json_data=payload)
        return response.json()

    async def list_user_repositories(self) -> list[dict]:
        """Fetch repositories accessible by the current authenticated user/token."""
        url = f"{self._base_url}/user/repos"
        response = await self._get(url, accept=_ACCEPT_JSON, params={"sort": "updated", "per_page": 50})
        return response.json()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        """Construct standard headers sent with every request."""
        headers = {
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"DeployGuard-AI/{settings.app_name}",
        }
        if self._token and not self._token.startswith("ghp_dev_mock"):
            headers["Authorization"] = f"Bearer {self._token}"
        elif self._token and "api.github.com" not in self._base_url:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _patch(
        self,
        url: str,
        json_data: dict,
        accept: str = _ACCEPT_JSON,
    ) -> httpx.Response:
        """Internal PATCH request helper with error handling."""
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager.")

        response = await self._client.patch(
            url,
            headers={"Accept": accept},
            json=json_data,
        )
        self._check_rate_limit(response)

        if response.is_error:
            self._handle_error(response, url)

        return response

    async def _get(
        self,
        url: str,
        accept: str,
        params: dict | None = None,
    ) -> httpx.Response:
        """Internal GET request helper with error handling."""
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager.")

        response = await self._client.get(
            url,
            headers={"Accept": accept},
            params=params,
        )
        self._check_rate_limit(response)

        if response.is_error:
            self._handle_error(response, url)

        return response

    async def _post(
        self,
        url: str,
        json_data: dict,
        accept: str = _ACCEPT_JSON,
    ) -> httpx.Response:
        """Internal POST request helper with error handling."""
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager.")

        response = await self._client.post(
            url,
            headers={"Accept": accept},
            json=json_data,
        )
        self._check_rate_limit(response)

        if response.is_error:
            self._handle_error(response, url)

        return response

    async def _put(
        self,
        url: str,
        json_data: dict,
        accept: str = _ACCEPT_JSON,
    ) -> httpx.Response:
        """Internal PUT request helper with error handling."""
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager.")

        response = await self._client.put(
            url,
            headers={"Accept": accept},
            json=json_data,
        )
        self._check_rate_limit(response)

        if response.is_error:
            self._handle_error(response, url)

        return response

    def _check_rate_limit(self, response: httpx.Response) -> None:
        """Inspect rate limit header and warn if getting low."""
        remaining = response.headers.get(_RATE_LIMIT_REMAINING_HEADER)
        if remaining is not None and int(remaining) < _RATE_LIMIT_LOW_THRESHOLD:
            logger.warning("GitHub API rate limit is low: %s requests remaining.", remaining)

    def _handle_error(self, response: httpx.Response, url: str) -> None:
        """Raise appropriate typed exceptions on HTTP error responses."""
        if response.status_code == 429 or (
            response.status_code == 403 and "rate limit" in response.text.lower()
        ):
            raise GitHubRateLimitError(
                "GitHub API rate limit exceeded. Retry after the reset window.",
                status_code=response.status_code,
                response_body=response.text,
            )
        raise GitHubAPIError(
            f"GitHub API returned HTTP {response.status_code} for URL: {url}",
            status_code=response.status_code,
            response_body=response.text[:500],
        )
