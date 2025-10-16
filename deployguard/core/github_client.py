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

import logging
from typing import Final

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

    def __init__(self, repo_full_name: str, timeout_seconds: float = 30.0) -> None:
        self._repo = repo_full_name
        self._base_url = str(settings.github_api_base_url).rstrip("/")
        self._timeout = httpx.Timeout(timeout=timeout_seconds)
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

    async def post_pr_comment(self, pr_number: int, body: str) -> dict:
        """Post a Markdown review comment on a Pull Request."""
        url = f"{self._base_url}/repos/{self._repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        logger.info("Posting review comment on PR #%d (chars=%d)...", pr_number, len(body))
        response = await self._post(url, json_data=payload)
        return response.json()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        """Construct standard headers sent with every request."""
        return {
            "Authorization": f"Bearer {settings.github_api_token.get_secret_value()}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"DeployGuard-AI/{settings.app_name}",
        }

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
