"""
models/webhook.py — Pydantic models for inbound GitHub webhook payloads.

Only the fields DeployGuard AI actually uses are modelled here; all other
GitHub fields are silently ignored via ``model_config = {"extra": "ignore"}``.
This makes the models forward-compatible with future GitHub API additions
without requiring code changes.

Reference:
    https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class PRAction(StrEnum):
    """
    Subset of GitHub pull_request event actions that DeployGuard AI acts on.

    Other actions (e.g. ``labeled``, ``assigned``) are intentionally excluded;
    the webhook router will silently acknowledge and skip them.
    """

    OPENED = "opened"
    SYNCHRONIZE = "synchronize"
    REOPENED = "reopened"
    READY_FOR_REVIEW = "ready_for_review"


class UserInfo(BaseModel):
    """Minimal representation of a GitHub user object."""

    model_config = {"extra": "ignore"}

    login: str = Field(..., description="GitHub username of the actor.")
    id: int = Field(..., description="GitHub internal user ID.")
    html_url: HttpUrl = Field(..., description="Profile URL.")


class RepoInfo(BaseModel):
    """Minimal representation of a GitHub repository object."""

    model_config = {"extra": "ignore"}

    id: int = Field(..., description="GitHub internal repository ID.")
    full_name: str = Field(
        ...,
        description="Owner/repo format, e.g. 'acme-corp/payments-service'.",
        examples=["acme-corp/payments-service"],
    )
    default_branch: str = Field(default="main", description="The repository's default branch.")
    private: bool = Field(..., description="Whether the repository is private.")
    html_url: HttpUrl = Field(..., description="Web URL of the repository.")


class BranchRef(BaseModel):
    """Represents one side (head or base) of a pull request."""

    model_config = {"extra": "ignore"}

    label: str = Field(..., description="'owner:branch' formatted label.")
    ref: str = Field(..., description="Branch name.")
    sha: str = Field(..., description="Full commit SHA at the tip of this branch.")
    repo: RepoInfo = Field(..., description="Repository this branch belongs to.")


class PRInfo(BaseModel):
    """
    Core pull request metadata extracted from the GitHub webhook payload.

    This is the authoritative data structure passed through the entire
    DeployGuard pipeline for a single analysis run.
    """

    model_config = {"extra": "ignore"}

    number: int = Field(..., description="Pull request number within the repository.", ge=1)
    title: str = Field(..., description="Human-readable PR title.")
    body: str | None = Field(default=None, description="PR description body (Markdown). May be null.")
    state: str = Field(..., description="'open', 'closed', or 'merged'.")
    draft: bool = Field(default=False, description="Whether the PR is a draft.")
    html_url: HttpUrl = Field(..., description="Web URL of the pull request.")

    user: UserInfo = Field(..., description="Author of the pull request.")
    head: BranchRef = Field(..., description="The feature branch being merged in.")
    base: BranchRef = Field(..., description="The target branch (typically main/master).")

    commits: int = Field(..., description="Number of commits in the PR.", ge=0)
    additions: int = Field(..., description="Total lines added across all files.", ge=0)
    deletions: int = Field(..., description="Total lines deleted across all files.", ge=0)
    changed_files: int = Field(..., description="Number of files changed.", ge=0)

    diff_url: HttpUrl = Field(..., description="URL to fetch the unified diff.")
    patch_url: HttpUrl = Field(..., description="URL to fetch the patch.")

    @property
    def head_sha(self) -> str:
        """Short-hand accessor for the head commit SHA."""
        return self.head.sha

    @property
    def repo_full_name(self) -> str:
        """Short-hand accessor for owner/repo."""
        return self.head.repo.full_name


class GitHubPullRequestPayload(BaseModel):
    """
    Top-level model for a GitHub ``pull_request`` webhook event.

    GitHub sends this as the JSON body when any pull_request action occurs.
    DeployGuard only processes a subset of actions defined in ``PRAction``.
    """

    model_config = {"extra": "ignore"}

    action: str = Field(
        ...,
        description="The specific pull_request event action (e.g. 'opened', 'synchronize').",
    )
    number: int = Field(..., description="PR number — mirrors pull_request.number for quick access.", ge=1)
    pull_request: PRInfo = Field(..., description="Full pull request object.")
    repository: RepoInfo = Field(..., description="Repository the PR belongs to.")
    sender: UserInfo = Field(..., description="GitHub user who triggered the event.")

    @property
    def is_actionable(self) -> bool:
        """
        Return ``True`` if this payload should trigger a DeployGuard analysis.

        Draft PRs are intentionally skipped — they are not yet ready for
        gate enforcement and would produce noisy block decisions.
        """
        try:
            actionable_action = self.action in {a.value for a in PRAction}
        except Exception:
            actionable_action = False
        return actionable_action and not self.pull_request.draft

