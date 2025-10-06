"""
exceptions/__init__.py — Custom exception hierarchy for DeployGuard AI.

All application-specific exceptions inherit from ``DeployGuardError`` so
callers can catch the entire family with a single ``except`` clause when
needed.
"""

from __future__ import annotations


class DeployGuardError(Exception):
    """Base class for all DeployGuard AI application exceptions."""


# ---------------------------------------------------------------------------
# Security / Webhook Ingestion
# ---------------------------------------------------------------------------


class WebhookSignatureError(DeployGuardError):
    """
    Raised when a GitHub webhook payload fails HMAC-SHA256 signature
    verification.  This is a hard security boundary — the request must be
    rejected immediately.
    """


class WebhookPayloadError(DeployGuardError):
    """
    Raised when the webhook payload is structurally invalid (e.g. missing
    required fields, wrong event type, or exceeds the maximum allowed size).
    """


# ---------------------------------------------------------------------------
# GitHub API Client
# ---------------------------------------------------------------------------


class GitHubAPIError(DeployGuardError):
    """
    Raised when the GitHub REST API returns an unexpected status code or the
    response body cannot be parsed.

    Attributes:
        status_code: HTTP status code returned by GitHub.
        response_body: Raw response text for debugging.
    """

    def __init__(self, message: str, status_code: int | None = None, response_body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GitHubRateLimitError(GitHubAPIError):
    """Raised when GitHub API rate limit is exceeded (HTTP 429 / 403 with rate limit header)."""


# ---------------------------------------------------------------------------
# Diff Parsing
# ---------------------------------------------------------------------------


class DiffParseError(DeployGuardError):
    """
    Raised when the unified diff string cannot be parsed — typically because
    it is malformed or uses an unsupported extended diff format.
    """


# ---------------------------------------------------------------------------
# AST Analysis
# ---------------------------------------------------------------------------


class ASTAnalysisError(DeployGuardError):
    """
    Raised when Python AST parsing fails for a given source file.

    Attributes:
        filename: The file that caused the parse failure.
        original_error: The underlying ``SyntaxError`` or other exception.
    """

    def __init__(self, message: str, filename: str = "", original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.filename = filename
        self.original_error = original_error

