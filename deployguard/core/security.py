"""
core/security.py — HMAC-SHA256 webhook signature verification.

GitHub signs every webhook payload with a secret token using HMAC-SHA256.
The signature is sent in the ``X-Hub-Signature-256`` request header in the
format ``sha256=<hex-digest>``.

Security contract:
    - Verification uses ``hmac.compare_digest`` for constant-time comparison,
      which prevents timing-based oracle attacks.
    - The raw request body (bytes) must be used for verification — NOT a
      decoded / re-encoded form, as any whitespace normalization would break
      the signature.
    - If the header is absent or the signature is invalid, a 403 Forbidden
      response is returned immediately.

Reference:
    https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from deployguard.exceptions import WebhookSignatureError

logger = logging.getLogger(__name__)


def verify_github_signature(
    payload_bytes: bytes,
    signature_header: str | None,
    secret: str,
) -> None:
    """
    Verify a GitHub webhook HMAC-SHA256 payload signature.

    This function is a **pure security gate** — it raises on failure and
    returns ``None`` on success.  The caller is responsible for converting
    the raised exception into an appropriate HTTP response.

    Args:
        payload_bytes:
            The raw, unmodified bytes of the HTTP request body.  Must be
            read *before* any JSON parsing so no transformation has occurred.
        signature_header:
            The value of the ``X-Hub-Signature-256`` HTTP header as received
            from GitHub.  Expected format: ``"sha256=<64-char-hex-string>"``.
            If ``None``, the request has no signature and is rejected.
        secret:
            The webhook secret token configured in GitHub (plain-text string).
            This is compared against the expected HMAC; it is never logged.

    Raises:
        WebhookSignatureError:
            - If ``signature_header`` is ``None`` or empty.
            - If the header does not start with the ``sha256=`` prefix.
            - If the computed HMAC does not match the provided signature.

    Example::

        # Inside a FastAPI dependency
        try:
            verify_github_signature(body, request.headers.get("X-Hub-Signature-256"), secret)
        except WebhookSignatureError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    """
    if not signature_header:
        raise WebhookSignatureError(
            "Missing 'X-Hub-Signature-256' header. "
            "All webhook requests must include a valid HMAC signature."
        )

    if not signature_header.startswith("sha256="):
        raise WebhookSignatureError(
            f"Malformed signature header '{signature_header}'. "
            "Expected format: 'sha256=<hex-digest>'."
        )

    received_hex: str = signature_header[len("sha256="):]

    # Compute the expected HMAC using the shared secret
    computed_hmac = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256,
    )
    expected_hex: str = computed_hmac.hexdigest()

    # Constant-time comparison to prevent timing oracle attacks
    if not hmac.compare_digest(expected_hex, received_hex):
        # Log the failure without revealing either digest value
        logger.warning(
            "Webhook signature mismatch detected. "
            "Payload rejected. Check that the webhook secret is correctly configured."
        )
        raise WebhookSignatureError(
            "Webhook signature verification failed. "
            "The computed HMAC does not match the 'X-Hub-Signature-256' header."
        )

    logger.debug("Webhook signature verified successfully.")


def extract_event_type(event_header: str | None) -> str:
    """
    Extract and validate the GitHub event type from the ``X-GitHub-Event``
    header.

    Args:
        event_header:
            Value of the ``X-GitHub-Event`` header.

    Returns:
        The lowercase event type string (e.g. ``"pull_request"``).

    Raises:
        WebhookSignatureError:
            If the header is absent or empty — indicates the request did not
            originate from GitHub.
    """
    if not event_header:
        raise WebhookSignatureError(
            "Missing 'X-GitHub-Event' header. "
            "All legitimate GitHub webhooks include this header."
        )
    return event_header.strip().lower()

