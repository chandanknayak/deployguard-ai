"""
tests/unit/test_security.py — Unit tests for HMAC-SHA256 webhook signature verification.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from deployguard.core.security import extract_event_type, verify_github_signature
from deployguard.exceptions import WebhookSignatureError

SECRET = "test-webhook-secret-abc123"
PAYLOAD = b'{"action": "opened", "number": 42}'


def _make_signature(payload: bytes, secret: str) -> str:
    """Helper: compute a valid HMAC-SHA256 signature."""
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class TestVerifyGithubSignature:
    def test_valid_signature_passes(self) -> None:
        sig = _make_signature(PAYLOAD, SECRET)
        # Should not raise
        verify_github_signature(PAYLOAD, sig, SECRET)

    def test_missing_header_raises(self) -> None:
        with pytest.raises(WebhookSignatureError, match="Missing"):
            verify_github_signature(PAYLOAD, None, SECRET)

    def test_empty_header_raises(self) -> None:
        with pytest.raises(WebhookSignatureError):
            verify_github_signature(PAYLOAD, "", SECRET)

    def test_wrong_prefix_raises(self) -> None:
        sig = _make_signature(PAYLOAD, SECRET).replace("sha256=", "sha1=")
        with pytest.raises(WebhookSignatureError, match="Malformed"):
            verify_github_signature(PAYLOAD, sig, SECRET)

    def test_tampered_payload_raises(self) -> None:
        sig = _make_signature(PAYLOAD, SECRET)
        tampered = PAYLOAD + b"EXTRA"
        with pytest.raises(WebhookSignatureError, match="verification failed"):
            verify_github_signature(tampered, sig, SECRET)

    def test_wrong_secret_raises(self) -> None:
        sig = _make_signature(PAYLOAD, "wrong-secret")
        with pytest.raises(WebhookSignatureError):
            verify_github_signature(PAYLOAD, sig, SECRET)

    def test_tampered_signature_raises(self) -> None:
        sig = "sha256=" + "a" * 64  # Valid format, wrong digest
        with pytest.raises(WebhookSignatureError):
            verify_github_signature(PAYLOAD, sig, SECRET)


class TestExtractEventType:
    def test_returns_lowercase_event_type(self) -> None:
        result = extract_event_type("pull_request")
        assert result == "pull_request"

    def test_strips_whitespace(self) -> None:
        result = extract_event_type("  push  ")
        assert result == "push"

    def test_none_header_raises(self) -> None:
        with pytest.raises(WebhookSignatureError, match="Missing"):
            extract_event_type(None)

    def test_empty_string_raises(self) -> None:
        with pytest.raises(WebhookSignatureError):
            extract_event_type("")

