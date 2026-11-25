"""
tests/unit/test_crypto.py — Unit tests for at-rest token encryption.
"""

from __future__ import annotations

import pytest

from deployguard.core.crypto import decrypt_secret, encrypt_secret


def test_encrypt_decrypt_roundtrip():
    token = "ghp_superSecretGitHubTokenValue123456"
    enc = encrypt_secret(token)
    assert enc is not None
    assert enc.startswith("enc:v1:")
    assert token not in enc
    assert decrypt_secret(enc) == token


def test_encryption_uses_unique_nonce():
    token = "ghp_sameTokenTwice"
    enc1 = encrypt_secret(token)
    enc2 = encrypt_secret(token)
    assert enc1 != enc2
    assert decrypt_secret(enc1) == token
    assert decrypt_secret(enc2) == token


def test_encrypt_is_idempotent_and_handles_empty():
    assert encrypt_secret(None) is None
    assert encrypt_secret("") == ""
    assert decrypt_secret(None) is None
    assert decrypt_secret("") == ""

    enc = encrypt_secret("ghp_abc")
    assert encrypt_secret(enc) == enc


def test_decrypt_backwards_compatible_with_legacy_plaintext():
    legacy = "ghp_legacy_unencrypted_token"
    assert decrypt_secret(legacy) == legacy


def test_decrypt_detects_tampering():
    enc = encrypt_secret("ghp_sensitive_token")
    assert enc is not None
    parts = enc.split(":")
    # Corrupt one character of the ciphertext/MAC segment
    corrupted_tag = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
    tampered = ":".join([*parts[:-1], corrupted_tag])
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_secret(tampered)
