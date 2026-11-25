"""
core/crypto.py — Authenticated symmetric encryption for secrets stored at rest.

Encrypts user GitHub Personal Access Tokens and OAuth tokens before persistence
in MongoDB using Encrypt-then-MAC (SHA-256 CTR stream cipher + HMAC-SHA256 tag)
with zero third-party native dependencies.

Format:
    enc:v1:<nonce_b64url>:<ciphertext_b64url>:<hmac_b64url>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Final

_PREFIX: Final[str] = "enc:v1:"
_DEFAULT_DEV_KEY: Final[str] = "deployguard-secret-change-in-prod-32chars"


def _get_master_secret() -> bytes:
    """Resolve the master secret used for token encryption key derivation."""
    raw = (
        os.environ.get("TOKEN_ENCRYPTION_KEY")
        or os.environ.get("JWT_SECRET_KEY")
        or _DEFAULT_DEV_KEY
    )
    return raw.encode("utf-8")


def _derive_keys(master_secret: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Derive independent encryption and MAC subkeys from master secret + nonce."""
    enc_key = hmac.new(master_secret, b"dg-enc-v1:" + nonce, hashlib.sha256).digest()
    mac_key = hmac.new(master_secret, b"dg-mac-v1:" + nonce, hashlib.sha256).digest()
    return enc_key, mac_key


def _keystream_xor(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Generate a deterministic SHA-256 counter-mode keystream and XOR with data."""
    out = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        block = hashlib.sha256(
            enc_key + nonce + counter.to_bytes(4, "big")
        ).digest()
        chunk_len = min(32, len(data) - offset)
        for i in range(chunk_len):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += chunk_len
        counter += 1
    return bytes(out)


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def encrypt_secret(plaintext: str | None) -> str | None:
    """
    Encrypt a plaintext secret (e.g., GitHub PAT) for safe storage in MongoDB.

    Returns ``None`` or empty string unchanged if empty. Already-encrypted strings
    (prefixed with ``enc:v1:``) are returned as-is to prevent double encryption.
    """
    if not plaintext:
        return plaintext
    if plaintext.startswith(_PREFIX):
        return plaintext

    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(_get_master_secret(), nonce)
    ct = _keystream_xor(enc_key, nonce, plaintext.encode("utf-8"))
    tag = hmac.new(mac_key, b"enc:v1:" + nonce + ct, hashlib.sha256).digest()
    return f"{_PREFIX}{_b64e(nonce)}:{_b64e(ct)}:{_b64e(tag)}"


def decrypt_secret(stored: str | None) -> str | None:
    """
    Decrypt a stored secret encrypted by ``encrypt_secret``.

    For backwards compatibility with pre-encryption database records, values not
    prefixed with ``enc:v1:`` are returned as-is. Values with the prefix are
    HMAC-verified before decryption and raise ``ValueError`` on tampering.
    """
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        return stored

    body = stored[len(_PREFIX):]
    parts = body.split(":")
    if len(parts) != 3:
        raise ValueError("Malformed encrypted token payload.")

    nonce = _b64d(parts[0])
    ct = _b64d(parts[1])
    tag = _b64d(parts[2])

    enc_key, mac_key = _derive_keys(_get_master_secret(), nonce)
    expected_tag = hmac.new(mac_key, b"enc:v1:" + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Encrypted token authentication failed (invalid key or tampered data).")

    plaintext_bytes = _keystream_xor(enc_key, nonce, ct)
    return plaintext_bytes.decode("utf-8")
