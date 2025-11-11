"""
scripts/test_live_api.py — Executes live API requests against the FastAPI server.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sys

# Ensure repository root is in Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from starlette.testclient import TestClient

from deployguard.api.main import create_app
from deployguard.config import settings


def run_api_tests() -> None:
    print("=" * 80)
    print("🚀 DEPLOYGUARD AI — LIVE FASTAPI ENDPOINT EXECUTION")
    print("=" * 80)

    app = create_app()
    client = TestClient(app)

    # 1. Healthz probe
    print("\n[1] Testing GET /healthz (Liveness Probe)...")
    res = client.get("/healthz")
    print(f"    Status: {res.status_code}")
    print(f"    Body:   {res.json()}")
    assert res.status_code == 200

    # 2. Readyz probe
    print("\n[2] Testing GET /readyz (Readiness Probe)...")
    res = client.get("/readyz")
    print(f"    Status: {res.status_code}")
    print(f"    Body:   {res.json()}")

    # 3. Security: Webhook without signature (Expect 403)
    print("\n[3] Testing POST /webhook/github without HMAC signature (Security Gate)...")
    res = client.post("/webhook/github", json={"test": "data"})
    print(f"    Status: {res.status_code}")
    print(f"    Body:   {res.json()}")
    assert res.status_code == 403

    # 4. Security: Webhook with invalid signature (Expect 403)
    print("\n[4] Testing POST /webhook/github with invalid HMAC signature...")
    res = client.post(
        "/webhook/github",
        content=b'{"test": "data"}',
        headers={
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Event": "pull_request",
        },
    )
    print(f"    Status: {res.status_code}")
    print(f"    Body:   {res.json()}")
    assert res.status_code == 403

    # 5. Legitimate GitHub Pull Request Webhook (Expect 202 Accepted)
    print("\n[5] Testing POST /webhook/github with VALID HMAC-SHA256 signature...")
    secret = settings.github_webhook_secret.get_secret_value()

    payload_dict = {
        "action": "opened",
        "number": 4821,
        "pull_request": {
            "number": 4821,
            "title": "refactor: optimize charge_card retry logic with exponential backoff",
            "body": "Implements exponential backoff to address retry spikes.",
            "state": "open",
            "draft": False,
            "html_url": "https://github.com/acme/payment-service/pull/4821",
            "user": {
                "login": "elena.vasquez",
                "id": 1049281,
                "html_url": "https://github.com/elena.vasquez",
            },
            "head": {
                "label": "acme:feat/backoff",
                "ref": "feat/backoff",
                "sha": "c7d3e8f1a2b5094d6e810a992bc",
                "repo": {
                    "id": 839102,
                    "full_name": "acme/payment-service",
                    "default_branch": "main",
                    "private": True,
                    "html_url": "https://github.com/acme/payment-service",
                },
            },
            "base": {
                "label": "acme:main",
                "ref": "main",
                "sha": "a1b2c3d4e5f60718293a",
                "repo": {
                    "id": 839102,
                    "full_name": "acme/payment-service",
                    "default_branch": "main",
                    "private": True,
                    "html_url": "https://github.com/acme/payment-service",
                },
            },
            "commits": 2,
            "additions": 14,
            "deletions": 3,
            "changed_files": 1,
            "diff_url": "https://github.com/acme/payment-service/pull/4821.diff",
            "patch_url": "https://github.com/acme/payment-service/pull/4821.patch",
        },
        "repository": {
            "id": 839102,
            "full_name": "acme/payment-service",
            "default_branch": "main",
            "private": True,
            "html_url": "https://github.com/acme/payment-service",
        },
        "sender": {
            "login": "elena.vasquez",
            "id": 1049281,
            "html_url": "https://github.com/elena.vasquez",
        },
    }

    raw_payload_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw_payload_bytes, hashlib.sha256).hexdigest()

    res = client.post(
        "/webhook/github",
        content=raw_payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": f"sha256={sig}",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "7b8e1f0a-3c4d-4e5f-9a1b-0c2d3e4f5a6b",
        },
    )

    print(f"    Status: {res.status_code} (Accepted & Enqueued)")
    print(f"    Body:   {json.dumps(res.json(), indent=4)}")
    assert res.status_code == 202

    print("\n" + "=" * 80)
    print("✅ ALL LIVE FASTAPI ENDPOINT TESTS PASSED WITH 100% SUCCESS")
    print("=" * 80)


if __name__ == "__main__":
    run_api_tests()

