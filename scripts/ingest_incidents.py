"""
scripts/ingest_incidents.py — Seed historical incident documents with embeddings.

Populates the ``incidents`` collection with historical post-mortems for
Atlas Vector Search ($vectorSearch).

If an OpenAI API key is configured, uses ``text-embedding-3-small`` (1536-dim)
to generate high-fidelity vector embeddings. If no key is set, generates
synthetic deterministic 1536-dim vectors so local development and testing
can proceed without an external OpenAI account.

Run:
    python scripts/ingest_incidents.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import math
from pathlib import Path
import sys
from typing import Any

# Ensure repository root is in Python path for direct script invocation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from motor.motor_asyncio import AsyncIOMotorClient

from deployguard.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ingest_incidents")

SAMPLE_INCIDENTS: list[dict[str, Any]] = [
    {
        "incident_id": "INC-2024-0317",
        "title": "Payment retry storm caused 40-minute checkout outage",
        "severity": "P0",
        "duration_minutes": 40,
        "affected_service": "payment-service",
        "root_cause_tags": ["retry-logic", "payment", "thundering-herd", "timeout"],
        "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-0317",
        "description": (
            "A refactoring to payment retry logic increased retry attempts without exponential backoff "
            "or jitter, triggering a thundering-herd cascade that overwhelmed downstream database connections."
        ),
    },
    {
        "incident_id": "INC-2024-0522",
        "title": "Order service database connection pool starvation under load",
        "severity": "P0",
        "duration_minutes": 65,
        "affected_service": "order-service",
        "root_cause_tags": ["connection-pool", "database", "deadlock", "order"],
        "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-0522",
        "description": (
            "Synchronous nested transactions in create_order consumed all available connection slots, "
            "blocking concurrent cart operations across all commerce clusters."
        ),
    },
    {
        "incident_id": "INC-2024-0809",
        "title": "Subscription billing ledger drift due to unhandled API exception",
        "severity": "P1",
        "duration_minutes": 120,
        "affected_service": "subscription-billing",
        "root_cause_tags": ["billing", "ledger", "exception-handling", "drift"],
        "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-0809",
        "description": (
            "An unhandled TimeoutException when calling payment_service resulted in renewal records "
            "being marked active without corresponding ledger credit entries."
        ),
    },
    {
        "incident_id": "INC-2024-0914",
        "title": "Fraud detection model timeout degraded checkout response latency by 3x",
        "severity": "P1",
        "duration_minutes": 25,
        "affected_service": "fraud-detection",
        "root_cause_tags": ["fraud", "latency", "timeout", "model-inference"],
        "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-0914",
        "description": (
            "A new feature extraction step in evaluate_risk did not implement an aggressive fallback timeout, "
            "causing checkout requests to block up to 5 seconds during peak volume."
        ),
    },
    {
        "incident_id": "INC-2024-1002",
        "title": "Notification service rate limit exhaustion blocked customer 2FA emails",
        "severity": "P2",
        "duration_minutes": 15,
        "affected_service": "notification-service",
        "root_cause_tags": ["notification", "rate-limit", "email", "2fa"],
        "postmortem_url": "https://wiki.acme.com/postmortems/INC-2024-1002",
        "description": (
            "Marketing email blast saturated the unified SES quota, delaying transactional 2FA OTP delivery."
        ),
    },
]


def _generate_synthetic_embedding(text: str, dimensions: int = 1536) -> list[float]:
    """
    Generate a deterministic synthetic 1536-dim normalized vector from text hash.
    Used when no OpenAI API key is supplied.
    """
    vector = []
    for i in range(dimensions):
        h = hashlib.sha256(f"{text}:{i}".encode("utf-8")).digest()
        val = int.from_bytes(h[:4], "little", signed=True) / (2**31)
        vector.append(val)

    # L2 normalize
    norm = math.sqrt(sum(x * x for x in vector)) or 1.0
    return [round(x / norm, 6) for x in vector]


async def _get_embedding(text: str) -> list[float]:
    """Fetch real embedding from OpenAI if key is set, else fallback to synthetic."""
    api_key = settings.openai_api_key.get_secret_value()
    if api_key and not api_key.startswith("your-") and not api_key.startswith("sk-placeholder"):
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=api_key)
            resp = await client.embeddings.create(
                model=settings.openai_embedding_model,
                input=text,
                encoding_format="float",
            )
            await client.close()
            return resp.data[0].embedding
        except Exception as exc:
            logger.warning("OpenAI API call failed (%s); using synthetic embedding fallback.", exc)

    return _generate_synthetic_embedding(text)


async def ingest() -> None:
    uri = settings.mongodb_uri.get_secret_value()
    db_name = settings.mongodb_db_name
    collection_name = settings.mongodb_incidents_collection

    logger.info("Connecting to MongoDB (%s)...", db_name)
    client = AsyncIOMotorClient(uri)
    db = client[db_name]
    collection = db[collection_name]

    count = 0
    for inc in SAMPLE_INCIDENTS:
        embed_text = f"{inc['title']}. {inc['description']}. Tags: {', '.join(inc['root_cause_tags'])}"
        logger.info("  Generating embedding for incident %s...", inc["incident_id"])
        embedding = await _get_embedding(embed_text)

        doc = {
            "incident_id": inc["incident_id"],
            "title": inc["title"],
            "severity": inc["severity"],
            "duration_minutes": inc["duration_minutes"],
            "affected_service": inc["affected_service"],
            "root_cause_tags": inc["root_cause_tags"],
            "postmortem_url": inc["postmortem_url"],
            "description": inc["description"],
            "embedding": embedding,
            "created_at": datetime.now(timezone.utc),
        }

        await collection.update_one(
            {"incident_id": doc["incident_id"]},
            {"$set": doc},
            upsert=True,
        )
        count += 1
        logger.info("  ✓ Seeded incident: %s (Severity: %s, Similarity Vector: 1536d)", inc["incident_id"], inc["severity"])

    logger.info("🎉 Successfully ingested %d historical incident records into '%s'.", count, collection_name)
    client.close()


if __name__ == "__main__":
    asyncio.run(ingest())

