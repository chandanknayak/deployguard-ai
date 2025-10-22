"""
scripts/seed_graph.py — Seed the MongoDB code dependency graph with sample microservices.

Populates the ``code_graph`` collection with nodes and downstream dependency edges,
enabling $graphLookup blast radius queries right out of the box.

Run:
    python scripts/seed_graph.py
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import sys
from typing import Any

# Ensure repository root is in Python path for direct script invocation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from motor.motor_asyncio import AsyncIOMotorClient

from deployguard.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_graph")

# Realistic enterprise microservices dependency graph
SAMPLE_SERVICES: list[dict[str, Any]] = [
    {
        "service_name": "payment-service",
        "symbol": "payment_service.charge_card",
        "sla_tier": "P0",
        "owner_team": "billing-infra",
        "on_call_email": "billing-oncall@acme.com",
        "language": "python",
        "repo": "acme/payment-service",
        "status": "active",
        "downstream_services": ["order-service", "fraud-detection", "vault-service"],
    },
    {
        "service_name": "order-service",
        "symbol": "order_service.create_order",
        "sla_tier": "P0",
        "owner_team": "commerce-platform",
        "on_call_email": "commerce-oncall@acme.com",
        "language": "python",
        "repo": "acme/order-service",
        "status": "active",
        "downstream_services": ["inventory-service", "notification-service"],
    },
    {
        "service_name": "subscription-billing",
        "symbol": "subscription_billing.renew_subscription",
        "sla_tier": "P0",
        "owner_team": "billing-infra",
        "on_call_email": "billing-oncall@acme.com",
        "language": "python",
        "repo": "acme/subscription-billing",
        "status": "active",
        "downstream_services": ["payment-service", "ledger-service"],
    },
    {
        "service_name": "fraud-detection",
        "symbol": "fraud_detection.evaluate_risk",
        "sla_tier": "P1",
        "owner_team": "trust-safety",
        "on_call_email": "fraud-oncall@acme.com",
        "language": "python",
        "repo": "acme/fraud-detection",
        "status": "active",
        "downstream_services": ["user-profile-service"],
    },
    {
        "service_name": "vault-service",
        "symbol": "vault_service.tokenize_card",
        "sla_tier": "P0",
        "owner_team": "security-infra",
        "on_call_email": "sec-oncall@acme.com",
        "language": "python",
        "repo": "acme/vault-service",
        "status": "active",
        "downstream_services": [],
    },
    {
        "service_name": "inventory-service",
        "symbol": "inventory_service.reserve_stock",
        "sla_tier": "P1",
        "owner_team": "supply-chain",
        "on_call_email": "supply-oncall@acme.com",
        "language": "python",
        "repo": "acme/inventory-service",
        "status": "active",
        "downstream_services": ["warehouse-service"],
    },
    {
        "service_name": "notification-service",
        "symbol": "notification_service.send_email",
        "sla_tier": "P2",
        "owner_team": "customer-comms",
        "on_call_email": "comms-oncall@acme.com",
        "language": "python",
        "repo": "acme/notification-service",
        "status": "active",
        "downstream_services": [],
    },
    {
        "service_name": "user-profile-service",
        "symbol": "user_profile_service.get_user",
        "sla_tier": "P1",
        "owner_team": "core-identity",
        "on_call_email": "identity-oncall@acme.com",
        "language": "python",
        "repo": "acme/user-profile-service",
        "status": "active",
        "downstream_services": [],
    },
    {
        "service_name": "ledger-service",
        "symbol": "ledger_service.record_transaction",
        "sla_tier": "P0",
        "owner_team": "finance-engineering",
        "on_call_email": "finance-oncall@acme.com",
        "language": "python",
        "repo": "acme/ledger-service",
        "status": "active",
        "downstream_services": [],
    },
    {
        "service_name": "warehouse-service",
        "symbol": "warehouse_service.dispatch_item",
        "sla_tier": "P2",
        "owner_team": "fulfillment",
        "on_call_email": "fulfillment-oncall@acme.com",
        "language": "python",
        "repo": "acme/warehouse-service",
        "status": "active",
        "downstream_services": [],
    },
]


async def seed() -> None:
    uri = settings.mongodb_uri.get_secret_value()
    db_name = settings.mongodb_db_name
    collection_name = settings.mongodb_code_graph_collection

    logger.info("Connecting to MongoDB (%s)...", db_name)
    client = AsyncIOMotorClient(uri)
    db = client[db_name]
    collection = db[collection_name]

    count = 0
    for doc in SAMPLE_SERVICES:
        # Upsert based on unique service_name
        await collection.update_one(
            {"service_name": doc["service_name"]},
            {"$set": doc},
            upsert=True,
        )
        count += 1
        logger.info("  ✓ Seeded service node: %-22s (SLA: %s)", doc["service_name"], doc["sla_tier"])

    logger.info("🎉 Successfully seeded %d microservice nodes into '%s'.", count, collection_name)
    client.close()


if __name__ == "__main__":
    asyncio.run(seed())

