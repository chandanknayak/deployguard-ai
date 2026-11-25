"""
db/client.py — Async MongoDB connection client (Motor).

Architecture decisions:
    ┌─────────────────────────────────────────────────────────────────────┐
    │  Why Motor over PyMongo?                                            │
    │                                                                     │
    │  FastAPI is built on the async ASGI standard. PyMongo is           │
    │  synchronous — every database call would block the entire event    │
    │  loop, negating FastAPI's concurrency model. Motor wraps PyMongo   │
    │  in an async shell, giving us true non-blocking I/O that plays    │
    │  well with ``await`` throughout the application.                   │
    │                                                                     │
    │  Why a singleton client (not per-request)?                         │
    │                                                                     │
    │  MongoDB connections are expensive (TCP handshake + auth + TLS).  │
    │  Motor's AsyncIOMotorClient maintains an internal connection pool  │
    │  that is shared across all coroutines. Creating one client at      │
    │  startup and reusing it for the application lifetime is the        │
    │  correct pattern. Closing it at shutdown drains the pool cleanly. │
    └─────────────────────────────────────────────────────────────────────┘

Usage (FastAPI lifespan)::

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db = await MongoDBClient.create()
        yield
        await app.state.db.close()

    # In a route or background task:
    db = get_db_client(request.app)
    blast = await get_blast_radius(db, "payment-service")
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
except ImportError:
    AsyncIOMotorClient = None  # type: ignore[misc, assignment]
    AsyncIOMotorDatabase = None  # type: ignore[misc, assignment]

from deployguard.config import settings

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection pool settings
# ---------------------------------------------------------------------------

# Maximum number of simultaneous connections in the pool.
# For a webhook ingestion service that fires bursts of parallel queries
# on PR arrival, 20 is a safe upper bound for an M10 Atlas cluster.
_POOL_MAX_SIZE = 20

# Timeout in milliseconds to wait for a connection from the pool before
# raising a PoolWaitQueueTimeoutError. Prevents queue pile-up under load.
_WAIT_QUEUE_TIMEOUT_MS = 5_000

# Server selection timeout: how long to wait when no healthy MongoDB node
# is available (catches Atlas cluster cold-start / failover scenarios).
_SERVER_SELECTION_TIMEOUT_MS = 10_000


class MongoDBClient:
    """
    Async MongoDB client wrapper managing the Motor connection pool.

    This class is intentionally **not** a context manager for the client
    socket itself — it wraps the lifecycle of the Motor client that should
    live for the entire application lifetime.

    Attributes:
        _motor_client: The underlying ``AsyncIOMotorClient`` instance.
        _db: The ``AsyncIOMotorDatabase`` handle for ``settings.mongodb_db_name``.
    """

    def __init__(self, motor_client: AsyncIOMotorClient) -> None:
        self._motor_client = motor_client
        self._db: AsyncIOMotorDatabase = motor_client[settings.mongodb_db_name]

    # ------------------------------------------------------------------
    # Factory constructor (async-safe)
    # ------------------------------------------------------------------

    @classmethod
    async def create(cls) -> "MongoDBClient":
        """
        Asynchronously create and validate a ``MongoDBClient`` instance.

        Calls ``ping`` on the admin database immediately after connecting to
        fail fast if the MongoDB URI is misconfigured or the cluster is
        unreachable — rather than discovering this on the first real query.

        Returns:
            A ready-to-use ``MongoDBClient``.

        Raises:
            ``motor.motor_asyncio.exceptions.*``: On connection failure.
            ``pymongo.errors.ConfigurationError``: On invalid URI.
        """
        if AsyncIOMotorClient is None:
            raise RuntimeError("The 'motor' package is not installed. Run 'pip install motor'.")

        uri = settings.mongodb_uri.get_secret_value()
        logger.info(
            "Connecting to MongoDB database '%s' (pool_size=%d)...",
            settings.mongodb_db_name,
            _POOL_MAX_SIZE,
        )

        motor_client: AsyncIOMotorClient = AsyncIOMotorClient(
            uri,
            maxPoolSize=_POOL_MAX_SIZE,
            waitQueueTimeoutMS=_WAIT_QUEUE_TIMEOUT_MS,
            serverSelectionTimeoutMS=_SERVER_SELECTION_TIMEOUT_MS,
            # Prefer reads from nearest replica — reduces latency for
            # read-heavy blast radius and vector search queries.
            readPreference="nearest",
        )

        # Validate connectivity immediately (fail fast)
        await motor_client.admin.command("ping")
        logger.info("MongoDB connection pool established successfully.")

        return cls(motor_client)

    # ------------------------------------------------------------------
    # Property accessors
    # ------------------------------------------------------------------

    @property
    def db(self) -> AsyncIOMotorDatabase:
        """Return the primary database handle."""
        return self._db

    @property
    def code_graph(self):
        """Shorthand accessor for the code dependency graph collection."""
        return self._db[settings.mongodb_code_graph_collection]

    @property
    def incidents(self):
        """Shorthand accessor for the historical incidents collection."""
        return self._db[settings.mongodb_incidents_collection]

    @property
    def assessments(self):
        """Shorthand accessor for the risk assessments audit log collection."""
        return self._db[settings.mongodb_assessments_collection]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """
        Gracefully close the Motor client and drain the connection pool.

        Should be called exactly once during application shutdown (e.g.
        inside the FastAPI ``lifespan`` context manager after ``yield``).
        """
        self._motor_client.close()
        logger.info("MongoDB connection pool closed.")

    async def ping(self) -> bool:
        """
        Check if the MongoDB server is reachable.

        Used by the ``/readyz`` health endpoint.

        Returns:
            ``True`` if the ping succeeds, ``False`` otherwise.
        """
        try:
            await self._motor_client.admin.command("ping")
            return True
        except Exception as exc:
            logger.warning("MongoDB ping failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# FastAPI application-level helper
# ---------------------------------------------------------------------------


def get_db_client(app: "FastAPI") -> MongoDBClient:
    """
    Retrieve the ``MongoDBClient`` stored on the FastAPI application state.

    This is the recommended access pattern for route handlers and background
    tasks that receive the ``Request`` object::

        from fastapi import Request
        from deployguard.db.client import get_db_client

        async def my_handler(request: Request) -> None:
            db = get_db_client(request.app)
            results = await get_blast_radius(db, "payment-service")

    Args:
        app: The FastAPI application instance (available as ``request.app``).

    Returns:
        The singleton ``MongoDBClient``.

    Raises:
        ``AttributeError``: If ``create_app()`` did not initialise ``app.state.db``.
    """
    return app.state.db

