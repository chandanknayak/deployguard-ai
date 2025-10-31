"""
api/main.py — FastAPI application factory and server entry point.

Exposes a ``create_app()`` factory function (preferred for testing) and a
module-level ``app`` instance for direct invocation via ``uvicorn``.

--- Application Lifecycle ---

Startup:
    - Validates all required environment variables via Pydantic settings.
    - Logs a structured startup banner with key configuration values.

Shutdown:
    - Cleanly closes any open connection pools (MongoDB, HTTP clients).

--- Middleware Stack ---

    1. RequestLoggingMiddleware — structured request/response logging.
    2. TrustedHostMiddleware  — reject requests with unexpected Host headers
       (defense-in-depth against Host header injection).
    3. GZipMiddleware          — compress large JSON responses.

--- Health & Observability Endpoints ---

    GET /healthz        — Liveness probe (always returns 200 if the process is up).
    GET /readyz          — Readiness probe (checks MongoDB connectivity).
    GET /metrics         — Placeholder for Prometheus metrics exposition.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from deployguard.agent.risk_agent import RiskAssessmentAgent
from deployguard.api.routers import webhook
from deployguard.api.routers import assessments
from deployguard.config import settings
from deployguard.db.client import MongoDBClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured Request Logging Middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs each request and response with structured fields.

    Fields logged per request:
        - HTTP method and URL path
        - Response status code
        - Wall-clock duration in milliseconds
        - ``X-GitHub-Delivery`` header (for webhook tracing)

    Sensitive headers (``Authorization``, ``X-Hub-Signature-256``) are
    intentionally excluded from log output.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.monotonic()
        delivery_id = request.headers.get("X-GitHub-Delivery", "-")

        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "method=%s path=%s status=%d duration=%.1fms delivery=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            delivery_id,
        )
        return response


# ---------------------------------------------------------------------------
# Application Lifespan (startup / shutdown hooks)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Async context manager for FastAPI application lifespan.

    Handles startup initialisation and graceful shutdown cleanup.
    Using the ``lifespan`` parameter is the modern FastAPI approach,
    replacing the deprecated ``@app.on_event("startup")`` pattern.
    """
    # --- STARTUP ---
    logger.info(
        "🛡️  %s starting up | env=%s | log_level=%s",
        settings.app_name,
        settings.app_env,
        settings.log_level,
    )
    logger.info(
        "Supported AST languages: %s | Max diff files: %d",
        settings.supported_ast_languages,
        settings.max_diff_files,
    )

    # Initialize MongoDB client
    try:
        app.state.db = await MongoDBClient.create()
    except Exception as exc:
        logger.warning("Could not establish initial MongoDB connection: %s. Continuing in degraded mode.", exc)
        app.state.db = None

    # Initialize RiskAssessmentAgent
    try:
        app.state.agent = RiskAssessmentAgent()
    except Exception as exc:
        logger.warning("Could not initialize RiskAssessmentAgent: %s. Continuing in degraded mode.", exc)
        app.state.agent = None

    yield  # Application runs here

    # --- SHUTDOWN ---
    logger.info("%s shutting down gracefully.", settings.app_name)
    if getattr(app.state, "db", None) is not None:
        await app.state.db.close()
    if getattr(app.state, "agent", None) is not None:
        await app.state.agent.close()


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Using a factory function (rather than a module-level instance) ensures
    each test gets a fresh application instance with isolated state, making
    the test suite hermetic.

    Returns:
        A fully configured ``FastAPI`` application instance.
    """
    app = FastAPI(
        title=settings.app_name,
        description=(
            "AI-Powered Release Risk & Change-Impact Platform. "
            "Webhook ingestion layer and deterministic AST analysis engine."
        ),
        version="1.0.0",
        docs_url="/docs" if settings.app_env != "production" else None,
        redoc_url="/redoc" if settings.app_env != "production" else None,
        openapi_url="/openapi.json" if settings.app_env != "production" else None,
        lifespan=lifespan,
    )

    # -----------------------------------------------------------------------
    # Middleware (outermost to innermost — order matters for execution)
    # -----------------------------------------------------------------------

    # GZip compression for responses larger than 1KB
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # CORS — allow the Streamlit dashboard (and any frontend) to call the API
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],          # Tighten to specific domains in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Trusted Host enforcement (add your actual hostnames in production)
    if settings.app_env == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["deployguard.yourdomain.com"],  # Configure per deployment
        )

    # Request/response structured logging
    app.add_middleware(RequestLoggingMiddleware)

    # -----------------------------------------------------------------------
    # Routers
    # -----------------------------------------------------------------------
    app.include_router(webhook.router)
    app.include_router(assessments.router)

    # -----------------------------------------------------------------------
    # Health & Observability Endpoints
    # -----------------------------------------------------------------------

    @app.get("/healthz", tags=["Observability"], summary="Liveness probe")
    async def healthz() -> JSONResponse:
        """
        Kubernetes/GCP liveness probe.

        Returns HTTP 200 as long as the process is running.  Does NOT check
        downstream dependencies (that is ``/readyz``'s responsibility).
        """
        return JSONResponse({"status": "ok", "service": settings.app_name})

    @app.get("/readyz", tags=["Observability"], summary="Readiness probe")
    async def readyz() -> JSONResponse:
        """
        Kubernetes/GCP readiness probe.

        Checks connectivity to downstream dependencies (MongoDB, GitHub API).
        Returns HTTP 200 only when the service is ready to accept traffic.
        """
        db_ready = False
        if getattr(app.state, "db", None) is not None:
            db_ready = await app.state.db.ping()

        agent_ready = getattr(app.state, "agent", None) is not None

        checks = {
            "mongodb": "healthy" if db_ready else "unhealthy",
            "risk_agent": "ready" if agent_ready else "unconfigured",
        }
        all_ready = db_ready
        status_code = 200 if all_ready else 503
        return JSONResponse(
            status_code=status_code,
            content={"status": "ready" if all_ready else "degraded", "checks": checks},
        )

    @app.get("/metrics", tags=["Observability"], summary="Prometheus metrics (placeholder)")
    async def metrics() -> JSONResponse:
        """
        Prometheus-compatible metrics endpoint.

        TODO: Integrate with ``prometheus-fastapi-instrumentator``.
        """
        return JSONResponse({"status": "metrics_not_yet_implemented"})

    # -----------------------------------------------------------------------
    # Global exception handlers
    # -----------------------------------------------------------------------

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Catch-all handler for any unhandled exception that escapes the
        endpoint handlers.  Returns HTTP 500 with a safe error message
        (no stack traces in production).
        """
        logger.exception("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error.",
                "detail": str(exc) if settings.app_env != "production" else "Contact support.",
            },
        )

    return app


# ---------------------------------------------------------------------------
# Module-level app instance (for uvicorn / gunicorn direct invocation)
# ---------------------------------------------------------------------------

app: FastAPI = create_app()

# ---------------------------------------------------------------------------
# Dev server entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "deployguard.api.main:app",
        host="0.0.0.0",
        port=8080,
        reload=settings.app_env == "development",
        log_level=settings.log_level.lower(),
    )

