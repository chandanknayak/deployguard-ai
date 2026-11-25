# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Builder Stage
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source
COPY pyproject.toml README.md ./
COPY deployguard/ deployguard/

# Install application and production dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ---------------------------------------------------------------------------
# Final Runtime Stage
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runner

WORKDIR /app

# Install curl for container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged system user for container security
RUN groupadd -r deployguard && useradd -r -g deployguard deployguard

# Copy the pre-built virtualenv and application code
COPY --from=builder --chown=deployguard:deployguard /opt/venv /opt/venv
COPY --chown=deployguard:deployguard deployguard/ deployguard/
COPY --chown=deployguard:deployguard scripts/ scripts/

USER deployguard

EXPOSE 8080

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production \
    LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

CMD ["uvicorn", "deployguard.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
