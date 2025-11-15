# syntax=docker/dockerfile:1
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and README
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
FROM python:3.11-slim as runner

WORKDIR /app

# Create a non-privileged system user for container security
RUN groupadd -r deployguard && useradd -r -g deployguard deployguard

# Copy the pre-built virtualenv from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy source code
COPY --chown=deployguard:deployguard deployguard/ deployguard/
COPY --chown=deployguard:deployguard scripts/ scripts/

# Switch to non-root user
USER deployguard

# Expose HTTP port
EXPOSE 8080

# Configure environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production \
    LOG_LEVEL=INFO

# Health check against liveness probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

# Start FastAPI with Uvicorn
CMD ["uvicorn", "deployguard.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]

