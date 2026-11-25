<div align="center">

# 🛡️ DeployGuard AI

### Deterministic Pre-Deployment Risk Gate, Cross-File AST Analyzer & RBAC Release Platform

*Know what breaks before you merge — real GitHub PR scanning, cross-file call-graph tracing, workspace RBAC (Developer / Reviewer / DevOps Admin), and policy-gated releases.*

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async%20API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas%20%24graphLookup-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## What DeployGuard AI Actually Does

DeployGuard AI is a full-stack release safety SaaS built on **FastAPI + MongoDB + Python `ast` + GitHub REST API**:

1. **Deterministic Base-vs-Head Python AST Structural Diff (`deployguard/core/ast_analyzer.py`)**
   - Compares base branch vs PR head ASTs (`compare_ast_versions`) to catch removed FastAPI/Flask endpoints (`REMOVED_ROUTE`), modified route contracts (`MODIFIED_ROUTE_CONTRACT`), deleted public symbols (`REMOVED_SYMBOL`), and breaking argument changes (`BREAKING_SIGNATURE`).
2. **Cross-File Impact & MongoDB `$graphLookup` Blast Radius (`build_cross_file_impact_graph`, `db/db_operations.py`)**
   - Traces imports and calls across repository Python files (`Modified File → Symbol → Downstream Consumer/Route`) and combines them with MongoDB service dependency traversal (`P0`/`P1`/`P2` SLA tiers).
3. **Transparent Weighted Risk Engine — 40 / 30 / 20 / 10 (`deployguard/core/risk_engine.py`)**
   - **AST Structural Diff (40%)** + **Blast Radius Impact (30%)** + **Critical Path Sensitivity (20%)** + **Test Coverage Gap (10%)**.
   - Explicit handling: docs/asset-only PRs deterministically score `0/100 PASS`; breaking route removals enforce `BLOCK (>= 74)`. Works 100% deterministically with zero OpenAI dependency, and blends GPT-4o + `$vectorSearch` historical incident lookup when `OPENAI_API_KEY` is configured.
4. **Workspace RBAC & Real GitHub SDLC Workflow (`auth.py`, `repos.py`, `enterprise.py`)**
   - **DevOps Admin (`devops_admin`)**: Creates/connects GitHub repos (including 1-click **Create & Seed Demo GitHub Repo**), invites GitHub collaborators, assigns workspace roles, edits Governance Policy & SSRF-protected Staging Health Probe URLs, executes **Admin Override Merge** on blocked PRs, and triggers deployments.
   - **Reviewer (`reviewer`)**: Submits GitHub PR Reviews (`APPROVE` / `REQUEST_CHANGES` / `COMMENT`) and merges safe (`PASS`) PRs; blocked from Admin Overrides, Policy changes, and Production Deploys (`HTTP 403`).
   - **Developer (`developer`)**: Opens real GitHub PRs, inspects PR diffs/graphs, runs AST risk scans and live sandbox simulations; blocked from merging, reviewing, or deploying (`HTTP 403`).
5. **Security Hardening**
   - HMAC-SHA256 webhook signature verification (`verify_github_signature`), SHA-256 CTR + HMAC-SHA256 encryption at rest (`deployguard/core/crypto.py`) for stored GitHub PATs, stateless HMAC-signed OAuth states (multi-worker safe), strict SSRF IP checks on health/deploy URLs, tenant-scoped `workspace_id` isolation, and XSS-escaped SPA rendering.

---

## Project Structure

```text
deployguard-ai/
├── deployguard/
│   ├── api/
│   │   ├── main.py                # FastAPI factory, security headers, static SPA mount
│   │   └── routers/
│   │       ├── auth.py            # Workspace auth, JWT, PBKDF2, RBAC role guards, OAuth
│   │       ├── repos.py           # Repos, demo repo seeding, collaborators, real PRs, reviews, merge
│   │       ├── enterprise.py      # Team RBAC, policy, SSRF-safe deploy probe, audit log, AST sandbox, public PR inspector
│   │       ├── assessments.py     # Tenant-scoped assessment queries & SSE stream
│   │       └── webhook.py         # GitHub webhook ingestion (HMAC + 202 async pipeline)
│   ├── agent/risk_agent.py        # Optional OpenAI Structured Outputs synthesis
│   ├── core/
│   │   ├── ast_analyzer.py        # AST parser, base/head diff, cross-file call graph
│   │   ├── risk_engine.py         # 40/30/20/10 weighted scoring & gate state machine
│   │   ├── pipeline.py            # Concurrent GitHub PR analysis orchestrator
│   │   ├── comment_renderer.py    # Idempotent GitHub PR Markdown report renderer
│   │   ├── diff_parser.py         # Unified git diff parser
│   │   ├── github_client.py       # Async GitHub REST API client
│   │   ├── crypto.py              # Encrypt-then-MAC at-rest secret encryption
│   │   └── security.py            # Webhook HMAC verification
│   ├── db/
│   │   ├── client.py              # Motor async MongoDB connection pool
│   │   └── db_operations.py       # $graphLookup blast radius, $vectorSearch, indexes, demo seeding
│   ├── models/                    # Pydantic models (AnalysisResult, webhook payload)
│   ├── static/                    # Built-in SPA UI (index.html, app.js, styles.css)
│   └── config.py                  # Pydantic Settings configuration
├── scripts/
│   ├── seed_graph.py              # Seed sample service dependency graph into MongoDB
│   ├── ingest_incidents.py        # Seed historical incident vectors into MongoDB
│   ├── create_indexes.js          # MongoDB Atlas index definitions
│   ├── demo_preview.py            # Offline CLI dry-run preview
│   ├── test_live_api.py           # FastAPI TestClient smoke verification
│   └── setup_webhook.py           # Environment & webhook verification helper
├── tests/unit/                    # Automated unit & RBAC integration test suite
├── docker/                        # Dockerfile & docker-compose.yml
├── .github/workflows/ci.yml       # Ruff lint, pytest + coverage, Docker build
├── render.yaml                    # Render deployment manifest
└── pyproject.toml                 # Dependencies & tooling config
```

---

## Local Setup & Running

### 1. Install Dependencies

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate  |  Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure `.env`

```bash
cp .env.example .env
```

Set at minimum:
- `MONGODB_URI` (local MongoDB or Atlas cluster)
- `JWT_SECRET_KEY` & `TOKEN_ENCRYPTION_KEY` (strong random 32+ char strings in production)
- `GITHUB_WEBHOOK_SECRET` & optional `GITHUB_API_TOKEN`
- Optional `OPENAI_API_KEY` (if omitted, the deterministic 40/30/20/10 AST + Graph engine runs cleanly by itself)

### 3. Start the Server & Open the Web UI

```bash
python -m uvicorn deployguard.api.main:app --host 0.0.0.0 --port 8080 --reload
```

Open **[http://localhost:8080](http://localhost:8080)** (or **`http://localhost:8080/?demo=1`** to jump straight into the Live Public PR & AST Sandbox without logging in).

### 4. Step-by-Step Real GitHub & RBAC Workflow (Inside the App)

1. **Create Workspace**: Sign up — you are created as **DevOps Admin** (`devops_admin`).
2. **Tab 1 (`Setup & Team`)**:
   - Click **Link GitHub** and save your GitHub PAT (`repo` scope — encrypted before saving to MongoDB).
   - Click **Create & Seed Real GitHub Repo** to create a genuine microservice repository (`services/payments.py`, `routes/checkout.py`, `services/auth_tokens.py`, `tests/test_payments.py`).
   - Add teammates in **Team Members & Workspace RBAC** (`developer`, `reviewer`, `devops_admin`) and optionally invite real GitHub usernames under **GitHub Repository Collaborators**.
3. **Tab 2 (`Pull Requests`)**:
   - Click **+ Open Test PR on GitHub** (e.g., *Breaking Route Removal* or *Safe Helper*) — creates a real branch & PR on GitHub and scans it automatically.
   - Switch into a **Developer** account via **Switch Role**: can inspect & scan PRs, while Merge/Review buttons are locked (`HTTP 403`).
   - Switch into a **Reviewer** account: submit `APPROVE` / `REQUEST_CHANGES` directly onto the GitHub PR; merge `PASS` PRs while `BLOCK`ed PRs stay guarded.
   - Switch back to **DevOps Admin**: authorize **Admin Override & Merge** (justification logged to MongoDB Audit Trail) and merge on GitHub.
4. **Tab 4 (`Deploy & Audit`)**:
   - Only **DevOps Admin** can trigger Canary/Staging/Production rollouts with live SSRF-protected HTTP health probing and review the immutable MongoDB workspace audit log.

---

## Running Tests

```bash
pytest -v
```
