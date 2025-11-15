<div align="center">

# 🛡️ DeployGuard AI

### AI-Powered Release Risk & Change-Impact Platform

*An intelligent CI/CD gate that deterministically maps code changes, surfaces historical blast radius, and autonomously blocks high-risk deployments before they reach production.*

---

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-CI%2FCD%20Gate-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/features/actions)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![LangChain](https://img.shields.io/badge/LangChain-Agent%20Framework-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white)](https://www.langchain.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)
[![Status](https://img.shields.io/badge/Status-Production--Ready-blue?style=for-the-badge)]()

</div>

---

## 📌 Table of Contents

1. [Elevator Pitch — The Enterprise Problem](#-elevator-pitch--the-enterprise-problem)
2. [System Architecture](#-system-architecture)
3. [Tech Stack & Engineering Justifications](#-tech-stack--engineering-justifications)
4. [How It Works — End-to-End Flow](#-how-it-works--end-to-end-flow)
5. [Sample Risk Assessment Output](#-sample-risk-assessment-output)
6. [Project Structure](#-project-structure)
7. [Local Setup & Installation](#-local-setup--installation)
8. [CI/CD Integration](#-cicd-integration)
9. [Configuration Reference](#-configuration-reference)
10. [Roadmap](#-roadmap)
11. [Contributing](#-contributing)

---

## 🚀 Elevator Pitch — The Enterprise Problem

> **Every major production outage shares one root cause: a change no one fully understood.**

Modern engineering organizations ship code hundreds of times per day. Each merge is a calculated gamble. Engineers lack a deterministic, automated answer to the single most critical pre-deployment question:

**"If this PR lands, what breaks — and have we broken it before?"**

The status quo is broken:

| Current Reality | Consequence |
|---|---|
| Manual code reviews miss cross-service blast radius | Cascading failures that span teams |
| LLMs hallucinate impact analysis without code structure | False confidence in AI-generated reviews |
| Post-incident retrospectives don't feed back into the deploy pipeline | The same incidents repeat, quarter after quarter |
| Risk assessment is qualitative, not quantitative | Engineering managers cannot make data-driven gate decisions |

**DeployGuard AI solves this at the infrastructure layer.** It sits as an autonomous agent inside your CI/CD pipeline — before merge, before deploy, before damage. It:

1. **Deterministically parses** every changed file into an Abstract Syntax Tree (AST), extracting exact function signatures, call graphs, and dependency edges — not guesses.
2. **Traverses your historical code-change graph** using MongoDB's `$graphLookup` to compute multi-hop blast radius: *"This function is called by 7 upstream services — two of which caused P0 incidents last quarter."*
3. **Semantically searches 18 months of incident history** using MongoDB Vector Search to surface past outages that look like the current change pattern.
4. **Runs an LLM agent** that synthesizes deterministic data (AST + graph) with historical signal (vector search) to produce a quantified Risk Score (0–100) and a human-readable audit trail.
5. **Issues a hard CI/CD gate decision** — Pass, Warn, or Block — with a machine-readable JSON report attached to the PR.

The result: **Blast radius becomes visible before production. Outages that repeat become impossible to deploy.**

This is not a linting tool. This is not another AI code reviewer. This is **pre-flight intelligence for production systems** — built for engineering managers who need accountability, and for staff engineers who refuse to ship blind.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DEVELOPER WORKFLOW                              │
│                                                                         │
│   git push ──► Pull Request Opened / Updated (GitHub / GitLab / ADO)   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │  Webhook / GitHub Actions Trigger
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     DEPLOYGUARD AI PIPELINE                              │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 1 │ DIFF EXTRACTOR                                        │    │
│  │          │ • Fetches PR unified diff via GitHub API              │    │
│  │          │ • Normalizes file paths, identifies languages         │    │
│  │          │ • Routes changed files to language-specific parsers   │    │
│  └──────────────────────────────┬───────────────────────────────────┘    │
│                                 │ Raw diff + file list                    │
│                                 ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 2 │ AST PARSER ENGINE (Python ast / tree-sitter)          │    │
│  │          │ • Parses each changed file into a full AST            │    │
│  │          │ • Extracts: function defs, class defs, imports,       │    │
│  │          │   call graphs, decorators, type signatures            │    │
│  │          │ • Emits structured ChangeSet: {added, modified,       │    │
│  │          │   deleted} symbols with full qualified names          │    │
│  └──────────────────────────────┬───────────────────────────────────┘    │
│                                 │ Structured ChangeSet (JSON)             │
│                                 ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 3 │ MONGODB INTELLIGENCE LAYER                            │    │
│  │          │                                                        │    │
│  │  ┌───────────────────────┐    ┌──────────────────────────────┐   │    │
│  │  │  CODE DEPENDENCY GRAPH│    │  INCIDENT VECTOR STORE       │   │    │
│  │  │  Collection: code_graph│   │  Collection: incidents       │   │    │
│  │  │                       │    │                              │   │    │
│  │  │  $graphLookup:        │    │  MongoDB Atlas Vector Search │   │    │
│  │  │  Multi-hop traversal  │    │  Embedding: text-embedding   │   │    │
│  │  │  of caller/callee     │    │  -3 (OpenAI) / nomic-embed   │   │    │
│  │  │  relationships across │    │                              │   │    │
│  │  │  services             │    │  Query: ChangeSet summary    │   │    │
│  │  │                       │    │  → Top-K similar incidents   │   │    │
│  │  │  Output: Blast Radius │    │  with severity, duration,    │   │    │
│  │  │  graph (N-hops)       │    │  root cause tags             │   │    │
│  │  └───────────┬───────────┘    └──────────────┬───────────────┘   │    │
│  │              │ Graph context                  │ Incident history  │    │
│  │              └───────────────┬────────────────┘                   │    │
│  └──────────────────────────────┼───────────────────────────────────┘    │
│                                 │ Enriched context bundle                 │
│                                 ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 4 │ LLM RISK ASSESSMENT AGENT                             │    │
│  │          │ • Framework: LangChain / LangGraph ReAct agent        │    │
│  │          │ • Model: GPT-4o / Gemini 1.5 Pro (configurable)       │    │
│  │          │ • Tools available to agent:                           │    │
│  │          │     - query_blast_radius(symbol)                      │    │
│  │          │     - search_similar_incidents(query)                 │    │
│  │          │     - get_service_ownership(service_id)               │    │
│  │          │     - get_on_call_schedule()                          │    │
│  │          │ • Produces: RiskScore (0-100), severity, rationale,   │    │
│  │          │   mitigations, affected_services[]                    │    │
│  └──────────────────────────────┬───────────────────────────────────┘    │
│                                 │ Risk Assessment JSON                    │
│                                 ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  STAGE 5 │ CI/CD GATE ENFORCER                                   │    │
│  │          │                                                        │    │
│  │  Score 0-39  ──► PASS   → PR approved, comment posted            │    │
│  │  Score 40-69 ──► WARN   → PR flagged, owner notified             │    │
│  │  Score 70-100 ──► BLOCK → PR blocked, escalation triggered       │    │
│  │                                                                   │    │
│  │  Outputs: GitHub Status Check, PR Comment, Audit log → MongoDB   │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Tech Stack & Engineering Justifications

### Why MongoDB `$graphLookup` for Blast Radius?

Code dependency graphs are, by definition, **directed acyclic graphs (DAGs)** with potentially hundreds of hops across services. The critical question — *"what does changing function X affect?"* — requires recursive, multi-hop graph traversal.

**The engineering decision:**

```
Option A: Relational DB (PostgreSQL recursive CTEs)
  → Requires schema migrations on every new service onboarded.
  → Recursive CTE performance degrades non-linearly at 4+ hops.
  → Rigid schema fights against the organic, evolving nature of codebases.

Option B: Dedicated Graph DB (Neo4j)
  → Excellent for graph traversal, but adds a second primary database.
  → Operational overhead: two databases to monitor, back up, and scale.
  → No native vector search for incident analysis — requires a third system.

✅ Option C: MongoDB $graphLookup (chosen)
  → Single database serves both the graph and the vector store.
  → $graphLookup performs recursive collection traversal natively, with
    a configurable maxDepth for bounded blast radius computation.
  → Document model stores rich node metadata (service, owner, SLA tier)
    co-located with graph edges — no joins needed.
  → Atlas Vector Search runs in the same cluster as the graph,
    allowing a single atomic aggregation pipeline to combine
    graph context WITH semantically similar incident vectors.
```

`$graphLookup` pipeline used for blast radius:
```javascript
db.code_graph.aggregate([
  { $match: { symbol: "payment_service.charge_card" } },
  {
    $graphLookup: {
      from: "code_graph",
      startWith: "$symbol",
      connectFromField: "symbol",
      connectToField: "callers",
      as: "blast_radius",
      maxDepth: 5,
      restrictSearchWithMatch: { "sla_tier": { $in: ["P0", "P1"] } }
    }
  }
])
```

---

### Why AST Parsing Over LLM-Based Code Understanding?

This is the **most important architectural decision** in DeployGuard AI.

| Dimension | LLM Code Analysis | AST Parsing (DeployGuard AI) |
|---|---|---|
| **Correctness** | Probabilistic — can hallucinate call relationships | Deterministic — 100% accurate function/call extraction |
| **Reproducibility** | Same code → different analysis on every run | Same code → identical AST on every run |
| **Auditability** | Black box — "the AI said so" | Full traceable tree: every edge is provable |
| **Cost at scale** | O(tokens) per file — expensive at 500+ file PRs | O(n) parse time — trivial CPU cost |
| **Context window** | Fails on large files / cross-file dependencies | Parses entire repository graph incrementally |
| **CI/CD suitability** | Latency and cost unpredictable | Sub-second parse, deterministic SLA |

> **The core insight:** LLMs are excellent at *synthesizing meaning* from structured data. They are poor at *extracting structure* from unstructured code at production scale. DeployGuard AI uses each tool for its comparative advantage: AST for extraction, LLM for reasoning.

The AST engine supports:
- **Python**: stdlib `ast` module + `libcst` for comment-preserving transforms
- **JavaScript/TypeScript**: `tree-sitter` with `tree-sitter-javascript` grammar
- **Java**: `javalang` parser
- **Go**: `go/ast` via subprocess (extensible via plugin interface)

---

### Why an Agentic AI Architecture?

A naive implementation would chain fixed prompts: `prompt_1 → prompt_2 → final_answer`. This fails in production because risk assessment is **non-linear**.

Consider: *An agent analyzing a change to a database migration script needs to:*
1. Identify the affected tables (AST)
2. Look up all services that read those tables (graph, 3 hops)
3. Check if any of those services have a P0 SLA (service registry tool call)
4. Search for past incidents tagged `db-migration` + `data-loss` (vector search)
5. Check if the on-call engineer for the affected team is available (PagerDuty tool)
6. Synthesize all of the above into a coherent risk score with citations

No linear prompt chain handles conditional, tool-using reasoning. A **ReAct (Reason + Act) agent** can:
- Decide *which* tools to invoke based on intermediate findings
- Iterate: if blast radius returns 0 nodes, deprioritize graph analysis
- Self-correct: if incident search returns low confidence, expand the query
- Produce a **reasoning trace** that is itself an audit artifact

This is not AI for AI's sake. The agentic architecture exists because the **reasoning task is genuinely non-linear**, and the tools are the system's ground truth.

---

## ⚙️ How It Works — End-to-End Flow

### Step 1: PR Triggers the Pipeline

A GitHub Actions workflow fires on `pull_request` events, invoking the DeployGuard AI container as a GitHub Actions step.

### Step 2: AST ChangeSet Extraction

The diff is parsed and each changed symbol is extracted:

```python
# Simplified AST extraction
import ast

class SymbolExtractor(ast.NodeVisitor):
    def visit_FunctionDef(self, node):
        self.symbols.append({
            "type": "function",
            "name": node.name,
            "qualified_name": f"{self.module}.{node.name}",
            "lineno": node.lineno,
            "calls": [
                n.func.id for n in ast.walk(node)
                if isinstance(n, ast.Call) and hasattr(n.func, 'id')
            ]
        })
```

### Step 3: MongoDB Graph Traversal

The qualified function names are used as entry points for `$graphLookup`, returning all upstream callers up to N hops across the full service mesh.

### Step 4: Vector Search for Historical Incidents

The ChangeSet summary is embedded and queried against the incident collection:

```python
# Atlas Vector Search query
pipeline = [
    {
        "$vectorSearch": {
            "index": "incident_embedding_index",
            "path": "embedding",
            "queryVector": embed(changeset_summary),
            "numCandidates": 150,
            "limit": 10
        }
    },
    {
        "$project": {
            "incident_id": 1, "title": 1, "severity": 1,
            "duration_minutes": 1, "root_cause_tags": 1,
            "score": { "$meta": "vectorSearchScore" }
        }
    }
]
```

### Step 5: Agent Synthesizes Risk Report

The LangChain ReAct agent receives the structured context bundle and uses its tool suite to produce the final assessment.

---

## 📊 Sample Risk Assessment Output

The following is a real-format JSON output produced by DeployGuard AI for a PR modifying the payment service's charge handler:

```json
{
  "deployguard_version": "1.4.2",
  "assessment_id": "dg-2024-11-01-a3f9c1",
  "pr": {
    "number": 4821,
    "title": "refactor: optimize charge_card retry logic with exponential backoff",
    "author": "elena.vasquez",
    "base_branch": "main",
    "head_sha": "c7d3e8f1a2b5094d6e"
  },
  "changeset": {
    "files_changed": 3,
    "symbols_modified": [
      "payment_service.charge_card",
      "payment_service.RetryPolicy.__init__",
      "payment_service.RetryPolicy.compute_backoff"
    ],
    "symbols_added": ["payment_service.RetryPolicy.jitter_factor"],
    "symbols_deleted": []
  },
  "blast_radius": {
    "hop_depth_searched": 4,
    "total_affected_nodes": 14,
    "critical_path_services": [
      {
        "service": "order_service",
        "sla_tier": "P0",
        "hops_from_change": 1,
        "owner_team": "commerce-platform"
      },
      {
        "service": "subscription_billing",
        "sla_tier": "P0",
        "hops_from_change": 2,
        "owner_team": "billing-infra"
      },
      {
        "service": "fraud_detection",
        "sla_tier": "P1",
        "hops_from_change": 3,
        "owner_team": "trust-and-safety"
      }
    ]
  },
  "historical_incidents": {
    "similar_incidents_found": 3,
    "top_match": {
      "incident_id": "INC-2024-0317",
      "title": "Payment retry storm caused 40-minute checkout outage",
      "severity": "P0",
      "duration_minutes": 40,
      "root_cause_tags": ["retry-logic", "payment", "thundering-herd"],
      "similarity_score": 0.94,
      "postmortem_url": "https://wiki.internal/postmortems/INC-2024-0317"
    }
  },
  "risk_assessment": {
    "risk_score": 78,
    "severity": "HIGH",
    "gate_decision": "BLOCK",
    "confidence": 0.91,
    "rationale": "The modification to charge_card's retry policy directly impacts 2 P0-tier services (order_service, subscription_billing) within 2 hops. Historical vector search surfaces INC-2024-0317 (similarity: 0.94), a P0 outage caused by an analogous retry-logic change in the same service 8 months ago that resulted in a thundering-herd payment storm. The new jitter_factor parameter lacks test coverage in the CI suite. Combining high blast radius, direct precedent of failure, and insufficient test coverage yields a risk score of 78/100.",
    "recommended_mitigations": [
      "Add unit tests for RetryPolicy.compute_backoff covering jitter_factor edge cases (0, negative, >1.0)",
      "Add a circuit-breaker reference test simulating retry saturation",
      "Obtain explicit LGTM from billing-infra and commerce-platform team leads",
      "Consider feature-flagging the retry policy change for staged rollout",
      "Review postmortem INC-2024-0317 before proceeding"
    ],
    "escalation_contacts": [
      { "team": "billing-infra", "on_call": "james.okafor@company.com" },
      { "team": "commerce-platform", "on_call": "priya.nair@company.com" }
    ]
  },
  "agent_reasoning_trace": [
    "THOUGHT: Changed symbol is payment_service.charge_card — this is a critical payment path. Initiating graph traversal.",
    "ACTION: query_blast_radius('payment_service.charge_card', max_depth=4)",
    "OBSERVATION: 14 nodes found. 2 are P0 services within 2 hops.",
    "THOUGHT: P0 blast radius detected. Must search for historical payment retry incidents.",
    "ACTION: search_similar_incidents('payment service retry logic exponential backoff')",
    "OBSERVATION: INC-2024-0317 returned with 0.94 similarity. P0, 40 min duration.",
    "THOUGHT: Near-identical historical incident found. This dramatically elevates risk. Checking test coverage.",
    "ACTION: check_test_coverage('payment_service.RetryPolicy')",
    "OBSERVATION: coverage.py reports 34% coverage on RetryPolicy class. jitter_factor has 0 test cases.",
    "THOUGHT: Insufficient test coverage combined with P0 blast radius and precedent incident. Risk score: 78. Gate decision: BLOCK."
  ],
  "metadata": {
    "analysis_duration_seconds": 4.3,
    "ast_parse_time_ms": 87,
    "graph_query_time_ms": 210,
    "vector_search_time_ms": 310,
    "agent_inference_time_ms": 3700,
    "model_used": "gpt-4o",
    "tokens_consumed": 3847
  }
}
```

---

## 📁 Project Structure

```
deployguard-ai/
│
├── .github/
│   └── workflows/
│       └── deployguard.yml        # GitHub Actions CI/CD gate workflow
│
├── deployguard/
│   ├── __init__.py
│   ├── config.py                  # Pydantic settings from env vars
│   │
│   ├── ast_engine/
│   │   ├── __init__.py
│   │   ├── base_parser.py         # Abstract parser interface
│   │   ├── python_parser.py       # Python AST extractor (ast + libcst)
│   │   ├── js_parser.py           # JS/TS extractor (tree-sitter)
│   │   ├── java_parser.py         # Java extractor (javalang)
│   │   └── changeset.py           # ChangeSet dataclass + serialization
│   │
│   ├── mongodb/
│   │   ├── __init__.py
│   │   ├── client.py              # Motor async MongoDB client
│   │   ├── graph.py               # $graphLookup blast radius queries
│   │   ├── vector_search.py       # Atlas Vector Search queries
│   │   └── audit_log.py           # Assessment persistence
│   │
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── risk_agent.py          # LangChain ReAct agent definition
│   │   ├── tools.py               # Agent tool implementations
│   │   ├── prompts.py             # System and tool prompts
│   │   └── scoring.py             # Risk score computation logic
│   │
│   ├── gate/
│   │   ├── __init__.py
│   │   ├── enforcer.py            # Gate decision engine (PASS/WARN/BLOCK)
│   │   ├── github_client.py       # GitHub Status Check + PR comment API
│   │   └── notifier.py            # Slack / PagerDuty escalation
│   │
│   └── api/
│       ├── __init__.py
│       └── main.py                # FastAPI server (optional REST mode)
│
├── tests/
│   ├── unit/
│   │   ├── test_python_parser.py
│   │   ├── test_graph_queries.py
│   │   └── test_scoring.py
│   └── integration/
│       ├── test_full_pipeline.py
│       └── fixtures/
│           └── sample_pr_diff.txt
│
├── scripts/
│   ├── seed_graph.py              # Seeds code_graph collection from repo
│   ├── ingest_incidents.py        # Embeds and loads incident history
│   └── create_indexes.js          # MongoDB index creation script
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── .env.example
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## 🛠️ Local Setup & Installation

### Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ | Uses `match` statements, `tomllib` |
| Docker | 24.0+ | For containerized deployment |
| MongoDB Atlas | M10+ cluster | Required for Vector Search and `$graphLookup` |
| OpenAI API Key | — | For LLM agent and embeddings |
| GitHub Token | — | For PR status check writes |

---

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/deployguard-ai.git
cd deployguard-ai
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```dotenv
# MongoDB
MONGODB_URI=mongodb+srv://<user>:<password>@cluster0.mongodb.net/?retryWrites=true
MONGODB_DB_NAME=deployguard

# LLM Agent
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
EMBEDDING_MODEL=text-embedding-3-small

# GitHub
GITHUB_TOKEN=ghp_...
GITHUB_REPO=your-org/your-repo

# Gate Thresholds (optional overrides)
RISK_THRESHOLD_WARN=40
RISK_THRESHOLD_BLOCK=70

# Notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
PAGERDUTY_ROUTING_KEY=...
```

### 3. Install Dependencies

```bash
# Using pip (recommended: virtual environment)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Or with `uv` (faster):

```bash
uv sync --all-extras
```

### 4. Provision MongoDB Collections & Indexes

```bash
# Create Atlas Search indexes (requires mongosh)
mongosh "$MONGODB_URI" --file scripts/create_indexes.js

# Seed the code dependency graph from your repository
python scripts/seed_graph.py --repo-path /path/to/your/service --language python

# Ingest and embed historical incident data (CSV or JSON)
python scripts/ingest_incidents.py --source incidents.json
```

### 5. Run Locally Against a Test PR

```bash
# Analyze a specific PR
python -m deployguard analyze \
  --pr-number 4821 \
  --repo your-org/your-repo \
  --dry-run                     # skips writing GitHub status check
```

### 6. Run with Docker

```bash
docker compose up --build
```

The service exposes a REST API at `http://localhost:8080`. Trigger an assessment via:

```bash
curl -X POST http://localhost:8080/assess \
  -H "Content-Type: application/json" \
  -d '{"pr_number": 4821, "repo": "your-org/your-repo"}'
```

### 7. Run Tests

```bash
pytest tests/ -v --cov=deployguard --cov-report=term-missing
```

---

## 🔗 CI/CD Integration

Add DeployGuard AI as a required status check in your GitHub branch protection rules. Drop the following into `.github/workflows/deployguard.yml`:

```yaml
name: DeployGuard AI — Risk Assessment

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  risk-assessment:
    name: DeployGuard Risk Assessment
    runs-on: ubuntu-latest
    # This is a required status check — failure blocks merge

    steps:
      - name: Checkout PR
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run DeployGuard AI
        uses: docker://ghcr.io/your-org/deployguard-ai:latest
        env:
          MONGODB_URI:        ${{ secrets.DEPLOYGUARD_MONGODB_URI }}
          OPENAI_API_KEY:     ${{ secrets.DEPLOYGUARD_OPENAI_API_KEY }}
          GITHUB_TOKEN:       ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER:          ${{ github.event.pull_request.number }}
          GITHUB_REPO:        ${{ github.repository }}

      - name: Upload Risk Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: deployguard-risk-report
          path: deployguard-report.json
```

**Configure as a Required Status Check:**
1. Navigate to **Settings → Branches → Branch protection rules**
2. Enable **"Require status checks to pass before merging"**
3. Add **"DeployGuard Risk Assessment"** as a required check
4. Enable **"Do not allow bypassing the above settings"** for BLOCK-severity changes

---

## ⚙️ Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `RISK_THRESHOLD_WARN` | `40` | Score at or above this value triggers a WARN gate |
| `RISK_THRESHOLD_BLOCK` | `70` | Score at or above this value triggers a BLOCK gate |
| `GRAPH_MAX_DEPTH` | `5` | Maximum hops in `$graphLookup` blast radius search |
| `VECTOR_SEARCH_CANDIDATES` | `150` | `numCandidates` for Atlas Vector Search ANN |
| `VECTOR_SEARCH_LIMIT` | `10` | Top-K incidents returned from semantic search |
| `AGENT_MAX_ITERATIONS` | `12` | Maximum ReAct agent reasoning steps |
| `OPENAI_MODEL` | `gpt-4o` | LLM used for risk synthesis |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model for incident vectors |
| `SUPPORTED_LANGUAGES` | `python,javascript,java` | Languages processed by the AST engine |
| `DRY_RUN` | `false` | If `true`, skips all GitHub API writes |

---

## 🗺️ Roadmap

- [x] **v1.0** — Python AST parser, MongoDB graph traversal, GPT-4o agent, GitHub gate
- [x] **v1.4** — MongoDB Vector Search incident analysis, Slack notifications
- [ ] **v2.0** — JavaScript/TypeScript AST support via tree-sitter
- [ ] **v2.1** — Java and Go parser plugins
- [ ] **v2.2** — GitLab CI and Azure DevOps integrations
- [ ] **v2.3** — Historical risk trend dashboard (Streamlit / Grafana)
- [ ] **v3.0** — Multi-repo blast radius federation (cross-service graph)
- [ ] **v3.1** — Real-time risk score streaming via Server-Sent Events
- [ ] **v3.2** — Self-improving incident embeddings via RLHF feedback loop

---

## 🤝 Contributing

Contributions are welcome from engineers who take production seriously.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature-name`
3. Write tests for your changes: `pytest tests/ -v`
4. Ensure code quality: `ruff check . && mypy deployguard/`
5. Open a Pull Request — DeployGuard AI will assess its own risk

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for our code of conduct and pull request process.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by engineers who believe that the best incident is the one that never happens.**

*DeployGuard AI — Know your blast radius. Ship with confidence.*

</div>
