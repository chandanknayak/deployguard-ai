"""
agent/risk_agent.py — LLM Risk Assessment Agent with Structured Outputs.

Architecture overview
─────────────────────
┌─────────────────────────────────────────────────────────────────────────┐
│  DESIGN PRINCIPLE: AST + Graph = Deterministic Facts                    │
│                    LLM Agent   = Non-linear Synthesis                   │
│                                                                         │
│  DeployGuard AI deliberately separates concerns:                        │
│                                                                         │
│  1. The AST parser and $graphLookup produce ground truth:               │
│     - Exactly which symbols changed (100% deterministic)                │
│     - Exactly which downstream services are in the blast radius         │
│     - Exactly which historical incidents are semantically similar       │
│                                                                         │
│  2. The LLM agent receives this structured, factual context and         │
│     performs the reasoning task that is genuinely non-linear:           │
│     - Weighing blast radius depth vs. SLA tier vs. incident history     │
│     - Proposing targeted test strategies for the specific change type   │
│     - Recommending a deployment strategy (canary vs. rollback plan)     │
│                                                                         │
│  This is the correct separation — LLMs are excellent at synthesis       │
│  over structured data; they are unreliable for structured extraction    │
│  from raw unstructured code.                                            │
└─────────────────────────────────────────────────────────────────────────┘

Why Structured Outputs (not free-form text)?
─────────────────────────────────────────────
Structured Outputs (``response_format=RiskAssessment``) uses OpenAI's
JSON Schema-constrained generation to guarantee the model returns a
response that exactly matches the Pydantic model schema. This means:

    - No JSON parsing exceptions — the SDK parses + validates automatically.
    - No hallucinated field names or missing required fields.
    - The ``risk_score`` is always an integer in [0, 100].
    - The ``risk_level`` is always one of {"LOW", "MEDIUM", "HIGH", "CRITICAL"}.
    - CI/CD gate logic can trust the output type without defensive checks.

This is fundamentally different from prompt engineering that asks the model
to "respond in JSON" — that approach has ~5% parse failure rates at scale.

Why ``temperature=0.1`` (not 0.0)?
────────────────────────────────────
Pure temperature=0.0 (greedy decoding) produces identical outputs for
identical inputs, which sounds desirable — but for risk assessment, a tiny
amount of temperature produces slightly more varied reasoning paths that
catch edge cases a purely deterministic decode would miss. 0.1 is the
accepted production sweet spot for analytical tasks requiring consistency
but not rigid determinism.

References:
    - OpenAI Structured Outputs: https://platform.openai.com/docs/guides/structured-outputs
    - OpenAI Python SDK: https://github.com/openai/openai-python
"""

from __future__ import annotations

import logging
import textwrap
import time
from enum import StrEnum
from typing import Any

try:
    from openai import AsyncOpenAI, APIError, APITimeoutError, RateLimitError
except ImportError:
    AsyncOpenAI = None  # type: ignore[misc, assignment]
    class APIError(Exception): pass  # type: ignore[no-redef]
    class APITimeoutError(Exception): pass  # type: ignore[no-redef]
    class RateLimitError(Exception): pass  # type: ignore[no-redef]
from pydantic import BaseModel, Field, field_validator

from deployguard.config import settings
from deployguard.db.db_operations import BlastRadiusResult, IncidentRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured Output Schema (Pydantic models)
# ---------------------------------------------------------------------------
# These models serve a dual purpose:
#   1. As the OpenAI Structured Output schema — the model is constrained to
#      produce JSON that exactly matches this schema.
#   2. As the application's internal data contract — downstream code (the
#      CI/CD gate, MongoDB persistence, GitHub PR comment renderer) all
#      consume these typed objects.


class RiskLevel(StrEnum):
    """
    Enumeration of risk severity levels produced by the agent.

    Mapped to CI/CD gate decisions:
        LOW      → PASS (green status check)
        MEDIUM   → WARN (yellow status check, human review requested)
        HIGH     → BLOCK (red status check, merge blocked)
        CRITICAL → BLOCK + ESCALATE (PagerDuty alert + Slack escalation)
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DeploymentStrategy(StrEnum):
    """
    Recommended deployment approach based on the assessed risk level.

    STANDARD:        Normal deploy pipeline — no special precautions.
    CANARY:          Deploy to 1-5% of traffic first; monitor error rates.
    BLUE_GREEN:      Spin up new environment, switch traffic atomically.
    FEATURE_FLAGGED: Deploy behind a feature flag; enable incrementally.
    ROLLBACK_READY:  Ensure a tested rollback plan is documented before deploy.
    BLOCK:           Do not deploy until the identified issues are resolved.
    """

    STANDARD = "STANDARD"
    CANARY = "CANARY"
    BLUE_GREEN = "BLUE_GREEN"
    FEATURE_FLAGGED = "FEATURE_FLAGGED"
    ROLLBACK_READY = "ROLLBACK_READY"
    BLOCK = "BLOCK"


class AffectedServiceSummary(BaseModel):
    """
    A concise summary of a downstream service the agent identifies as at risk.

    This is the agent's *interpretation* of the blast radius data — it may
    add reasoning about *why* a service is at risk, not just that it is.
    """

    service_name: str = Field(
        ...,
        description="Name of the downstream service at risk.",
    )
    sla_tier: str = Field(
        ...,
        description="SLA tier (P0, P1, P2, P3) of this service.",
    )
    risk_reason: str = Field(
        ...,
        description=(
            "One-sentence explanation of why this specific service is at risk "
            "from the proposed change."
        ),
    )
    hops_from_change: int = Field(
        ...,
        description="Number of dependency hops from the changed service to this one.",
        ge=0,
    )


class RiskAssessment(BaseModel):
    """
    The structured risk assessment output produced by the LLM agent.

    This Pydantic model is passed directly to OpenAI as the
    ``response_format`` schema, guaranteeing type-safe structured output.

    Every field has a detailed ``description`` because OpenAI's Structured
    Outputs use the JSON Schema ``description`` field as model guidance —
    it is semantically equivalent to a per-field prompt instruction.
    """

    risk_score: int = Field(
        ...,
        description=(
            "Numeric risk score from 0 to 100. "
            "0-39 = LOW risk (safe to deploy). "
            "40-69 = MEDIUM risk (deploy with extra monitoring). "
            "70-89 = HIGH risk (deployment should be blocked pending review). "
            "90-100 = CRITICAL risk (immediate escalation required, do not deploy)."
        ),
        ge=0,
        le=100,
    )
    risk_level: RiskLevel = Field(
        ...,
        description=(
            "Categorical risk level derived from risk_score. "
            "Must be consistent with the numeric score: "
            "LOW if score 0-39, MEDIUM if 40-69, HIGH if 70-89, CRITICAL if 90-100."
        ),
    )
    confidence: float = Field(
        ...,
        description=(
            "The agent's confidence in this assessment [0.0, 1.0]. "
            "Low confidence (< 0.6) indicates insufficient historical data "
            "or ambiguous blast radius. High confidence (> 0.85) indicates "
            "strong historical precedent and clear blast radius."
        ),
        ge=0.0,
        le=1.0,
    )
    rationale: str = Field(
        ...,
        description=(
            "A structured, multi-sentence explanation of the risk score, citing "
            "specific blast radius findings (service names, SLA tiers, hop counts) "
            "and historical incident matches (incident IDs, similarity scores). "
            "This text is rendered directly in the GitHub PR comment and must be "
            "actionable and precise, not generic."
        ),
        min_length=50,
    )
    affected_services: list[AffectedServiceSummary] = Field(
        default_factory=list,
        description=(
            "The subset of blast radius services the agent considers most at risk. "
            "Prioritise P0 and P1 services. Omit P3 services unless they are "
            "within 1 hop of the change."
        ),
    )
    recommended_tests: list[str] = Field(
        ...,
        description=(
            "Specific, actionable test recommendations targeting the exact symbols "
            "and services identified in the analysis. Do NOT suggest generic advice "
            "like 'add more tests'. Instead, name the specific function/class/endpoint "
            "that needs coverage, and the failure scenario to cover. "
            "Each item should be a single imperative sentence."
        ),
        min_length=1,
    )
    deployment_strategy: DeploymentStrategy = Field(
        ...,
        description=(
            "The recommended deployment approach. Choose based on risk_level: "
            "LOW → STANDARD, MEDIUM → CANARY or FEATURE_FLAGGED, "
            "HIGH → ROLLBACK_READY or BLUE_GREEN, CRITICAL → BLOCK."
        ),
    )
    escalation_required: bool = Field(
        ...,
        description=(
            "True if the change affects P0 services within 2 hops AND has a "
            "historical incident match with similarity > 0.85. In this case, "
            "on-call engineers should be notified before the PR is merged."
        ),
    )
    similar_incident_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Incident IDs from the historical search that directly informed this "
            "assessment. These will be linked in the PR comment for engineer review."
        ),
    )

    @field_validator("risk_level", mode="before")
    @classmethod
    def _validate_risk_level_consistency(cls, v: str, info: Any) -> str:
        """
        Validate that risk_level is consistent with risk_score.

        This validator runs after all fields are parsed. It overrides an
        inconsistent risk_level with the correct value derived from the score,
        preventing the LLM from producing contradictory outputs like
        risk_score=85 with risk_level=LOW.
        """
        score = info.data.get("risk_score")
        if score is None:
            return v
        expected = _score_to_level(score)
        if v != expected:
            logger.warning(
                "risk_level='%s' inconsistent with risk_score=%d. Correcting to '%s'.",
                v,
                score,
                expected,
            )
            return expected
        return v


def _score_to_level(score: int) -> str:
    """Map a numeric risk score to the corresponding RiskLevel string."""
    if score < 40:
        return RiskLevel.LOW
    if score < 70:
        return RiskLevel.MEDIUM
    if score < 90:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Agent context builder — prompt engineering
# ---------------------------------------------------------------------------


def _build_system_prompt() -> str:
    """
    Return the system prompt that defines the agent's role and reasoning rules.

    The system prompt is static — it establishes the agent's identity,
    scoring rubric, and output constraints once per conversation. This
    maximises the user message's context window budget for factual data.
    """
    return textwrap.dedent("""
        You are DeployGuard AI, an expert production systems risk analyst embedded
        in a CI/CD pipeline. Your role is to assess the deployment risk of a pull
        request by synthesising three sources of ground-truth evidence:

        1. CHANGED SYMBOLS: The exact Python functions, classes, and API endpoints
           modified by the PR (extracted deterministically via AST parsing).

        2. BLAST RADIUS: The transitive downstream services affected by this change,
           computed via MongoDB $graphLookup. Each service includes its SLA tier
           (P0 = most critical), the number of hops from the change, and owner team.

        3. HISTORICAL INCIDENTS: The top-K semantically similar past outages,
           retrieved via MongoDB Atlas Vector Search on incident embeddings.
           Each includes a similarity score [0-1] and root cause tags.

        SCORING RUBRIC:
        ──────────────
        Base score starts at 0. Add points for each risk factor:

          Blast Radius:
            +30 if any P0 service is within 2 hops
            +20 if any P0 service is within 3-5 hops
            +15 if any P1 service is within 2 hops
            +10 if total affected nodes > 10

          Historical Precedent:
            +25 if any incident has similarity >= 0.90 AND severity P0/P1
            +15 if any incident has similarity >= 0.80 AND severity P0/P1
            +10 if any incident has similarity >= 0.70

          Change Surface:
            +10 if any changed symbol is an API route/endpoint handler
            +10 if more than 3 symbols were modified
            +5  if an __init__ or base class constructor was modified

          Test Coverage Signal:
            -10 if the changed symbols have high test coverage (>80%)
            +10 if changed symbols appear to have low/no test coverage

        Cap at 100. A score of 0 indicates negligible risk.

        OUTPUT RULES:
        ─────────────
        1. The rationale MUST cite specific evidence: name the incident ID,
           the service name, the similarity score. Do not write generic statements.
        2. recommended_tests MUST name the specific function or endpoint to test.
        3. Never recommend BLOCK unless risk_score >= 70.
        4. escalation_required is ONLY true if P0 is within 2 hops AND
           a historical incident has similarity > 0.85.
        5. Be concise but precise. Engineering managers read the rationale;
           on-call engineers read the recommended_tests.
    """).strip()


def _build_user_message(
    pr_title: str,
    pr_author: str,
    changed_symbols: list[dict[str, Any]],
    blast_radius: BlastRadiusResult,
    similar_incidents: list[IncidentRecord],
) -> str:
    """
    Build the structured user message containing all factual context.

    This message is the agent's "evidence package" — it contains only
    structured data derived from deterministic sources (AST + MongoDB).
    No interpretation or opinion is injected here; that is the agent's job.

    Args:
        pr_title:         The pull request title.
        pr_author:        The GitHub login of the PR author.
        changed_symbols:  List of symbol dicts from the AST analysis stage.
        blast_radius:     ``BlastRadiusResult`` from $graphLookup.
        similar_incidents: ``IncidentRecord`` list from $vectorSearch.

    Returns:
        A formatted plain-text string optimised for LLM consumption.
    """
    # Format changed symbols
    symbol_lines = []
    for sym in changed_symbols:
        entry = f"  - [{sym.get('kind', 'function')}] {sym.get('symbol', sym.get('qualified_name', 'unknown'))}"
        if sym.get("route"):
            entry += f"  →  API: {sym['route']}"
        entry += f"  (lines {sym.get('lines', '?')}, {sym.get('modified_line_count', '?')} modified lines)"
        symbol_lines.append(entry)

    symbols_text = "\n".join(symbol_lines) if symbol_lines else "  (no symbols detected)"

    # Format blast radius
    blast_lines = []
    for node in blast_radius.affected_nodes[:20]:  # Cap display at 20 nodes
        blast_lines.append(
            f"  - {node.service_name} "
            f"[SLA: {node.sla_tier}] "
            f"[hops: {node.hops}] "
            f"[team: {node.owner_team}]"
        )
    blast_text = "\n".join(blast_lines) if blast_lines else "  (no downstream dependencies found)"

    # Format historical incidents
    incident_lines = []
    for inc in similar_incidents:
        incident_lines.append(
            f"  - [{inc.incident_id}] \"{inc.title}\"\n"
            f"    Severity: {inc.severity} | Duration: {inc.duration_minutes} min | "
            f"Similarity: {inc.similarity_score:.3f}\n"
            f"    Tags: {', '.join(inc.root_cause_tags)}\n"
            f"    Postmortem: {inc.postmortem_url or 'N/A'}"
        )
    incidents_text = "\n".join(incident_lines) if incident_lines else "  (no similar historical incidents found)"

    return textwrap.dedent(f"""
        PULL REQUEST CONTEXT:
        ─────────────────────
        Title:  {pr_title}
        Author: {pr_author}

        ══════════════════════════════════════════════
        EVIDENCE 1: CHANGED SYMBOLS (from AST parser)
        ══════════════════════════════════════════════
        {symbols_text}

        ══════════════════════════════════════════════
        EVIDENCE 2: BLAST RADIUS (from $graphLookup)
        ══════════════════════════════════════════════
        Origin service: {blast_radius.origin_service}
        Total downstream nodes: {blast_radius.total_affected}
        Has P0 impact: {blast_radius.has_p0_impact}
        Has P1 impact: {blast_radius.has_p1_impact}
        Max traversal depth: {blast_radius.max_depth_reached}

        Affected downstream services:
{blast_text}

        ══════════════════════════════════════════════
        EVIDENCE 3: SIMILAR HISTORICAL INCIDENTS ($vectorSearch)
        ══════════════════════════════════════════════
{incidents_text}

        ══════════════════════════════════════════════
        TASK
        ══════════════════════════════════════════════
        Based on the evidence above, produce a RiskAssessment using the
        scoring rubric defined in your system prompt. Be specific and cite
        the exact evidence (incident IDs, service names, similarity scores).
    """).strip()


# ---------------------------------------------------------------------------
# Risk Assessment Agent
# ---------------------------------------------------------------------------


class RiskAssessmentAgent:
    """
    Async LLM agent that synthesises AST + graph + vector evidence into a
    structured ``RiskAssessment`` using OpenAI's Structured Outputs API.

    The agent is designed to be instantiated once and reused across multiple
    assessments (the AsyncOpenAI client maintains an HTTP connection pool).

    Usage::

        agent = RiskAssessmentAgent()
        assessment = await agent.assess(
            pr_title="refactor: optimize charge_card retry logic",
            pr_author="elena.vasquez",
            changed_symbols=[...],
            blast_radius=blast_radius_result,
            similar_incidents=incident_records,
        )
        print(assessment.risk_score, assessment.risk_level)
        print(assessment.model_dump_json(indent=2))
    """

    def __init__(self) -> None:
        if AsyncOpenAI is None:
            raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")
        # Keep SDK internal retries low & bounded timeout so CI/PR pipelines never stall
        self._client = AsyncOpenAI(
            api_key=settings.openai_api_key.get_secret_value(),
            timeout=10.0,
            max_retries=1,
        )
        self._model = settings.openai_model
        self._system_prompt = _build_system_prompt()
        self._disabled_until: float = 0.0

    @property
    def is_temporarily_disabled(self) -> bool:
        return time.monotonic() < self._disabled_until

    def _trip_circuit_if_quota_error(self, exc: Exception) -> bool:
        msg = str(exc).lower()
        if "insufficient_quota" in msg or "no credits" in msg or "billing" in msg:
            self._disabled_until = time.monotonic() + 300.0
            logger.warning("OpenAI quota exhausted — tripping 5m circuit breaker to deterministic engine.")
            return True
        return False

    async def assess(
        self,
        pr_title: str,
        pr_author: str,
        changed_symbols: list[dict[str, Any]],
        blast_radius: BlastRadiusResult,
        similar_incidents: list[IncidentRecord],
    ) -> RiskAssessment:
        if self.is_temporarily_disabled:
            raise RuntimeError("OpenAI agent temporarily bypassed (quota circuit breaker active).")
        """
        Run the risk assessment agent and return a validated ``RiskAssessment``.

        This method calls the OpenAI Chat Completions API with:
            - A structured system prompt defining the scoring rubric.
            - A user message containing the formatted evidence package.
            - ``response_format=RiskAssessment`` to enforce structured output.
            - Retry logic for transient API errors (rate limits, timeouts).

        Args:
            pr_title:         Pull request title for context.
            pr_author:        GitHub login of the PR author.
            changed_symbols:  Serialised AST analysis result (list of dicts).
            blast_radius:     ``BlastRadiusResult`` from the $graphLookup stage.
            similar_incidents: ``IncidentRecord`` list from the $vectorSearch stage.

        Returns:
            A validated ``RiskAssessment`` Pydantic model instance.

        Raises:
            ``openai.RateLimitError``:   If rate limit is exceeded after retries.
            ``openai.APITimeoutError``:  If the API call times out after retries.
            ``openai.APIError``:         For other irrecoverable API errors.
            ``pydantic.ValidationError``: If the LLM output is structurally invalid
                (extremely rare with Structured Outputs but possible on model refusals).
        """
        user_message = _build_user_message(
            pr_title=pr_title,
            pr_author=pr_author,
            changed_symbols=changed_symbols,
            blast_radius=blast_radius,
            similar_incidents=similar_incidents,
        )

        logger.info(
            "Invoking risk agent: model=%s, symbols=%d, blast_radius_nodes=%d, incidents=%d.",
            self._model,
            len(changed_symbols),
            blast_radius.total_affected,
            len(similar_incidents),
        )

        start_time = time.monotonic()
        assessment = await self._call_with_retry(user_message)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        logger.info(
            "Risk assessment complete: score=%d, level=%s, confidence=%.2f, elapsed=%.0fms.",
            assessment.risk_score,
            assessment.risk_level,
            assessment.confidence,
            elapsed_ms,
        )
        return assessment

    async def _call_with_retry(self, user_message: str) -> RiskAssessment:
        """
        Call the OpenAI Structured Outputs API with exponential back-off retry.

        Retries on:
            - ``RateLimitError`` (429) — back off and retry up to max_retries.
            - ``APITimeoutError``      — network timeout, safe to retry.

        Does NOT retry on:
            - ``APIError`` with 4xx status (client errors are not transient).
            - Pydantic validation errors (structural issue, not transient).

        Args:
            user_message: The formatted evidence package for the agent.

        Returns:
            A validated ``RiskAssessment`` model instance.
        """
        last_error: Exception | None = None

        for attempt in range(1, settings.agent_max_retries + 1):
            try:
                return await self._call_api(user_message)

            except RateLimitError as exc:
                if self._trip_circuit_if_quota_error(exc):
                    raise
                wait = 2 ** attempt  # Exponential back-off: 2s, 4s, 8s
                logger.warning(
                    "OpenAI rate limit hit (attempt %d/%d). Retrying in %ds.",
                    attempt,
                    settings.agent_max_retries,
                    wait,
                )
                import asyncio
                await asyncio.sleep(wait)
                last_error = exc

            except APITimeoutError as exc:
                logger.warning(
                    "OpenAI API timeout (attempt %d/%d). Retrying...",
                    attempt,
                    settings.agent_max_retries,
                )
                last_error = exc

            except APIError as exc:
                # Non-transient API errors (4xx) — do not retry
                logger.error("OpenAI API error (non-retryable): %s", exc)
                raise

        # All retries exhausted
        raise last_error or RuntimeError("All API retry attempts exhausted.")

    async def _call_api(self, user_message: str) -> RiskAssessment:
        """
        Make a single OpenAI Structured Outputs API call.

        Uses ``client.beta.chat.completions.parse()`` — the high-level
        method that accepts a Pydantic model class as ``response_format``
        and automatically validates + parses the response into that model.

        This is fundamentally different from ``client.chat.completions.create()``
        with ``response_format={"type": "json_object"}`` — that approach
        merely requests JSON-formatted text with no schema enforcement.
        ``parse()`` uses the model's JSON Schema for constrained generation.

        Args:
            user_message: The formatted evidence package.

        Returns:
            A validated ``RiskAssessment`` instance.

        Raises:
            ``openai.APIError``: On API failure.
            ``pydantic.ValidationError``: On schema mismatch (extremely rare).
        """
        response = await self._client.beta.chat.completions.parse(
            model=self._model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user",   "content": user_message},
            ],
            response_format=RiskAssessment,
            temperature=settings.agent_temperature,
            # max_tokens: Structured output responses are typically 400-800 tokens.
            # Setting an upper bound prevents runaway generation on edge cases.
            max_tokens=2048,
        )

        # The SDK automatically validates the response against the Pydantic schema.
        # ``message.parsed`` is a ``RiskAssessment`` instance (or None on refusal).
        message = response.choices[0].message

        if message.refusal:
            # The model refused to complete (safety filter or policy violation).
            # Treat as a blocking risk — we cannot assess something the model refuses.
            logger.warning("OpenAI model refused the request: %s", message.refusal)
            return RiskAssessment(
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                confidence=0.0,
                rationale=(
                    f"Risk assessment could not be completed — the model refused "
                    f"the request: {message.refusal}. Blocking as a safety precaution."
                ),
                affected_services=[],
                recommended_tests=["Manual review required before deployment."],
                deployment_strategy=DeploymentStrategy.BLOCK,
                escalation_required=True,
                similar_incident_ids=[],
            )

        if message.parsed is None:
            raise ValueError(
                "OpenAI returned a null parsed response with no refusal. "
                "This is an unexpected SDK state."
            )

        # Log token usage for cost monitoring
        if response.usage:
            logger.info(
                "OpenAI token usage: prompt=%d, completion=%d, total=%d.",
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
                response.usage.total_tokens,
            )

        return message.parsed

    async def get_embedding(self, text: str) -> list[float]:
        if self.is_temporarily_disabled:
            raise RuntimeError("OpenAI embeddings temporarily bypassed (quota circuit breaker active).")
        try:
            response = await self._client.embeddings.create(
                model=settings.openai_embedding_model,
                input=text,
                encoding_format="float",
            )
            embedding = response.data[0].embedding
            logger.debug(
                "Embedding generated: model=%s, dimensions=%d.",
                settings.openai_embedding_model,
                len(embedding),
            )
            return embedding
        except Exception as exc:
            self._trip_circuit_if_quota_error(exc)
            raise

    async def close(self) -> None:
        """
        Close the underlying AsyncOpenAI HTTP client.

        Call this during application shutdown to cleanly drain the connection
        pool. In FastAPI, this belongs in the ``lifespan`` context manager
        after ``yield``.
        """
        await self._client.close()

