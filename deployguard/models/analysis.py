"""
models/analysis.py — Pydantic models representing the output of DeployGuard's
AST analysis pipeline.

These models flow through the system from the AST analyzer all the way to the
MongoDB audit log and the GitHub PR comment renderer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """
    Enumeration of possible gate decisions produced by the analysis pipeline.

    Thresholds are governed by ``RISK_THRESHOLD_WARN`` and
    ``RISK_THRESHOLD_BLOCK`` in ``config.py``.
    """

    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"  # Analysis could not be completed


class SymbolKind(StrEnum):
    """
    The syntactic category of a Python symbol detected by the AST analyzer.
    """

    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    CLASS = "class"
    METHOD = "method"
    ASYNC_METHOD = "async_method"
    FASTAPI_ROUTE = "fastapi_route"          # @app.get / @router.post / etc.
    FLASK_ROUTE = "flask_route"              # @app.route(...)
    DJANGO_VIEW = "django_view"              # Detected via CBV / FBV heuristics
    LAMBDA = "lambda"


class ModifiedHunk(BaseModel):
    """
    A contiguous block of modified lines within a single file, as parsed
    from the unified diff ``@@`` hunk header.
    """

    start_line: int = Field(..., description="First modified line number in the *new* file.", ge=1)
    end_line: int = Field(..., description="Last modified line number in the *new* file.", ge=1)
    line_count: int = Field(..., description="Total number of lines in this hunk.", ge=1)

    @property
    def line_range(self) -> range:
        """Return a Python ``range`` spanning this hunk (inclusive)."""
        return range(self.start_line, self.end_line + 1)


class AffectedSymbol(BaseModel):
    """
    A single Python symbol (function, class, route handler, etc.) whose
    definition overlaps with at least one modified line in the diff.
    """

    name: str = Field(..., description="Bare symbol name (e.g. 'charge_card').")
    qualified_name: str = Field(
        ...,
        description="Fully qualified dotted name (e.g. 'payment_service.PaymentHandler.charge_card').",
    )
    kind: SymbolKind = Field(..., description="Syntactic category of this symbol.")
    start_line: int = Field(..., description="First line of the symbol's definition in the source file.", ge=1)
    end_line: int = Field(..., description="Last line of the symbol's definition in the source file.", ge=1)

    # Route-specific metadata (populated for API endpoint symbols only)
    http_methods: list[str] = Field(
        default_factory=list,
        description="HTTP methods if this symbol is an API route handler (e.g. ['GET', 'POST']).",
    )
    route_path: str | None = Field(
        default=None,
        description="URL path pattern if this symbol is an API route handler (e.g. '/api/v1/charge').",
    )
    decorator_names: list[str] = Field(
        default_factory=list,
        description="Names of all decorators applied to this symbol.",
    )

    # Overlap details
    modified_lines_overlap: list[int] = Field(
        default_factory=list,
        description="The specific line numbers (from the diff) that fall inside this symbol.",
    )


class FileAnalysis(BaseModel):
    """
    Complete analysis result for a single changed file in the PR.
    """

    filename: str = Field(..., description="Repo-relative file path (e.g. 'src/payments/charge.py').")
    language: str = Field(..., description="Detected programming language (e.g. 'python').")
    is_ast_eligible: bool = Field(
        ...,
        description="False if the file is not in a supported language or could not be parsed.",
    )
    parse_error: str | None = Field(
        default=None,
        description="Human-readable error message if AST parsing failed for this file.",
    )

    total_modified_lines: int = Field(
        default=0,
        description="Total count of modified lines (additions + context) across all hunks.",
        ge=0,
    )
    modified_hunks: list[ModifiedHunk] = Field(
        default_factory=list,
        description="Parsed hunk ranges from the unified diff for this file.",
    )
    affected_symbols: list[AffectedSymbol] = Field(
        default_factory=list,
        description="Symbols whose definitions overlap with modified lines.",
    )

    @property
    def has_api_changes(self) -> bool:
        """Return True if any affected symbol is an API route/endpoint handler."""
        api_kinds = {SymbolKind.FASTAPI_ROUTE, SymbolKind.FLASK_ROUTE, SymbolKind.DJANGO_VIEW}
        return any(s.kind in api_kinds for s in self.affected_symbols)


class AnalysisResult(BaseModel):
    """
    Top-level result object produced by the DeployGuard analysis pipeline
    for a single pull request.

    This is the canonical output written to MongoDB and rendered as a GitHub
    PR comment / status check.
    """

    assessment_id: str = Field(..., description="Unique identifier for this analysis run (UUID4).")
    pr_number: int = Field(..., description="GitHub pull request number.", ge=1)
    repo_full_name: str = Field(..., description="'owner/repo' of the target repository.")
    head_sha: str = Field(..., description="The commit SHA that was analysed.")

    risk_level: RiskLevel = Field(
        default=RiskLevel.UNKNOWN,
        description="Gate decision — PASS, WARN, BLOCK, or UNKNOWN.",
    )
    risk_score: int | None = Field(
        default=None,
        description="Numeric risk score 0-100 (populated by the LLM agent stage).",
        ge=0,
        le=100,
    )

    files_analysed: list[FileAnalysis] = Field(
        default_factory=list,
        description="Per-file analysis results.",
    )
    total_affected_symbols: int = Field(
        default=0,
        description="Total count of unique symbols affected across all files.",
        ge=0,
    )
    has_api_surface_changes: bool = Field(
        default=False,
        description="True if any changed file contains API route/endpoint modifications.",
    )

    # Pipeline timing metadata
    analysis_duration_ms: float = Field(
        default=0.0,
        description="Wall-clock time for the AST analysis stage in milliseconds.",
    )

    # Raw context bundle passed downstream to the LLM agent stage
    context_bundle: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured context emitted for consumption by the LLM risk agent.",
    )

    # Detailed LLM agent assessment output
    agent_assessment: dict[str, Any] | None = Field(
        default=None,
        description="Structured RiskAssessment output generated by the LLM agent.",
    )

    # Blast radius summary
    blast_radius_summary: dict[str, Any] | None = Field(
        default=None,
        description="Summary of downstream affected services and critical SLA paths.",
    )

    error: str | None = Field(
        default=None,
        description="Top-level error message if the entire analysis pipeline failed.",
    )

