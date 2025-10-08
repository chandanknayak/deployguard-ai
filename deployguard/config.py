"""
config.py — Application-wide configuration via Pydantic BaseSettings.

All settings are sourced from environment variables (or a .env file).
Provides a single, validated, type-safe configuration object imported
across the application as ``from deployguard.config import settings``.
"""

from __future__ import annotations

from functools import lru_cache
import os
from typing import Any, Literal

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseModel

    class BaseSettings(BaseModel):  # type: ignore[no-redef]
        def __init__(self, **values: Any) -> None:
            # Populate from environment variables if not passed
            env_values = {}
            for field_name in self.__class__.model_fields:
                env_key = field_name.upper()
                if env_key in os.environ and field_name not in values:
                    val = os.environ[env_key]
                    field_type = self.__class__.model_fields[field_name].annotation
                    if field_type is SecretStr:
                        env_values[field_name] = SecretStr(val)
                    else:
                        env_values[field_name] = val
            super().__init__(**{**env_values, **values})

    SettingsConfigDict = dict  # type: ignore[misc, assignment]



class Settings(BaseSettings):
    """
    Central settings class for DeployGuard AI.

    All fields map 1-to-1 with environment variables (case-insensitive).
    Secret fields use ``SecretStr`` so values are never leaked in logs or
    repr output.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = Field(default="DeployGuard AI", description="Human-readable service name.")
    app_env: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment — controls log verbosity and debug mode.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Root logger level.",
    )

    # ------------------------------------------------------------------
    # GitHub Integration
    # ------------------------------------------------------------------
    github_webhook_secret: SecretStr = Field(
        default=SecretStr("dev-webhook-secret-token"),
        description=(
            "Secret token configured in the GitHub webhook settings. "
            "Used to verify HMAC-SHA256 signatures on incoming payloads."
        ),
    )
    github_api_token: SecretStr = Field(
        default=SecretStr("ghp_dev_mock_token_for_local_testing"),
        description=(
            "Personal Access Token (PAT) or GitHub App installation token "
            "with 'repo' scope for fetching PR diffs via the REST API."
        ),
    )
    github_api_base_url: AnyHttpUrl = Field(
        default="https://api.github.com",  # type: ignore[assignment]
        description="Base URL for GitHub REST API (override for GitHub Enterprise).",
    )

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------
    max_payload_size_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Maximum accepted webhook payload size in bytes.",
        ge=1024,
    )

    # ------------------------------------------------------------------
    # Diff / AST Analysis
    # ------------------------------------------------------------------
    max_diff_files: int = Field(
        default=200,
        description="Maximum number of changed files to process per PR.",
        ge=1,
    )
    supported_ast_languages: list[str] = Field(
        default=["python"],
        description="File extensions (without dot) eligible for AST analysis.",
    )

    # ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------
    mongodb_uri: SecretStr = Field(
        default=SecretStr("mongodb://localhost:27017"),
        description="MongoDB connection URI (Atlas or local). Use Atlas for Vector Search.",
    )
    mongodb_db_name: str = Field(
        default="deployguard",
        description="MongoDB database name.",
    )
    mongodb_code_graph_collection: str = Field(
        default="code_graph",
        description="Collection storing service dependency graph nodes/edges.",
    )
    mongodb_incidents_collection: str = Field(
        default="incidents",
        description="Collection storing historical incident documents with embeddings.",
    )
    mongodb_assessments_collection: str = Field(
        default="risk_assessments",
        description="Collection for persisting completed risk assessment results.",
    )
    graph_max_depth: int = Field(
        default=5,
        description="Maximum hop depth for $graphLookup blast radius traversal.",
        ge=1,
        le=10,
    )
    vector_search_index_name: str = Field(
        default="incident_embedding_index",
        description="Name of the Atlas Vector Search index on the incidents collection.",
    )
    vector_search_num_candidates: int = Field(
        default=150,
        description="numCandidates for Atlas Vector Search ANN (higher = more recall, slower).",
        ge=10,
    )
    vector_search_limit: int = Field(
        default=5,
        description="Top-K results to return from Vector Search.",
        ge=1,
        le=50,
    )

    # ------------------------------------------------------------------
    # OpenAI / LLM Agent
    # ------------------------------------------------------------------
    openai_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="OpenAI API key for the LLM risk assessment agent.",
    )
    openai_model: str = Field(
        default="gpt-4o",
        description="OpenAI model used for risk synthesis (must support structured outputs).",
    )
    openai_embedding_model: str = Field(
        default="text-embedding-3-small",
        description="OpenAI model used for generating incident embeddings.",
    )
    agent_max_retries: int = Field(
        default=3,
        description="Maximum retry attempts for the OpenAI agent call.",
        ge=1,
    )
    agent_temperature: float = Field(
        default=0.1,
        description="LLM temperature for risk synthesis (low = deterministic / consistent).",
        ge=0.0,
        le=1.0,
    )

    # ------------------------------------------------------------------
    # Diff / AST Analysis
    # ------------------------------------------------------------------
    max_diff_files: int = Field(
        default=200,
        description="Maximum number of changed files to process per PR.",
        ge=1,
    )
    supported_ast_languages: list[str] = Field(
        default=["python"],
        description="File extensions (without dot) eligible for AST analysis.",
    )

    @field_validator("supported_ast_languages", mode="before")
    @classmethod
    def _parse_languages(cls, v: str | list[str]) -> list[str]:
        """Allow comma-separated string or JSON list from env."""
        if isinstance(v, str):
            return [lang.strip().lower() for lang in v.split(",") if lang.strip()]
        return [lang.lower() for lang in v]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton ``Settings`` instance.

    Using ``@lru_cache`` ensures the .env file is read exactly once, even
    in multi-threaded FastAPI startup scenarios.
    """
    return Settings()  # type: ignore[call-arg]


# Convenience alias — import this everywhere:  from deployguard.config import settings
settings: Settings = get_settings()

