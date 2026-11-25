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

from pydantic import AliasChoices, AnyHttpUrl, Field, SecretStr, field_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseModel

    class BaseSettings(BaseModel):  # type: ignore[no-redef]
        def __init__(self, **values: Any) -> None:
            env_values = {}
            for field_name, field_info in self.__class__.model_fields.items():
                if field_name in values:
                    continue
                keys = [field_name.upper()]
                alias = getattr(field_info, "validation_alias", None)
                if isinstance(alias, AliasChoices):
                    keys = [str(c).upper() for c in alias.choices]
                for env_key in keys:
                    if env_key in os.environ:
                        val = os.environ[env_key]
                        env_values[field_name] = (
                            SecretStr(val) if field_info.annotation is SecretStr else val
                        )
                        break
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
    github_client_id: str = Field(
        default="",
        description="GitHub OAuth App Client ID for direct 'Continue with GitHub' login.",
    )
    github_client_secret: SecretStr = Field(
        default=SecretStr(""),
        description="GitHub OAuth App Client Secret for GitHub OAuth token exchange.",
    )

    # ------------------------------------------------------------------
    # Security & Hosting
    # ------------------------------------------------------------------
    max_payload_size_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Maximum accepted webhook payload size in bytes.",
        ge=1024,
    )
    allowed_hosts: list[str] = Field(
        default=["*"],
        description="Trusted hosts allowed by TrustedHostMiddleware.",
    )
    enable_docs: bool = Field(
        default=True,
        description="Expose interactive OpenAPI /docs and /redoc endpoints.",
    )
    public_url: str = Field(
        default="https://deployguard-ai.onrender.com",
        description="Public base URL used for OAuth callbacks and GitHub check target links.",
    )
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("deployguard-secret-change-in-prod-32chars"),
        description="HMAC secret key used to sign user session JWT tokens.",
    )
    token_encryption_key: SecretStr = Field(
        default=SecretStr(""),
        description="Optional encryption secret for GitHub tokens stored in MongoDB.",
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
        validation_alias=AliasChoices("OPENAI_EMBEDDING_MODEL", "EMBEDDING_MODEL"),
        description="OpenAI model used for generating incident embeddings.",
    )
    app_host: str = Field(default="0.0.0.0", description="Bind host for ASGI server.")
    app_port: int = Field(default=8080, ge=1, le=65535, description="Bind port for ASGI server.")

    @property
    def using_default_secrets(self) -> bool:
        """True if JWT/token encryption still relies on public dev placeholder secrets."""
        jwt_val = self.jwt_secret_key.get_secret_value()
        enc_val = self.token_encryption_key.get_secret_value()
        return jwt_val.startswith("deployguard-secret-change-in-prod") and not enc_val
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

    @field_validator("supported_ast_languages", "allowed_hosts", mode="before")
    @classmethod
    def _parse_languages(cls, v: str | list[str]) -> list[str]:
        """Allow comma-separated string or JSON list from env."""
        if isinstance(v, str):
            stripped = v.strip()
            if stripped.startswith("["):
                import json
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(x).strip().lower() for x in parsed if str(x).strip()]
                except Exception:
                    pass
            return [lang.strip().lower() for lang in stripped.split(",") if lang.strip()]
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

