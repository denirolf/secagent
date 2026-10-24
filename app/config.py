"""Application configuration, loaded from environment (pydantic-settings).

No secrets are hardcoded. Secrets may be supplied as environment variables, via a `.env`
file (local dev only), or as files in a secrets directory (Docker/Kubernetes secrets):
set ``SECRETS_DIR`` or mount them under ``/run/secrets`` and each file named after a
setting's alias (e.g. ``/run/secrets/API_KEY_PEPPER``) is read automatically. See
``.env.example`` for the full set of variables and ``docs/DEPLOYMENT.md`` for production
guidance.
"""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_secrets_dir() -> str | None:
    # Honour an explicit SECRETS_DIR; otherwise use /run/secrets when it is mounted.
    explicit = os.environ.get("SECRETS_DIR")
    if explicit:
        return explicit
    return "/run/secrets" if os.path.isdir("/run/secrets") else None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", secrets_dir=_default_secrets_dir()
    )

    # Anthropic / Claude
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    claude_model: str = Field(default="claude-sonnet-4-5", alias="CLAUDE_MODEL")
    claude_fallback_model: str = Field(
        default="claude-haiku-4-5", alias="CLAUDE_FALLBACK_MODEL"
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://secagent:secagent@localhost:5432/secagent",
        alias="DATABASE_URL",
    )
    database_url_sync: str = Field(
        default="postgresql+psycopg2://secagent:secagent@localhost:5432/secagent",
        alias="DATABASE_URL_SYNC",
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # Run limits (defaults; per-project values override)
    default_max_iterations: int = Field(default=12, alias="DEFAULT_MAX_ITERATIONS")
    default_max_tool_calls: int = Field(default=40, alias="DEFAULT_MAX_TOOL_CALLS")
    default_max_budget_usd: float = Field(default=5.0, alias="DEFAULT_MAX_BUDGET_USD")

    # Sandbox
    sandbox_network: str = Field(default="secagent_lab", alias="SANDBOX_NETWORK")
    sandbox_cpu_limit: float = Field(default=1.0, alias="SANDBOX_CPU_LIMIT")
    sandbox_mem_limit: str = Field(default="512m", alias="SANDBOX_MEM_LIMIT")
    sandbox_timeout_seconds: int = Field(default=300, alias="SANDBOX_TIMEOUT_SECONDS")

    # --- Phase 5: production hardening ---------------------------------------------------

    # AuthN/Z. Disabled by default so local dev, the test suite, and the e2e run without
    # credentials; set AUTH_ENABLED=true (and a pepper) for any shared/production deployment.
    auth_enabled: bool = Field(default=False, alias="AUTH_ENABLED")
    # Server-side secret mixed in before hashing API keys. Required when auth is enabled.
    api_key_pepper: str = Field(default="", alias="API_KEY_PEPPER")
    # If set and no API keys exist yet, an admin key with this secret is created on startup.
    bootstrap_admin_key: str = Field(default="", alias="BOOTSTRAP_ADMIN_KEY")
    bootstrap_admin_email: str = Field(default="admin@localhost", alias="BOOTSTRAP_ADMIN_EMAIL")

    # Rate limiting (token bucket, per API key or client IP). Set per-minute to 0 to disable.
    rate_limit_per_minute: int = Field(default=120, alias="RATE_LIMIT_PER_MINUTE")
    rate_limit_burst: int = Field(default=40, alias="RATE_LIMIT_BURST")

    # Observability
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_json: bool = Field(default=False, alias="LOG_JSON")

    # CORS: origins allowed to call the API from a browser (the dashboard).
    cors_origins: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000", alias="CORS_ORIGINS"
    )

    # Cost control. The hard ceiling is each project's max_budget_usd; these per-unit
    # estimates translate run usage into an accrued dollar estimate so that ceiling can
    # bite before a real bill does. They default to 0.0 (estimate off) and should be set
    # to your model's measured per-call/per-iteration cost in production.
    est_cost_per_iteration_usd: float = Field(default=0.0, alias="EST_COST_PER_ITERATION_USD")
    est_cost_per_tool_call_usd: float = Field(default=0.0, alias="EST_COST_PER_TOOL_CALL_USD")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
