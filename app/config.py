"""Application configuration, loaded from environment (pydantic-settings).

No secrets are hardcoded. See .env.example for the full set of variables.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
