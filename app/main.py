"""FastAPI application factory for the Autonomous Security Agent Platform.

Phase 5 adds the production-hardening layer around the same scope-gated engine:
API-key auth + RBAC, rate limiting, structured logging with request IDs, Prometheus
metrics, and liveness/readiness probes. None of it can relax the Scope Engine, sandbox,
approval, or audit guarantees — those live in the execution engine and are unchanged.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text

from app.api import admin, findings, knowledge, overview, projects, runs, ws
from app.config import get_settings
from app.db import models
from app.db.base import SessionLocal, engine
from app.engine.registry import ToolRegistry
from app.engine.tools.builtin import ALL_PHASE1_TOOLS
from app.observability import metrics
from app.observability.logging import configure_logging
from app.observability.middleware import ObservabilityMiddleware
from app.security.auth import hash_secret, parse_token
from app.security.deps import require_viewer
from app.security.ratelimit import RateLimiter, RateLimitMiddleware

_log = logging.getLogger("secagent.startup")


async def _maybe_bootstrap_admin_key() -> None:
    """When auth is on and no keys exist, adopt BOOTSTRAP_ADMIN_KEY if it is a valid
    ``sk-...`` token, else warn loudly that the API will reject every request until a key
    is created. Never logs a secret; failures here do not crash startup."""
    settings = get_settings()
    if not settings.auth_enabled:
        return
    try:
        async with SessionLocal() as session:
            count = (
                await session.execute(select(func.count()).select_from(models.ApiKey))
            ).scalar() or 0
            if count:
                return
            parsed = parse_token(settings.bootstrap_admin_key) if settings.bootstrap_admin_key else None
            if parsed and settings.api_key_pepper:
                prefix, secret = parsed
                session.add(models.ApiKey(
                    prefix=prefix,
                    key_hash=hash_secret(secret, settings.api_key_pepper),
                    name="bootstrap-admin", role="admin",
                ))
                await session.commit()
                _log.warning("Bootstrapped admin API key (prefix=%s) from BOOTSTRAP_ADMIN_KEY.", prefix)
            else:
                _log.warning(
                    "AUTH_ENABLED is on but no API keys exist. The API will reject all "
                    "requests until an admin key is created with scripts/create_api_key.py, "
                    "or BOOTSTRAP_ADMIN_KEY is set to an 'sk-...' token (with API_KEY_PEPPER)."
                )
    except Exception:  # pragma: no cover - startup resilience
        _log.exception("admin-key bootstrap check failed; continuing to start")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    await _maybe_bootstrap_admin_key()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="Autonomous Security Agent Platform",
        version="0.5.0",
        description="Authorized, isolated-lab security testing. Scope-gated and audited.",
        lifespan=_lifespan,
    )

    # Middleware is added innermost-first; the last add is outermost at request time.
    # Order at request time: CORS -> Observability -> RateLimit -> route.
    limiter = (
        RateLimiter(
            capacity=settings.rate_limit_burst,
            refill_per_sec=settings.rate_limit_per_minute / 60.0,
        )
        if settings.rate_limit_per_minute > 0
        else None
    )
    app.add_middleware(RateLimitMiddleware, limiter=limiter)
    app.add_middleware(ObservabilityMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["ops"])
    async def health():
        """Liveness: the process is up and tools are registered."""
        reg = ToolRegistry(ALL_PHASE1_TOOLS)
        return {"status": "ok", "tools": reg.ids()}

    @app.get("/ready", tags=["ops"])
    async def ready(response: Response):
        """Readiness: the database is reachable."""
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return {"status": "ready"}
        except Exception as exc:  # pragma: no cover - needs a down DB
            response.status_code = 503
            return {"status": "not_ready", "detail": str(exc)[:200]}

    @app.get("/metrics", tags=["ops"])
    async def prometheus_metrics(response: Response):
        if not settings.metrics_enabled:
            response.status_code = 404
            return {"detail": "metrics disabled"}
        data, content_type = metrics.render()
        return Response(content=data, media_type=content_type)

    # Read endpoints require at least 'viewer'; mutating routes raise the bar per-route.
    gate = [Depends(require_viewer)]
    app.include_router(projects.router, dependencies=gate)
    app.include_router(runs.router, dependencies=gate)
    app.include_router(findings.router, dependencies=gate)
    app.include_router(knowledge.router, dependencies=gate)
    app.include_router(overview.router, dependencies=gate)
    app.include_router(admin.router)  # admin dependency is declared on the router itself
    app.include_router(ws.router)     # WebSocket handshake is not gated by the bearer dep
    return app


app = create_app()
