"""FastAPI application factory for the Autonomous Security Agent Platform (Phase 1)."""
from __future__ import annotations

from fastapi import FastAPI

from app.api import findings, projects, runs, ws
from app.engine.registry import ToolRegistry
from app.engine.tools.builtin import ALL_PHASE1_TOOLS


def create_app() -> FastAPI:
    app = FastAPI(
        title="Autonomous Security Agent Platform",
        version="0.1.0",
        description="Authorized, isolated-lab security testing. Scope-gated and audited.",
    )

    @app.get("/health")
    async def health():
        reg = ToolRegistry(ALL_PHASE1_TOOLS)
        return {"status": "ok", "tools": reg.ids()}

    app.include_router(projects.router)
    app.include_router(runs.router)
    app.include_router(findings.router)
    app.include_router(ws.router)
    return app


app = create_app()
