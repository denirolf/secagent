"""Overview + agent status endpoints for the dashboard."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.contracts.enums import AgentId
from app.db import models
from app.db.base import get_session

router = APIRouter(tags=["overview"])

# Phase in which each agent is implemented (for the dashboard's Agents view).
_AGENTS = [
    {"agent_id": AgentId.ORCHESTRATOR.value, "name": "Master Orchestrator", "phase": 1},
    {"agent_id": AgentId.RECON.value, "name": "Reconnaissance", "phase": 1},
    {"agent_id": AgentId.VULN_ANALYSIS.value, "name": "Vulnerability Analysis", "phase": 1},
    {"agent_id": AgentId.EXPLOIT_RESEARCH.value, "name": "Exploit Research", "phase": 2},
    {"agent_id": AgentId.EXPLOIT_VALIDATION.value, "name": "Exploit Validation", "phase": 2},
    {"agent_id": AgentId.AUTH_SECURITY.value, "name": "Authentication Security", "phase": 3},
    {"agent_id": AgentId.REASONING.value, "name": "Security Reasoning", "phase": 3},
    {"agent_id": AgentId.REPORTING.value, "name": "Reporting", "phase": 1},
]


async def _count(session: AsyncSession, model, *where) -> int:
    stmt = select(func.count()).select_from(model)
    for w in where:
        stmt = stmt.where(w)
    return int((await session.execute(stmt)).scalar() or 0)


@router.get("/overview")
async def overview(session: AsyncSession = Depends(get_session)):
    projects = await _count(session, models.Project)
    assets = await _count(session, models.Asset)
    vulns = await _count(session, models.Vulnerability)
    lab_confirmed = await _count(session, models.Vulnerability,
                                 models.Vulnerability.status == "lab_confirmed")
    confirmed_authorized = await _count(session, models.Vulnerability,
                                        models.Vulnerability.status == "confirmed_authorized")
    runs_running = await _count(session, models.Run, models.Run.state == "running")
    runs_total = await _count(session, models.Run)
    return {
        "projects": projects,
        "assets": assets,
        "vulnerabilities": vulns,
        "lab_confirmed": lab_confirmed,
        "confirmed_authorized": confirmed_authorized,
        "agents": len(_AGENTS),
        "runs_running": runs_running,
        "runs_total": runs_total,
    }


@router.get("/agents")
async def agents():
    return _AGENTS


@router.get("/projects/{project_id}/assets")
async def list_assets(project_id, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.Asset).where(models.Asset.project_id == project_id)
    )).scalars().all()
    return [{"host": a.host, "ip": a.ip, "services": a.services} for a in rows]
