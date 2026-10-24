"""Vulnerability + audit read endpoints."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models
from app.db.base import get_session

router = APIRouter(prefix="/projects/{project_id}", tags=["findings"])


@router.get("/vulnerabilities")
async def list_vulnerabilities(project_id: UUID, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.Vulnerability).where(models.Vulnerability.project_id == project_id)
    )).scalars().all()
    return [
        {
            "asset": v.asset, "vulnerability_id": v.vulnerability_id, "cve": v.cve,
            "cwe": v.cwe, "severity": v.severity, "status": v.status,
            "confidence": v.confidence, "remediation": v.remediation,
        }
        for v in rows
    ]


@router.get("/audit")
async def list_audit(project_id: UUID, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.AuditLog).where(models.AuditLog.project_id == project_id)
        .order_by(models.AuditLog.started_at)
    )).scalars().all()
    return [
        {
            "agent_id": a.agent_id, "tool_id": a.tool_id, "target": a.target,
            "params": a.params, "scope_allowed": a.scope_allowed,
            "scope_reason": a.scope_reason, "decision": a.decision,
            "result_summary": a.result_summary,
        }
        for a in rows
    ]
