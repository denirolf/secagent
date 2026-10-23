"""Async persistence helpers mapping engine/orchestrator results into the schema."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.orchestrator import OrchestratorResult
from app.db import models
from app.engine.scope import AuthorizedScope
from app.contracts.enums import ScopeKind


async def create_project(
    session: AsyncSession, *, name: str, autonomy_level: int,
    max_iterations: int, max_tool_calls: int, max_budget_usd: float,
) -> models.Project:
    proj = models.Project(
        name=name, autonomy_level=autonomy_level, max_iterations=max_iterations,
        max_tool_calls=max_tool_calls, max_budget_usd=max_budget_usd,
    )
    session.add(proj)
    await session.flush()
    return proj


async def add_scope(
    session: AsyncSession, project_id: UUID, *, kind: str, value: str,
    is_lab_env: bool, note: str = "",
) -> models.AuthorizedScope:
    sc = models.AuthorizedScope(
        project_id=project_id, kind=kind, value=value, is_lab_env=is_lab_env, note=note
    )
    session.add(sc)
    await session.flush()
    return sc


async def get_project(session: AsyncSession, project_id: UUID) -> models.Project | None:
    return await session.get(models.Project, project_id)


async def load_scopes(session: AsyncSession, project_id: UUID) -> list[AuthorizedScope]:
    rows = (await session.execute(
        select(models.AuthorizedScope).where(models.AuthorizedScope.project_id == project_id)
    )).scalars().all()
    return [
        AuthorizedScope(id=r.id, kind=ScopeKind(r.kind), value=r.value, is_lab_env=r.is_lab_env)
        for r in rows
    ]


async def create_run(
    session: AsyncSession, project_id: UUID, objective: str
) -> models.Run:
    run = models.Run(project_id=project_id, objective=objective, state="running")
    session.add(run)
    await session.flush()
    return run


async def persist_result(
    session: AsyncSession, *, project_id: UUID, run: models.Run,
    result: OrchestratorResult, report: dict,
) -> None:
    # Audit logs (append-only).
    for e in result.audit:
        session.add(models.AuditLog(
            project_id=project_id, agent_id=e.agent_id, tool_id=e.tool_id,
            target=e.target, params=e.to_row()["params"], scope_allowed=e.scope_allowed,
            scope_reason=e.scope_reason[:255], decision=e.decision,
            result_summary=e.result_summary,
        ))

    asset_row: models.Asset | None = None
    if result.recon is not None:
        services = {
            str(s["port"]): {"service": s["service"], "product": s["product"],
                             "version": s["version"], "state": s["state"]}
            for s in result.recon.services
        }
        asset_row = models.Asset(
            project_id=project_id, host=result.recon.host,
            ip=(result.recon.http or {}).get("resolved_ip"), services=services,
        )
        session.add(asset_row)
        await session.flush()

    # Validation outcomes (Phase 2) keyed by finding id; these drive status elevation.
    outcomes = {v.finding_vuln_id: v for v in result.validations}

    for f in result.findings:
        outcome = outcomes.get(f.vulnerability_id)
        status = outcome.new_status.value if outcome else f.status.value
        vuln = models.Vulnerability(
            project_id=project_id, run_id=run.id,
            asset_id=asset_row.id if asset_row else None, asset=f.asset,
            vulnerability_id=f.vulnerability_id, cve=f.cve, cwe=f.cwe,
            severity=f.severity.value, status=status, confidence=f.confidence.value,
            recommended_validation=f.recommended_validation, remediation=f.remediation,
        )
        session.add(vuln)
        await session.flush()
        for ev in f.evidence:
            session.add(models.Evidence(
                vulnerability_id=vuln.id, kind=ev.kind, summary=ev.summary, data_ref=ev.data_ref
            ))
        if outcome is not None:
            session.add(models.ValidationResult(
                vulnerability_id=vuln.id, environment=outcome.environment,
                reproduced=outcome.reproduced, notes=outcome.notes,
            ))
            for ev in outcome.evidence:
                session.add(models.Evidence(
                    vulnerability_id=vuln.id, kind=ev.kind, summary=ev.summary
                ))

    session.add(models.Report(project_id=project_id, run_id=run.id, format="json", data=report))

    run.state = result.state
    run.tool_calls_used = result.tool_calls_used
    run.cost_usd = result.cost_usd
    from datetime import datetime, timezone
    run.finished_at = datetime.now(timezone.utc)
