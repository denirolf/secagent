"""Run endpoints: start a run, check status, fetch the report."""
from __future__ import annotations

import asyncio
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import RunIn, RunOut
from app.db import models, repo
from app.db.base import get_session
from app.reporting.report import render_html, render_markdown, render_pdf
from app.security.deps import require_operator
from app.services.runner import execute_run

router = APIRouter(tags=["runs"])

# Tracks background run tasks so they are not garbage-collected.
_tasks: set[asyncio.Task] = set()


@router.post("/projects/{project_id}/runs", response_model=RunOut,
             dependencies=[Depends(require_operator)])
async def start_run(project_id: UUID, body: RunIn, session: AsyncSession = Depends(get_session)):
    proj = await repo.get_project(session, project_id)
    if proj is None:
        raise HTTPException(404, "project not found")
    run = await repo.create_run(session, project_id, body.objective)
    await session.commit()

    async def _bg():
        try:
            await execute_run(
                project_id=project_id, run_id=run.id, objective=body.objective,
                target=body.target, use_llm=body.use_llm, run_nuclei=body.run_nuclei,
                validate_in_lab=body.validate_in_lab, lab_container=body.lab_container,
                auth_check=body.auth_check, reasoning=body.reasoning,
            )
        except Exception as exc:  # noqa: BLE001
            from app.db.base import SessionLocal
            async with SessionLocal() as s:
                r = await s.get(models.Run, run.id)
                if r:
                    r.state = "failed"
                    r.objective = f"{r.objective} [error: {exc}]"[:2000]
                    await s.commit()

    task = asyncio.create_task(_bg())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return RunOut(run_id=run.id, project_id=project_id, state="running")


@router.get("/projects/{project_id}/runs")
async def list_runs(project_id: UUID, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.Run).where(models.Run.project_id == project_id)
        .order_by(models.Run.started_at.desc())
    )).scalars().all()
    return [
        {"run_id": r.id, "objective": r.objective, "state": r.state,
         "tool_calls_used": r.tool_calls_used, "cost_usd": r.cost_usd,
         "started_at": r.started_at.isoformat() if r.started_at else None}
        for r in rows
    ]


@router.get("/runs/{run_id}")
async def get_run(run_id: UUID, session: AsyncSession = Depends(get_session)):
    run = await session.get(models.Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return {
        "run_id": run.id, "project_id": run.project_id, "state": run.state,
        "objective": run.objective, "tool_calls_used": run.tool_calls_used,
        "cost_usd": run.cost_usd,
    }


@router.get("/runs/{run_id}/report")
async def get_report(
    run_id: UUID,
    format: str = Query("json", pattern="^(json|md|markdown|html|pdf)$"),
    session: AsyncSession = Depends(get_session),
):
    row = (await session.execute(
        select(models.Report).where(models.Report.run_id == run_id)
        .order_by(models.Report.generated_at.desc())
    )).scalars().first()
    if row is None:
        raise HTTPException(404, "no report yet (run may still be in progress)")
    data = row.data
    if format == "json":
        return data
    if format in ("md", "markdown"):
        return PlainTextResponse(render_markdown(data), media_type="text/markdown; charset=utf-8")
    if format == "html":
        return HTMLResponse(render_html(data))
    # pdf
    return Response(
        content=render_pdf(data),
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="report-{run_id}.pdf"'},
    )
