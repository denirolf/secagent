"""Project + authorized-scope endpoints."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ProjectIn, ProjectOut, ScopeIn
from app.db import models, repo
from app.db.base import get_session

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut)
async def create_project(body: ProjectIn, session: AsyncSession = Depends(get_session)):
    proj = await repo.create_project(
        session, name=body.name, autonomy_level=body.autonomy_level,
        max_iterations=body.max_iterations, max_tool_calls=body.max_tool_calls,
        max_budget_usd=body.max_budget_usd,
    )
    for sc in body.scopes:
        await repo.add_scope(session, proj.id, kind=sc.kind, value=sc.value,
                             is_lab_env=sc.is_lab_env, note=sc.note)
    await session.commit()
    return await _project_out(session, proj.id)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(project_id: UUID, session: AsyncSession = Depends(get_session)):
    out = await _project_out(session, project_id)
    if out is None:
        raise HTTPException(404, "project not found")
    return out


async def _project_out(session: AsyncSession, project_id: UUID) -> ProjectOut | None:
    proj = await session.get(models.Project, project_id)
    if proj is None:
        return None
    rows = (await session.execute(
        select(models.AuthorizedScope).where(models.AuthorizedScope.project_id == project_id)
    )).scalars().all()
    return ProjectOut(
        id=proj.id, name=proj.name, autonomy_level=proj.autonomy_level,
        scopes=[ScopeIn(kind=r.kind, value=r.value, is_lab_env=r.is_lab_env, note=r.note) for r in rows],
    )
