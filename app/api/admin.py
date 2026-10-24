"""Admin API — API-key management (Phase 5). Every route requires the ``admin`` role.

A key's secret is returned in full exactly once, at creation. Afterwards only its prefix
and metadata are visible; the secret cannot be recovered (only its hash is stored).
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import models
from app.db.base import get_session
from app.security.auth import ROLES, generate_api_key
from app.security.deps import require_admin

router = APIRouter(
    prefix="/admin/api-keys", tags=["admin"], dependencies=[Depends(require_admin)]
)


class ApiKeyCreate(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer")


class ApiKeyInfo(BaseModel):
    id: str
    prefix: str
    name: str
    role: str
    revoked: bool
    created_at: str | None = None
    last_used_at: str | None = None


class ApiKeyCreated(ApiKeyInfo):
    token: str  # shown once, at creation


def _info(row: models.ApiKey) -> ApiKeyInfo:
    return ApiKeyInfo(
        id=str(row.id),
        prefix=row.prefix,
        name=row.name,
        role=row.role,
        revoked=row.revoked,
        created_at=row.created_at.isoformat() if row.created_at else None,
        last_used_at=row.last_used_at.isoformat() if row.last_used_at else None,
    )


@router.post("", response_model=ApiKeyCreated)
async def create_key(body: ApiKeyCreate, session: AsyncSession = Depends(get_session)):
    settings = get_settings()
    if body.role not in ROLES:
        raise HTTPException(422, f"role must be one of {ROLES}")
    if settings.auth_enabled and not settings.api_key_pepper:
        raise HTTPException(500, "API_KEY_PEPPER is not configured; cannot mint keys")
    gen = generate_api_key(settings.api_key_pepper)
    row = models.ApiKey(
        prefix=gen.prefix, key_hash=gen.key_hash, name=body.name, role=body.role
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return ApiKeyCreated(token=gen.token, **_info(row).model_dump())


@router.get("", response_model=list[ApiKeyInfo])
async def list_keys(session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(models.ApiKey).order_by(models.ApiKey.created_at.desc())
        )
    ).scalars().all()
    return [_info(r) for r in rows]


@router.delete("/{key_id}")
async def revoke_key(key_id: UUID, session: AsyncSession = Depends(get_session)):
    row = await session.get(models.ApiKey, key_id)
    if row is None:
        raise HTTPException(404, "API key not found")
    row.revoked = True
    await session.commit()
    return {"id": str(key_id), "revoked": True}
