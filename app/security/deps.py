"""FastAPI dependencies for API-key auth + RBAC.

``require_role(minimum)`` returns a dependency that resolves the caller's ``Principal`` and
enforces the minimum role. When auth is disabled it yields a synthetic admin, so routes can
declare their required role unconditionally and it simply becomes a no-op in dev/tests.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import models
from app.db.base import get_session
from app.security.auth import (
    Principal,
    SYNTHETIC_ADMIN,
    parse_token,
    role_satisfies,
    verify_secret,
)


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


async def authenticate(session: AsyncSession, token: str, pepper: str) -> Principal | None:
    parsed = parse_token(token)
    if parsed is None:
        return None
    prefix, secret = parsed
    row = (
        await session.execute(
            select(models.ApiKey).where(
                models.ApiKey.prefix == prefix,
                models.ApiKey.revoked.is_(False),
            )
        )
    ).scalar_one_or_none()
    if row is None or not verify_secret(secret, pepper, row.key_hash):
        return None
    try:  # best-effort last-used bookkeeping; never fail auth over it
        row.last_used_at = datetime.now(timezone.utc)
        await session.commit()
    except Exception:
        await session.rollback()
    return Principal(
        role=row.role,
        key_id=str(row.id),
        user_id=str(row.user_id) if row.user_id else None,
        email=row.name,
    )


def require_role(minimum: str):
    async def dependency(
        request: Request, session: AsyncSession = Depends(get_session)
    ) -> Principal:
        settings = get_settings()
        if not settings.auth_enabled:
            request.state.principal = SYNTHETIC_ADMIN
            return SYNTHETIC_ADMIN
        token = _bearer(request)
        if not token:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        principal = await authenticate(session, token, settings.api_key_pepper)
        if principal is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "invalid or revoked API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not role_satisfies(principal.role, minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"operation requires role '{minimum}'",
            )
        request.state.principal = principal
        return principal

    return dependency


# Pre-built dependencies for the three gate levels.
require_viewer = require_role("viewer")
require_operator = require_role("operator")
require_admin = require_role("admin")
