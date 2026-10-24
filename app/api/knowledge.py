"""Knowledge Base endpoints (CWE -> OWASP + remediation). Searchable reference data."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session
from app.knowledge.base import KnowledgeBase, seed_knowledge_base
from app.security.deps import require_admin

router = APIRouter(prefix="/knowledge", tags=["knowledge"])
_kb = KnowledgeBase()


def _as_dict(e):
    return {"cwe": e.cwe, "title": e.title, "owasp": e.owasp,
            "remediation": e.remediation, "references": e.references}


@router.get("")
async def list_knowledge():
    return [_as_dict(e) for e in _kb.all()]


@router.get("/search")
async def search_knowledge(q: str):
    return [_as_dict(e) for e in _kb.search(q)]


@router.post("/seed", dependencies=[Depends(require_admin)])
async def seed(session: AsyncSession = Depends(get_session)):
    n = await seed_knowledge_base(session)
    await session.commit()
    return {"seeded": n}
