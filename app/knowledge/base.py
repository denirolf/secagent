"""Knowledge Base for the Security Reasoning Agent (Phase 3).

A read-oriented store mapping CWE identifiers to OWASP Top 10 (2021) categories,
remediation strategies, and references. Backed by a bundled dataset so it works offline
and in tests; `seed_knowledge_base()` mirrors the dataset into the `knowledge_entries`
table so it is searchable through the API. Per the spec, the knowledge store is updatable
and searchable but never changes permissions on its own — it is pure reference data.
"""
from __future__ import annotations

from dataclasses import dataclass

# CWE -> reference entry. Kept small and factual; extend as coverage grows.
_CWE_DATA: dict[str, dict] = {
    "CWE-693": {
        "title": "Protection Mechanism Failure",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Set the missing defensive response header (CSP, nosniff, "
                       "Permissions-Policy) and verify across representative routes.",
        "references": ["https://cwe.mitre.org/data/definitions/693.html"],
    },
    "CWE-319": {
        "title": "Cleartext Transmission of Sensitive Information",
        "owasp": "A02:2021 Cryptographic Failures",
        "remediation": "Serve over HTTPS and send HSTS so browsers refuse plaintext.",
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
    },
    "CWE-1021": {
        "title": "Improper Restriction of Rendered UI Layers (Clickjacking)",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Set X-Frame-Options: DENY or a frame-ancestors CSP directive.",
        "references": ["https://cwe.mitre.org/data/definitions/1021.html"],
    },
    "CWE-200": {
        "title": "Exposure of Sensitive Information",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Suppress version/technology banners; avoid leaking internal detail.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "CWE-1004": {
        "title": "Sensitive Cookie Without HttpOnly Flag",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Set HttpOnly on session cookies so script cannot read them.",
        "references": ["https://cwe.mitre.org/data/definitions/1004.html"],
    },
    "CWE-614": {
        "title": "Sensitive Cookie Without Secure Flag",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Set Secure on session cookies so they are sent only over HTTPS.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },
    "CWE-1275": {
        "title": "Sensitive Cookie With Improper SameSite Attribute",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Set SameSite=Lax or Strict on session cookies to limit CSRF.",
        "references": ["https://cwe.mitre.org/data/definitions/1275.html"],
    },
}


@dataclass(frozen=True)
class KnowledgeEntry:
    cwe: str
    title: str
    owasp: str
    remediation: str
    references: list[str]


class KnowledgeBase:
    def __init__(self, data: dict[str, dict] | None = None) -> None:
        self._data = data or _CWE_DATA

    def lookup(self, cwe: str | None) -> KnowledgeEntry | None:
        if not cwe:
            return None
        d = self._data.get(cwe.upper())
        if not d:
            return None
        return KnowledgeEntry(cwe=cwe.upper(), title=d["title"], owasp=d["owasp"],
                              remediation=d["remediation"], references=list(d["references"]))

    def search(self, query: str) -> list[KnowledgeEntry]:
        q = query.lower().strip()
        out: list[KnowledgeEntry] = []
        for cwe, d in self._data.items():
            hay = f"{cwe} {d['title']} {d['owasp']}".lower()
            if q in hay:
                out.append(self.lookup(cwe))  # type: ignore[arg-type]
        return out

    def all(self) -> list[KnowledgeEntry]:
        return [self.lookup(c) for c in self._data]  # type: ignore[misc]


async def seed_knowledge_base(session) -> int:
    """Mirror the bundled dataset into knowledge_entries (idempotent upsert). Returns count."""
    from sqlalchemy import select

    from app.db import models

    kb = KnowledgeBase()
    count = 0
    for entry in kb.all():
        existing = (await session.execute(
            select(models.KnowledgeEntry).where(
                models.KnowledgeEntry.kind == "cwe", models.KnowledgeEntry.key == entry.cwe
            )
        )).scalars().first()
        body = {"title": entry.title, "owasp": entry.owasp,
                "remediation": entry.remediation, "references": entry.references}
        if existing:
            existing.body = body
        else:
            session.add(models.KnowledgeEntry(kind="cwe", key=entry.cwe, body=body))
        count += 1
    return count
