"""Audit system — append-only record of every engine action.

The engine never runs a tool (or denies one) without first writing an audit entry.
Entries are append-only: there is no update or delete path. A sink is injected so the
same engine code works with a DB-backed sink in production and an in-memory sink in tests.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Protocol
from uuid import UUID


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Sensitive keys are redacted before an audit entry is persisted.
_REDACT_KEYS = {"password", "passwd", "secret", "token", "api_key", "authorization"}


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k.lower() in _REDACT_KEYS:
            out[k] = "***redacted***"
        else:
            out[k] = v
    return out


@dataclass(frozen=True)
class AuditEntry:
    agent_id: str
    tool_id: str
    target: str
    params: dict[str, Any]
    scope_allowed: bool
    scope_reason: str
    decision: str  # "executed" | "denied_out_of_scope" | "denied_unregistered" |
    #                "awaiting_approval" | "approval_denied" | "error"
    result_summary: str = ""
    project_id: UUID | None = None
    task_id: UUID | None = None
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["params"] = redact_params(self.params)
        return row


class AuditSink(Protocol):
    async def record(self, entry: AuditEntry) -> None: ...


class InMemoryAuditSink:
    """Collects audit entries in memory. Used in tests and in the no-DB e2e path."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    async def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class CallableAuditSink:
    """Adapts any async callable (e.g. a DB insert) into an AuditSink."""

    def __init__(self, fn: Callable[[AuditEntry], Awaitable[None]]) -> None:
        self._fn = fn

    async def record(self, entry: AuditEntry) -> None:
        await self._fn(entry)
