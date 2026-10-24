"""SQLAlchemy ORM models — the PostgreSQL schema (spec section 7).

The safety model is encoded in the schema itself:
- authorized_scopes is the allowlist; an empty list means nothing is authorized.
- vulnerabilities.status is the suspected/lab_confirmed/confirmed_authorized enum.
- audit_logs is append-only (the application never updates or deletes rows).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    role: Mapped[str] = mapped_column(String(50), default="owner")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    autonomy_level: Mapped[int] = mapped_column(Integer, default=1)
    max_iterations: Mapped[int] = mapped_column(Integer, default=12)
    max_tool_calls: Mapped[int] = mapped_column(Integer, default=40)
    max_budget_usd: Mapped[float] = mapped_column(Float, default=5.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scopes: Mapped[list["AuthorizedScope"]] = relationship(back_populates="project")


class AuthorizedScope(Base):
    __tablename__ = "authorized_scopes"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    kind: Mapped[str] = mapped_column(String(20))  # ip | cidr | domain | lab_env
    value: Mapped[str] = mapped_column(String(255))
    is_lab_env: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")

    project: Mapped["Project"] = relationship(back_populates="scopes")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    scope_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("authorized_scopes.id"), nullable=True)
    host: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    services: Mapped[dict] = mapped_column(JSONB, default=dict)  # {port: {service, version}}
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(String(50), unique=True)
    status: Mapped[str] = mapped_column(String(30), default="idle")


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    objective: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="pending")
    iterations_used: Mapped[int] = mapped_column(Integer, default=0)
    tool_calls_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(50))
    state: Mapped[str] = mapped_column(String(30), default="pending")
    message: Mapped[dict] = mapped_column(JSONB, default=dict)  # serialized AgentMessage
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ToolExecution(Base):
    __tablename__ = "tool_executions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    tool_id: Mapped[str] = mapped_column(String(80))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)  # redacted
    target: Mapped[str] = mapped_column(String(512))
    scope_decision: Mapped[str] = mapped_column(String(80))
    exit_status: Mapped[str] = mapped_column(String(30))
    result_ref: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255))
    vulnerability_id: Mapped[str] = mapped_column(String(120))
    cve: Mapped[str | None] = mapped_column(String(40), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    # suspected | lab_confirmed | confirmed_authorized
    status: Mapped[str] = mapped_column(String(30), default="suspected")
    confidence: Mapped[str] = mapped_column(String(20))
    recommended_validation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ValidationResult(Base):
    """Populated in Phase 2. Its existence is what lets a finding move past 'suspected'."""

    __tablename__ = "validation_results"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id"))
    environment: Mapped[str] = mapped_column(String(80), default="lab")
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    before_state: Mapped[str] = mapped_column(Text, default="")
    after_state: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(Text)
    data_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True)
    operation_class: Mapped[str] = mapped_column(String(30))
    tool_id: Mapped[str] = mapped_column(String(80), default="")
    target: Mapped[str] = mapped_column(String(512), default="")
    state: Mapped[str] = mapped_column(String(20), default="pending")
    requested_by: Mapped[str] = mapped_column(String(80), default="")
    decided_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Append-only. The application never updates or deletes these rows."""

    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    agent_id: Mapped[str] = mapped_column(String(50))
    tool_id: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(512))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    scope_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    scope_reason: Mapped[str] = mapped_column(String(255), default="")
    decision: Mapped[str] = mapped_column(String(40))
    result_summary: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    format: Mapped[str] = mapped_column(String(20), default="json")
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    data_ref: Mapped[str] = mapped_column(Text, default="")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class KnowledgeEntry(Base):
    """Populated in Phase 3 (CVE/CWE/OWASP/notes). Schema present now."""

    __tablename__ = "knowledge_entries"
    __table_args__ = (UniqueConstraint("kind", "key", name="uq_knowledge_kind_key"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(40))
    key: Mapped[str] = mapped_column(String(120))
    body: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
