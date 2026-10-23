"""Pydantic v2 message contracts for inter-agent communication (spec section 5).

Every message between agents validates through `AgentMessage`. The same shapes are
persisted (as JSONB) in `agent_tasks` and emitted over the WebSocket to the dashboard.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from .enums import (
    AgentId,
    Confidence,
    FindingStatus,
    OperationClass,
    Severity,
    TaskState,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ToolRequest(BaseModel):
    """An agent's request to run a registered tool against a target.

    The agent supplies only the tool id and typed params. The System Execution
    Engine resolves these to a fixed argv; the agent never composes a command line.
    """

    tool_id: str
    operation_class: OperationClass
    target: str  # re-authorized by the Scope Engine immediately before execution
    params: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False


class Evidence(BaseModel):
    kind: Literal[
        "http_response", "banner", "scanner_output", "screenshot", "log", "note"
    ]
    summary: str
    data_ref: str | None = None  # pointer to stored artifact, not a raw blob inline
    collected_at: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    """A single vulnerability finding in the standardized output shape (spec Agent 3).

    `status` defaults to SUSPECTED and recon/vuln agents may never set anything higher.
    """

    asset: str
    vulnerability_id: str  # internal id, unique within a run
    cve: str | None = None
    cwe: str | None = None
    severity: Severity
    status: FindingStatus = FindingStatus.SUSPECTED
    confidence: Confidence
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_validation: str
    remediation: str

    @field_validator("status")
    @classmethod
    def _recon_vuln_cannot_confirm(cls, v: FindingStatus) -> FindingStatus:
        # Hard rule: nothing produced by the analysis agents is "confirmed".
        # Elevation happens only through validation_results (Phase 2) + human sign-off.
        if v != FindingStatus.SUSPECTED:
            raise ValueError(
                "Findings from recon/vuln analysis must be 'suspected'. "
                "Elevation to lab_confirmed/confirmed_authorized requires a "
                "validation_results record and human approval."
            )
        return v


class AgentMessage(BaseModel):
    """The universal envelope passed between agents (spec section 5)."""

    task_id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    agent_id: AgentId
    objective: str
    target_scope_id: UUID | None = None
    input_data: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str | None = None
    tool_request: ToolRequest | None = None
    execution_status: TaskState = TaskState.PENDING
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    confidence: Confidence | None = None
    timestamp: datetime = Field(default_factory=_utcnow)


class ScopeDecision(BaseModel):
    """Result of a Scope Engine authorization check."""

    allowed: bool
    target: str
    resolved_ip: str | None = None
    matched_scope_id: UUID | None = None
    matched_is_lab: bool = False
    reason: str
