"""Request/response models for the HTTP API."""
from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class ScopeIn(BaseModel):
    kind: str = Field(description="ip | cidr | domain | lab_env")
    value: str
    is_lab_env: bool = False
    note: str = ""


class ProjectIn(BaseModel):
    name: str
    autonomy_level: int = 1
    max_iterations: int = 12
    max_tool_calls: int = 40
    max_budget_usd: float = 5.0
    scopes: list[ScopeIn] = []


class ProjectOut(BaseModel):
    id: UUID
    name: str
    autonomy_level: int
    scopes: list[ScopeIn]


class RunIn(BaseModel):
    objective: str
    target: str
    use_llm: bool = True
    run_nuclei: bool = False
    validate_in_lab: bool = False  # Phase 2: reproduce findings in the isolated lab
    lab_container: str | None = None  # optional lab container to reset between tests
    auth_check: bool = False  # Phase 3: analyze session/auth posture (passive)
    reasoning: bool = False  # Phase 3: correlate findings, risk graph, prioritize


class RunOut(BaseModel):
    run_id: UUID
    project_id: UUID
    state: str
