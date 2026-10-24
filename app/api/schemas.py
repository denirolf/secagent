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


class RunOut(BaseModel):
    run_id: UUID
    project_id: UUID
    state: str
