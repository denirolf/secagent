"""Tool Registry — the catalog of permitted tools.

Each tool is a declarative spec: a unique id, a Pydantic params model, its operation
class, whether it needs approval, resource/time limits, and a pure function that builds a
fixed argument vector from *validated* params. The model picks a tool id and typed
params; this registry turns that into an execution plan. There is no path by which a
model-supplied string becomes a command line.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from app.contracts.enums import OperationClass


@dataclass(frozen=True)
class ExecutionPlan:
    tool_id: str
    kind: str  # "container" | "inprocess"
    operation_class: OperationClass
    timeout_s: int
    image: str | None = None  # for container tools
    argv: list[str] | None = None  # for container tools (fixed, from validated params)
    inproc_params: BaseModel | None = None  # for in-process tools


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    description: str
    params_model: type[BaseModel]
    operation_class: OperationClass
    kind: str  # "container" | "inprocess"
    timeout_s: int
    requires_approval: bool
    # JSON-schema-ish dict passed to the SDK @tool input_schema (param name -> type/meta)
    input_schema: dict[str, Any]
    # container tools only: builds argv from (validated params, target)
    build_argv: Callable[[BaseModel, str], list[str]] | None = None
    image: str | None = None


class ToolRegistryError(Exception):
    pass


class UnregisteredToolError(ToolRegistryError):
    pass


class ToolParamError(ToolRegistryError):
    pass


class ToolRegistry:
    def __init__(self, specs: list[ToolSpec]) -> None:
        self._specs: dict[str, ToolSpec] = {s.tool_id: s for s in specs}

    def ids(self) -> list[str]:
        return list(self._specs)

    def get(self, tool_id: str) -> ToolSpec:
        spec = self._specs.get(tool_id)
        if spec is None:
            raise UnregisteredToolError(f"tool '{tool_id}' is not registered")
        return spec

    def validate(self, tool_id: str, params: dict[str, Any]) -> BaseModel:
        spec = self.get(tool_id)
        try:
            return spec.params_model.model_validate(params)
        except ValidationError as exc:
            raise ToolParamError(f"invalid params for '{tool_id}': {exc}") from exc

    def build_plan(self, tool_id: str, params: dict[str, Any], target: str) -> ExecutionPlan:
        spec = self.get(tool_id)
        validated = self.validate(tool_id, params)
        if spec.kind == "container":
            assert spec.build_argv is not None and spec.image is not None
            argv = spec.build_argv(validated, target)
            return ExecutionPlan(
                tool_id=tool_id,
                kind="container",
                operation_class=spec.operation_class,
                timeout_s=spec.timeout_s,
                image=spec.image,
                argv=argv,
            )
        return ExecutionPlan(
            tool_id=tool_id,
            kind="inprocess",
            operation_class=spec.operation_class,
            timeout_s=spec.timeout_s,
            inproc_params=validated,
        )
