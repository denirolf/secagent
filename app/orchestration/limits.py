"""Run limits and the guard that enforces them.

The guard tracks iterations, tool calls, and an accrued cost estimate, and reports when a
project limit is reached. Tool-call volume is capped at the runtime (an agent stops calling
tools once ``max_tool_calls`` is hit); the guard additionally accrues an **estimated** cost
per iteration and per tool call so a project's ``max_budget_usd`` ceiling can stop a run at
a phase boundary before a real bill accumulates. The per-unit estimates default to 0.0
(estimate off, behaviour unchanged); set them to measured costs in production, or replace
them with real token accounting — the ceiling semantics stay the same.

``max_budget_usd == 0`` means "no budget ceiling" (not "stop immediately").
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunLimits:
    max_iterations: int
    max_tool_calls: int
    max_budget_usd: float


@dataclass(frozen=True)
class CostModel:
    per_iteration_usd: float = 0.0
    per_tool_call_usd: float = 0.0


class LimitGuard:
    def __init__(self, limits: RunLimits, cost_model: CostModel | None = None) -> None:
        self.limits = limits
        self.cost_model = cost_model or CostModel()
        self.iterations = 0
        self.tool_calls = 0
        self.cost_usd = 0.0

    def add_cost(self, usd: float) -> None:
        self.cost_usd += usd

    def step(self) -> None:
        self.iterations += 1
        self.cost_usd += self.cost_model.per_iteration_usd

    def record_tool_calls(self, total_used: int) -> None:
        """Sync the cumulative tool-call count from the runtime, accruing the estimated
        cost of any newly-used calls. Idempotent for a given total."""
        delta = max(0, total_used - self.tool_calls)
        self.tool_calls = max(self.tool_calls, total_used)
        self.cost_usd += delta * self.cost_model.per_tool_call_usd

    def exceeded(self) -> str | None:
        if self.iterations >= self.limits.max_iterations:
            return f"max_iterations ({self.limits.max_iterations}) reached"
        if self.limits.max_budget_usd > 0 and self.cost_usd >= self.limits.max_budget_usd:
            return f"max_budget_usd ({self.limits.max_budget_usd}) reached"
        return None
