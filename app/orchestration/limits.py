"""Run limits and the guard that enforces them."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunLimits:
    max_iterations: int
    max_tool_calls: int
    max_budget_usd: float


class LimitGuard:
    def __init__(self, limits: RunLimits) -> None:
        self.limits = limits
        self.iterations = 0
        self.cost_usd = 0.0

    def add_cost(self, usd: float) -> None:
        self.cost_usd += usd

    def step(self) -> None:
        self.iterations += 1

    def exceeded(self) -> str | None:
        if self.iterations >= self.limits.max_iterations:
            return f"max_iterations ({self.limits.max_iterations}) reached"
        if self.cost_usd >= self.limits.max_budget_usd:
            return f"max_budget_usd ({self.limits.max_budget_usd}) reached"
        return None
