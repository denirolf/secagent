"""SecureExecutor — the deterministic System Execution Engine.

Given an agent's ToolRequest it performs, in order:
  1. registry lookup      (unregistered -> deny)
  2. scope authorization  (out of scope -> deny)
  3. param validation     (invalid -> deny)
  4. approval check        (required & not granted -> awaiting_approval, nothing runs)
  5. sandboxed execution
  6. audit (always, including every denial)

This class contains no LLM. Agents reach the outside world only by calling it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable
from uuid import UUID

from app.contracts.enums import AutonomyLevel
from app.contracts.messages import ScopeDecision, ToolRequest
from app.engine.approvals import approval_required
from app.engine.audit import AuditEntry, AuditSink
from app.engine.registry import (
    ToolParamError,
    ToolRegistry,
    UnregisteredToolError,
)
from app.engine.sandbox import SandboxLimits, ToolRunResult, run_container, run_http_probe
from app.engine.scope import ScopeEngine

# Resolves whether a required approval has been granted. Returns True to proceed.
ApprovalResolver = Callable[[ToolRequest, "ProjectContext"], Awaitable[bool]]


@dataclass(frozen=True)
class ProjectContext:
    project_id: UUID
    autonomy_level: AutonomyLevel
    limits: SandboxLimits


@dataclass
class ExecResult:
    status: str  # executed | denied_out_of_scope | denied_unregistered |
    #              invalid_params | awaiting_approval | error
    summary: str
    scope: ScopeDecision | None = None
    run: ToolRunResult | None = None


async def _deny_all(_req: ToolRequest, _ctx: ProjectContext) -> bool:
    return False


class SecureExecutor:
    def __init__(
        self,
        scope_engine: ScopeEngine,
        registry: ToolRegistry,
        audit_sink: AuditSink,
        approval_resolver: ApprovalResolver | None = None,
    ) -> None:
        self._scope = scope_engine
        self._registry = registry
        self._audit = audit_sink
        self._approve = approval_resolver or _deny_all

    async def execute(
        self, req: ToolRequest, *, agent_id: str, ctx: ProjectContext
    ) -> ExecResult:
        # 1. registry
        try:
            spec = self._registry.get(req.tool_id)
        except UnregisteredToolError as exc:
            await self._record(agent_id, req, None, "denied_unregistered", str(exc), ctx)
            return ExecResult("denied_unregistered", str(exc))

        # 2. scope
        decision = self._scope.authorize(req.target)
        if not decision.allowed:
            await self._record(
                agent_id, req, decision, "denied_out_of_scope", decision.reason, ctx
            )
            return ExecResult("denied_out_of_scope", decision.reason, scope=decision)

        # 3. params + plan
        try:
            plan = self._registry.build_plan(req.tool_id, req.params, req.target)
        except ToolParamError as exc:
            await self._record(agent_id, req, decision, "invalid_params", str(exc), ctx)
            return ExecResult("invalid_params", str(exc), scope=decision)

        # 4. approval
        needs = approval_required(
            requires_approval=spec.requires_approval,
            operation_class=spec.operation_class,
            autonomy_level=ctx.autonomy_level,
            target_is_lab=decision.matched_is_lab,
        )
        if needs:
            granted = await self._approve(req, ctx)
            if not granted:
                await self._record(
                    agent_id, req, decision, "awaiting_approval",
                    "human approval required and not granted", ctx
                )
                return ExecResult(
                    "awaiting_approval",
                    "operation requires human approval before it can run",
                    scope=decision,
                )

        # 5. execute
        if plan.kind == "container":
            run = await run_container(plan, ctx.limits)
        else:
            run = await run_http_probe(plan, decision.target)

        decision_str = "executed" if run.ok else "error"
        summary = _summarize(run)
        await self._record(agent_id, req, decision, decision_str, summary, ctx)
        return ExecResult("executed" if run.ok else "error", summary, scope=decision, run=run)

    async def _record(
        self,
        agent_id: str,
        req: ToolRequest,
        decision: ScopeDecision | None,
        outcome: str,
        summary: str,
        ctx: ProjectContext,
    ) -> None:
        await self._audit.record(
            AuditEntry(
                agent_id=agent_id,
                tool_id=req.tool_id,
                target=req.target,
                params=req.params,
                scope_allowed=bool(decision and decision.allowed),
                scope_reason=decision.reason if decision else "n/a",
                decision=outcome,
                result_summary=summary[:2000],
                project_id=ctx.project_id,
            )
        )


def _summarize(run: ToolRunResult) -> str:
    if run.structured:
        s = run.structured
        return (
            f"status={s.get('status_code')} server={s.get('server')!r} "
            f"missing_sec_headers={s.get('missing_security_headers')}"
        )
    if run.timed_out:
        return "timed out"
    head = (run.stdout or run.stderr or "").strip().splitlines()[:1]
    return f"exit={run.exit_code} " + (head[0][:300] if head else "")
