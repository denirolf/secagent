"""Agent 1 — Master Orchestrator (run engine).

Builds the plan, dispatches the Recon and Vulnerability agents, records every decision,
and stops when a project limit is hit. This engine is DB-agnostic: it takes the authorized
scopes and project context directly and returns a structured result that the API layer
persists. Enforcement (scope/approval/sandbox/audit) lives entirely in the SecureExecutor
it constructs — the orchestrator cannot bypass it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from app.agents.base import AgentRuntime
from app.agents.auth_security import analyze_auth_posture
from app.agents.exploit_research import build_plans
from app.agents.exploit_validation import ExploitValidationAgent, LabOnlyViolation
from app.agents.reasoning import ReasoningResult, run_reasoning
from app.agents.recon import ReconResult, run_recon
from app.agents.vuln_analysis import run_vuln_analysis
from app.contracts.messages import Finding, ToolRequest
from app.contracts.validation import ValidationOutcome
from app.knowledge.base import KnowledgeBase
from app.engine.audit import AuditEntry, InMemoryAuditSink
from app.engine.executor import ProjectContext, SecureExecutor
from app.engine.registry import ToolRegistry
from app.engine.scope import AuthorizedScope, Resolver, ScopeEngine
from app.engine.tools.builtin import ALL_PHASE1_TOOLS
from app.orchestration.limits import LimitGuard, RunLimits


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Decision:
    step: str
    action: str
    rationale: str
    at: str = field(default_factory=_now)


@dataclass
class OrchestratorResult:
    state: str  # completed | stopped_limit | failed
    stop_reason: str
    recon: ReconResult | None
    findings: list[Finding]
    decisions: list[Decision]
    audit: list[AuditEntry]
    tool_calls_used: int
    cost_usd: float
    validations: list[ValidationOutcome] = field(default_factory=list)
    reasoning: ReasoningResult | None = None


ApprovalResolver = Callable[[ToolRequest, ProjectContext], Awaitable[bool]]


async def _auto_grant_lab(req: ToolRequest, ctx: ProjectContext) -> bool:
    # Default resolver used by the engine runner: approvals are only auto-granted by the
    # autonomy-level logic in approvals.py; anything that still reaches here is denied.
    return False


class MasterOrchestrator:
    def __init__(
        self,
        scopes: list[AuthorizedScope],
        ctx: ProjectContext,
        limits: RunLimits,
        *,
        resolver: Resolver | None = None,
        approval_resolver: ApprovalResolver | None = None,
    ) -> None:
        self.scopes = scopes
        self.ctx = ctx
        self.limits = limits
        self.audit_sink = InMemoryAuditSink()
        self.registry = ToolRegistry(ALL_PHASE1_TOOLS)
        self.scope_engine = ScopeEngine(scopes, resolver=resolver)
        self.executor = SecureExecutor(
            self.scope_engine, self.registry, self.audit_sink,
            approval_resolver=approval_resolver or _auto_grant_lab,
        )
        self.decisions: list[Decision] = []

    async def run(
        self,
        *,
        objective: str,
        target: str,
        use_llm: bool,
        model: str | None,
        max_turns: int = 6,
        run_nuclei: bool = False,
        validate: bool = False,
        lab_container: str | None = None,
        auth_check: bool = False,
        reasoning: bool = False,
        on_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> OrchestratorResult:
        async def emit(decision: Decision) -> None:
            self.decisions.append(decision)
            if on_event is not None:
                await on_event({"type": "decision", "step": decision.step,
                                "action": decision.action, "rationale": decision.rationale,
                                "at": decision.at})

        guard = LimitGuard(self.limits)
        runtime = AgentRuntime(
            agent_id="recon", executor=self.executor, registry=self.registry,
            ctx=self.ctx, max_tool_calls=self.limits.max_tool_calls,
        )

        await emit(Decision("plan", "recon+vuln",
            f"Objective: {objective!r}. Authorized target: {target}. "
            f"Plan: reconnaissance, then vulnerability analysis, within limits "
            f"(iter<={self.limits.max_iterations}, tools<={self.limits.max_tool_calls})."))

        # --- Phase: Reconnaissance ---
        guard.step()
        await emit(Decision("recon", "run_recon", "Inventory the attack surface."))
        recon = await run_recon(runtime, target, use_llm=use_llm, model=model, max_turns=max_turns)

        stop = guard.exceeded()
        if stop:
            return self._result("stopped_limit", stop, recon, [], runtime, guard)

        # --- Phase: Vulnerability analysis ---
        guard.step()
        runtime.agent_id = "vuln_analysis"
        await emit(Decision("vuln_analysis", "run_vuln_analysis",
            "Correlate recon evidence into suspected findings."))
        findings = await run_vuln_analysis(
            runtime, recon, use_llm=use_llm, model=model, max_turns=max_turns, run_nuclei=run_nuclei
        )

        # --- Phase: Authentication security (passive session/auth posture) ---
        if auth_check:
            guard.step()
            runtime.agent_id = "auth_security"
            await emit(Decision("auth_security", "analyze_auth_posture",
                "Analyze session cookie flags and auth posture (passive; synthetic/lab-only "
                "for any active test, which this phase does not perform)."))
            findings = findings + analyze_auth_posture(recon)

        validations: list[ValidationOutcome] = []
        if validate and findings:
            stop = guard.exceeded()
            if stop:
                return self._result("stopped_limit", stop, recon, findings, runtime, guard)
            # --- Phase: Exploit research (plans only, no execution on targets) ---
            guard.step()
            await emit(Decision("exploit_research", "build_validation_plans",
                "Analyze suspected findings; produce lab validation plans (no execution)."))
            plans = build_plans(findings)

            # --- Phase: Exploit validation (lab-only reproduction) ---
            guard.step()
            await emit(Decision("exploit_validation", "reproduce_in_lab",
                "Reproduce findings via bounded passive checks inside the isolated lab."))
            agent = ExploitValidationAgent(self.executor, self.ctx, lab_container=lab_container)
            try:
                validations = await agent.validate(target, plans, reset_each=bool(lab_container))
            except LabOnlyViolation as exc:
                await emit(Decision("exploit_validation", "refused", str(exc)))
                validations = []
            confirmed = sum(1 for v in validations if v.reproduced)
            await emit(Decision("validation_summary", "elevate",
                f"{confirmed}/{len(validations)} finding(s) reproduced in lab -> lab_confirmed."))

        # --- Phase: Security reasoning (correlate, risk graph, prioritize) ---
        reasoning_result: ReasoningResult | None = None
        if reasoning and findings:
            guard.step()
            runtime.agent_id = "reasoning"
            await emit(Decision("reasoning", "correlate",
                "Correlate findings, enrich via knowledge base, build risk graph, prioritize."))
            reasoning_result = run_reasoning(findings, validations, KnowledgeBase())
            top = reasoning_result.prioritized[0]["vulnerability_id"] if reasoning_result.prioritized else "n/a"
            await emit(Decision("reasoning_summary", "prioritize",
                f"{len(reasoning_result.risk_graph.edges)} risk chain(s) identified; "
                f"top-priority finding: {top}."))

        stop = guard.exceeded()
        state = "stopped_limit" if stop else "completed"
        await emit(Decision("finalize", "report",
            f"{len(findings)} suspected finding(s); "
            f"{sum(1 for v in validations if v.reproduced)} elevated to lab_confirmed."))
        return self._result(state, stop or "objective complete", recon, findings,
                            runtime, guard, validations, reasoning_result)

    def _result(self, state, reason, recon, findings, runtime, guard,
                validations=None, reasoning_result=None) -> OrchestratorResult:
        return OrchestratorResult(
            state=state, stop_reason=reason, recon=recon, findings=findings,
            decisions=self.decisions, audit=list(self.audit_sink.entries),
            tool_calls_used=runtime.tool_calls_used, cost_usd=guard.cost_usd,
            validations=validations or [], reasoning=reasoning_result,
        )
