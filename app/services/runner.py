"""Run service: load a project, execute the orchestrator, persist, broadcast events."""
from __future__ import annotations

from uuid import UUID

from app.agents.orchestrator import MasterOrchestrator
from app.config import get_settings
from app.contracts.enums import AutonomyLevel
from app.db import repo
from app.db.base import SessionLocal
from app.engine.executor import ProjectContext
from app.engine.sandbox import SandboxLimits
from app.orchestration.events import bus
from app.orchestration.limits import RunLimits
from app.reporting.report import build_report


async def execute_run(
    *, project_id: UUID, run_id: UUID, objective: str, target: str,
    use_llm: bool, run_nuclei: bool = False,
) -> dict:
    settings = get_settings()
    async with SessionLocal() as session:
        proj = await repo.get_project(session, project_id)
        if proj is None:
            raise ValueError("project not found")
        scopes = await repo.load_scopes(session, project_id)

    ctx = ProjectContext(
        project_id=project_id,
        autonomy_level=AutonomyLevel(proj.autonomy_level),
        limits=SandboxLimits(
            network=settings.sandbox_network, cpus=settings.sandbox_cpu_limit,
            memory=settings.sandbox_mem_limit, timeout_s=settings.sandbox_timeout_seconds,
        ),
    )
    limits = RunLimits(proj.max_iterations, proj.max_tool_calls, proj.max_budget_usd)
    orch = MasterOrchestrator(scopes, ctx, limits)

    async def on_event(ev: dict) -> None:
        await bus.publish(run_id, ev)

    model = settings.claude_model or None
    result = await orch.run(
        objective=objective, target=target, use_llm=use_llm, model=model,
        run_nuclei=run_nuclei, on_event=on_event,
    )
    report = build_report(
        project_name=proj.name, objective=objective, target=target, result=result
    )

    async with SessionLocal() as session:
        from app.db import models
        run = await session.get(models.Run, run_id)
        await repo.persist_result(
            session, project_id=project_id, run=run, result=result, report=report
        )
        await session.commit()

    await bus.publish(run_id, {"type": "done", "state": result.state,
                               "findings": report["summary"]["findings_total"]})
    return report
