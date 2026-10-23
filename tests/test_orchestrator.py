"""Deterministic end-to-end of the orchestrator (no LLM, no Docker).

Sandbox calls are mocked so the whole plan -> recon -> vuln -> report chain runs offline.
"""
from uuid import uuid4

import app.engine.executor as executor_mod
from app.agents.orchestrator import MasterOrchestrator
from app.contracts.enums import AutonomyLevel, ScopeKind
from app.engine.executor import ProjectContext
from app.engine.sandbox import SandboxLimits, ToolRunResult
from app.engine.scope import AuthorizedScope
from app.orchestration.limits import RunLimits
from app.reporting.report import build_report

NMAP_XML = """<?xml version="1.0"?><nmaprun><host>
<ports><port protocol="tcp" portid="3000"><state state="open"/>
<service name="http" product="Node.js Express framework" version="1.0"/></port></ports>
</host></nmaprun>"""

PROBE = {
    "url": "http://juiceshop:3000/", "status_code": 200, "server": "", "x_powered_by": "Express",
    "title": "OWASP Juice Shop", "present_security_headers": [],
    "missing_security_headers": ["content-security-policy", "x-frame-options",
                                 "x-content-type-options", "strict-transport-security"],
    "content_type": "text/html",
}


async def test_full_run_produces_suspected_report(monkeypatch):
    async def fake_container(plan, limits):
        return ToolRunResult(plan.tool_id, True, 0, NMAP_XML, "", False)

    async def fake_probe(plan, target):
        return ToolRunResult("http_probe", True, 0, "", "", False, structured=PROBE)

    monkeypatch.setattr(executor_mod, "run_container", fake_container)
    monkeypatch.setattr(executor_mod, "run_http_probe", fake_probe)

    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    ctx = ProjectContext(
        project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB,
        limits=SandboxLimits(network="secagent_lab", cpus=1.0, memory="512m", timeout_s=60),
    )
    orch = MasterOrchestrator(
        scopes, ctx, RunLimits(max_iterations=12, max_tool_calls=40, max_budget_usd=5.0),
        resolver=lambda h: {"juiceshop": ["172.20.0.5"]}.get(h, []),
    )
    result = await orch.run(
        objective="Assess the authorized Juice Shop lab target",
        target="http://juiceshop:3000", use_llm=False, model=None,
    )

    assert result.state == "completed"
    assert result.recon and any(s["port"] == 3000 for s in result.recon.services)
    assert result.findings, "expected suspected findings"
    assert all(f.status.value == "suspected" for f in result.findings)

    report = build_report(
        project_name="demo", objective="assess", target="http://juiceshop:3000", result=result
    )
    assert report["summary"]["findings_total"] == len(result.findings)
    assert report["summary"]["findings_by_status"].get("suspected") == len(result.findings)
    # Every executed tool call is audited.
    assert report["audit_summary"].get("executed", 0) >= 2


async def test_out_of_scope_target_yields_no_evidence(monkeypatch):
    async def fake_container(plan, limits):
        raise AssertionError("sandbox must not run for an out-of-scope target")

    async def fake_probe(plan, target):
        raise AssertionError("sandbox must not run for an out-of-scope target")

    monkeypatch.setattr(executor_mod, "run_container", fake_container)
    monkeypatch.setattr(executor_mod, "run_http_probe", fake_probe)

    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    ctx = ProjectContext(
        project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB,
        limits=SandboxLimits(network="secagent_lab", cpus=1.0, memory="512m", timeout_s=60),
    )
    orch = MasterOrchestrator(
        scopes, ctx, RunLimits(max_iterations=12, max_tool_calls=40, max_budget_usd=5.0),
        resolver=lambda h: {"evil.example": ["93.184.216.34"]}.get(h, []),
    )
    result = await orch.run(
        objective="attempt out of scope", target="http://evil.example",
        use_llm=False, model=None,
    )
    assert result.findings == []
    assert all(e.decision == "denied_out_of_scope" for e in result.audit)
