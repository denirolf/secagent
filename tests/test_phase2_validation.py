"""Phase 2 tests: exploit research planning + lab-only validation + status elevation."""
from uuid import uuid4

import pytest

import app.engine.executor as executor_mod
from app.agents.exploit_research import build_plans
from app.agents.exploit_validation import ExploitValidationAgent, LabOnlyViolation
from app.agents.orchestrator import MasterOrchestrator
from app.contracts.enums import (
    AutonomyLevel,
    Confidence,
    FindingStatus,
    ScopeKind,
    Severity,
)
from app.contracts.messages import Evidence, Finding
from app.engine.audit import InMemoryAuditSink
from app.engine.executor import ProjectContext, SecureExecutor
from app.engine.registry import ToolRegistry
from app.engine.sandbox import SandboxLimits, ToolRunResult
from app.engine.scope import AuthorizedScope, ScopeEngine
from app.engine.tools.builtin import ALL_PHASE1_TOOLS
from app.orchestration.limits import RunLimits

LIMITS = SandboxLimits(network="secagent_lab", cpus=1.0, memory="512m", timeout_s=60)

NMAP_XML = ('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="3000">'
            '<state state="open"/><service name="http"/></port></ports></host></nmaprun>')
PROBE = {
    "url": "http://juiceshop:3000/", "status_code": 200, "server": "", "x_powered_by": "Express",
    "title": "OWASP Juice Shop", "present_security_headers": ["x-frame-options"],
    "missing_security_headers": ["content-security-policy", "strict-transport-security",
                                 "referrer-policy", "permissions-policy"],
    "content_type": "text/html",
}


def _header_finding():
    return Finding(
        asset="juiceshop", vulnerability_id="HDR-0-0", cwe="CWE-693", severity=Severity.MEDIUM,
        status=FindingStatus.SUSPECTED, confidence=Confidence.HIGH,
        evidence=[Evidence(kind="http_response",
                           summary="Response from http://juiceshop/ is missing the "
                                   "'content-security-policy' header.")],
        recommended_validation="re-request", remediation="set CSP",
    )


def test_research_builds_bounded_lab_checks():
    plans = build_plans([_header_finding()])
    assert len(plans) == 1
    p = plans[0]
    assert p.bounded_checks and all(c.kind == "http_header_absent" for c in p.bounded_checks)
    assert all(c.header == "content-security-policy" for c in p.bounded_checks)
    assert p.mechanism and p.impact  # research produced a narrative


def _lab_executor(audit, resolver_map):
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    scope = ScopeEngine(scopes, resolver=lambda h: resolver_map.get(h, []))
    return SecureExecutor(scope, ToolRegistry(ALL_PHASE1_TOOLS), audit)


async def test_validation_elevates_when_reproduced(monkeypatch):
    async def fake_probe(plan, target):
        return ToolRunResult("http_probe", True, 0, "", "", False, structured=PROBE)

    monkeypatch.setattr(executor_mod, "run_http_probe", fake_probe)
    ctx = ProjectContext(project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB, limits=LIMITS)
    ex = _lab_executor(InMemoryAuditSink(), {"juiceshop": ["172.20.0.5"]})
    agent = ExploitValidationAgent(ex, ctx)
    plans = build_plans([_header_finding()])
    outcomes = await agent.validate("http://juiceshop:3000", plans)
    assert outcomes[0].reproduced is True
    assert outcomes[0].new_status == FindingStatus.LAB_CONFIRMED


async def test_validation_refuses_non_lab_target():
    # Scope authorizes a non-lab public IP explicitly, so it is allowed but NOT a lab env.
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.IP, value="93.184.216.34", is_lab_env=False)]
    scope = ScopeEngine(scopes, resolver=lambda h: {"owned.example": ["93.184.216.34"]}.get(h, []))
    ex = SecureExecutor(scope, ToolRegistry(ALL_PHASE1_TOOLS), InMemoryAuditSink())
    ctx = ProjectContext(project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB, limits=LIMITS)
    agent = ExploitValidationAgent(ex, ctx)
    with pytest.raises(LabOnlyViolation):
        await agent.validate("http://owned.example", build_plans([_header_finding()]))


async def test_full_phase2_run_reports_lab_confirmed(monkeypatch):
    async def fake_container(plan, limits):
        return ToolRunResult(plan.tool_id, True, 0, NMAP_XML, "", False)

    async def fake_probe(plan, target):
        return ToolRunResult("http_probe", True, 0, "", "", False, structured=PROBE)

    monkeypatch.setattr(executor_mod, "run_container", fake_container)
    monkeypatch.setattr(executor_mod, "run_http_probe", fake_probe)

    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    ctx = ProjectContext(project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB, limits=LIMITS)
    orch = MasterOrchestrator(
        scopes, ctx, RunLimits(20, 60, 5.0),
        resolver=lambda h: {"juiceshop": ["172.20.0.5"]}.get(h, []),
    )
    result = await orch.run(
        objective="assess+validate", target="http://juiceshop:3000",
        use_llm=False, model=None, validate=True,
    )
    assert result.validations, "expected validation outcomes"
    assert any(v.reproduced and v.new_status == FindingStatus.LAB_CONFIRMED for v in result.validations)

    from app.reporting.report import build_report
    report = build_report(project_name="demo", objective="x",
                          target="http://juiceshop:3000", result=result)
    assert report["summary"]["lab_confirmed"] >= 1
    assert report["validations"], "report should include a validations section"
