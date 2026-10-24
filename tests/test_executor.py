"""Tests for the SecureExecutor enforcement chain, with the sandbox mocked."""
from uuid import uuid4

import pytest

import app.engine.executor as executor_mod
from app.contracts.enums import AutonomyLevel, OperationClass, ScopeKind
from app.contracts.messages import ToolRequest
from app.engine.audit import InMemoryAuditSink
from app.engine.executor import ProjectContext, SecureExecutor
from app.engine.registry import ToolRegistry
from app.engine.sandbox import SandboxLimits, ToolRunResult
from app.engine.scope import AuthorizedScope, ScopeEngine
from app.engine.tools.builtin import ALL_PHASE1_TOOLS

LIMITS = SandboxLimits(network="secagent_lab", cpus=1.0, memory="512m", timeout_s=60)


def _ctx(level=AutonomyLevel.AUTONOMOUS_LAB):
    return ProjectContext(project_id=uuid4(), autonomy_level=level, limits=LIMITS)


def _engine(resolver_map, audit, approve=None):
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    scope = ScopeEngine(scopes, resolver=lambda h: resolver_map.get(h, []))
    reg = ToolRegistry(ALL_PHASE1_TOOLS)
    return SecureExecutor(scope, reg, audit, approval_resolver=approve)


async def _always_grant(req, ctx):
    return True


async def test_unregistered_tool_denied():
    audit = InMemoryAuditSink()
    ex = _engine({"juiceshop": ["172.20.0.5"]}, audit)
    req = ToolRequest(tool_id="rm_rf", operation_class=OperationClass.ACTIVE_AUTHORIZED, target="juiceshop")
    res = await ex.execute(req, agent_id="recon", ctx=_ctx())
    assert res.status == "denied_unregistered"
    assert audit.entries[-1].decision == "denied_unregistered"


async def test_out_of_scope_denied_and_nothing_runs(monkeypatch):
    ran = {"v": False}

    async def _boom(*a, **k):
        ran["v"] = True
        return ToolRunResult("port_scan", True, 0, "", "", False)

    monkeypatch.setattr(executor_mod, "run_container", _boom)
    audit = InMemoryAuditSink()
    ex = _engine({"evil.example": ["93.184.216.34"]}, audit)
    req = ToolRequest(tool_id="port_scan", operation_class=OperationClass.ACTIVE_AUTHORIZED, target="evil.example")
    res = await ex.execute(req, agent_id="recon", ctx=_ctx())
    assert res.status == "denied_out_of_scope"
    assert ran["v"] is False  # the sandbox must never have been reached


async def test_invalid_params_denied():
    audit = InMemoryAuditSink()
    ex = _engine({"juiceshop": ["172.20.0.5"]}, audit)
    # top_ports out of allowed range
    req = ToolRequest(
        tool_id="port_scan",
        operation_class=OperationClass.ACTIVE_AUTHORIZED,
        target="juiceshop",
        params={"top_ports": 99999},
    )
    res = await ex.execute(req, agent_id="recon", ctx=_ctx())
    assert res.status == "invalid_params"


async def test_active_op_needs_approval_at_level1():
    audit = InMemoryAuditSink()
    # No approval resolver -> default denies -> awaiting_approval.
    ex = _engine({"juiceshop": ["172.20.0.5"]}, audit)
    req = ToolRequest(tool_id="port_scan", operation_class=OperationClass.ACTIVE_AUTHORIZED, target="juiceshop")
    res = await ex.execute(req, agent_id="recon", ctx=_ctx(AutonomyLevel.ASSISTED))
    assert res.status == "awaiting_approval"


async def test_passive_probe_runs_without_approval(monkeypatch):
    async def _probe(plan, target):
        return ToolRunResult("http_probe", True, 0, "", "", False,
                             structured={"status_code": 200, "server": "x",
                                         "missing_security_headers": ["content-security-policy"]})

    monkeypatch.setattr(executor_mod, "run_http_probe", _probe)
    audit = InMemoryAuditSink()
    ex = _engine({"juiceshop": ["172.20.0.5"]}, audit)
    req = ToolRequest(tool_id="http_probe", operation_class=OperationClass.PASSIVE, target="http://juiceshop")
    res = await ex.execute(req, agent_id="recon", ctx=_ctx(AutonomyLevel.SEMI_AUTONOMOUS))
    assert res.status == "executed" and res.run.structured["status_code"] == 200


async def test_container_op_autoruns_in_lab_at_level3(monkeypatch):
    async def _run(plan, limits):
        return ToolRunResult(plan.tool_id, True, 0, "<nmaprun/>", "", False)

    monkeypatch.setattr(executor_mod, "run_container", _run)
    audit = InMemoryAuditSink()
    ex = _engine({"juiceshop": ["172.20.0.5"]}, audit, approve=_always_grant)
    req = ToolRequest(tool_id="port_scan", operation_class=OperationClass.ACTIVE_AUTHORIZED, target="juiceshop")
    res = await ex.execute(req, agent_id="recon", ctx=_ctx(AutonomyLevel.AUTONOMOUS_LAB))
    assert res.status == "executed"
