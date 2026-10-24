"""Phase 3 tests: auth posture analysis, knowledge base, security reasoning."""
from uuid import uuid4

import app.engine.executor as executor_mod
from app.agents.auth_security import analyze_auth_posture
from app.agents.orchestrator import MasterOrchestrator
from app.agents.reasoning import run_reasoning
from app.agents.recon import ReconResult
from app.contracts.enums import AutonomyLevel, Confidence, FindingStatus, ScopeKind, Severity
from app.contracts.messages import Evidence, Finding
from app.engine.executor import ProjectContext
from app.engine.sandbox import SandboxLimits, ToolRunResult
from app.engine.scope import AuthorizedScope
from app.knowledge.base import KnowledgeBase
from app.orchestration.limits import RunLimits

LIMITS = SandboxLimits(network="secagent_lab", cpus=1.0, memory="512m", timeout_s=60)


def _recon_with_cookie(httponly=False, secure=False, samesite=""):
    return ReconResult(
        host="juiceshop", web_url="http://juiceshop:3000",
        services=[{"port": 3000, "state": "open", "service": "http", "product": "", "version": ""}],
        http={
            "url": "http://juiceshop:3000/", "status_code": 200, "server": "",
            "x_powered_by": "Express", "missing_security_headers": ["content-security-policy"],
            "present_security_headers": [],
            "cookies": [{"name": "connect.sid", "httponly": httponly, "secure": secure,
                         "samesite": samesite}],
        },
    )


def test_auth_posture_flags_insecure_session_cookie():
    findings = analyze_auth_posture(_recon_with_cookie())
    ids = {f.vulnerability_id.split("-")[1] for f in findings}  # HTTPONLY/SECURE/SAMESITE
    assert {"HTTPONLY", "SECURE", "SAMESITE"} <= ids
    assert all(f.status == FindingStatus.SUSPECTED for f in findings)
    cwes = {f.cwe for f in findings}
    assert {"CWE-1004", "CWE-614", "CWE-1275"} <= cwes


def test_auth_posture_ignores_non_session_cookies():
    recon = _recon_with_cookie()
    recon.http["cookies"] = [{"name": "_ga", "httponly": False, "secure": False, "samesite": ""}]
    assert analyze_auth_posture(recon) == []


def test_auth_posture_secure_cookie_no_findings():
    assert analyze_auth_posture(_recon_with_cookie(True, True, "strict")) == []


def test_knowledge_base_lookup_and_search():
    kb = KnowledgeBase()
    e = kb.lookup("CWE-319")
    assert e and "Cryptographic" in e.owasp
    assert any(x.cwe == "CWE-1004" for x in kb.search("httponly") + kb.search("cookie"))


def _f(vid, cwe, sev=Severity.MEDIUM):
    return Finding(asset="juiceshop", vulnerability_id=vid, cwe=cwe, severity=sev,
                   status=FindingStatus.SUSPECTED, confidence=Confidence.HIGH,
                   evidence=[Evidence(kind="note", summary="x")],
                   recommended_validation="x", remediation="x")


def test_reasoning_builds_risk_chain_and_prioritizes():
    findings = [_f("HDR-0-0", "CWE-693"), _f("COOKIE-HTTPONLY-0", "CWE-1004"),
                _f("HDR-0-1", "CWE-319"), _f("COOKIE-SECURE-0", "CWE-614")]
    r = run_reasoning(findings, [], KnowledgeBase())
    relations = {e["relation"] for e in r.risk_graph.edges}
    assert "xss_surface_enables_session_theft" in relations
    assert "downgrade_enables_cookie_interception" in relations
    # Chained findings are prioritized above an isolated one.
    assert r.prioritized[0]["vulnerability_id"] in {
        "HDR-0-0", "COOKIE-HTTPONLY-0", "HDR-0-1", "COOKIE-SECURE-0"}
    assert r.owasp_summary and r.proposed_investigations


async def test_full_phase3_run_reports_reasoning(monkeypatch):
    nmap = ('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="3000">'
            '<state state="open"/><service name="http"/></port></ports></host></nmaprun>')
    probe = {
        "url": "http://juiceshop:3000/", "status_code": 200, "server": "", "x_powered_by": "Express",
        "missing_security_headers": ["content-security-policy", "strict-transport-security"],
        "present_security_headers": [],
        "cookies": [{"name": "connect.sid", "httponly": False, "secure": False, "samesite": ""}],
    }

    async def fake_container(plan, limits):
        return ToolRunResult(plan.tool_id, True, 0, nmap, "", False)

    async def fake_probe(plan, target):
        return ToolRunResult("http_probe", True, 0, "", "", False, structured=probe)

    monkeypatch.setattr(executor_mod, "run_container", fake_container)
    monkeypatch.setattr(executor_mod, "run_http_probe", fake_probe)

    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value="juiceshop", is_lab_env=True)]
    ctx = ProjectContext(project_id=uuid4(), autonomy_level=AutonomyLevel.AUTONOMOUS_LAB, limits=LIMITS)
    orch = MasterOrchestrator(scopes, ctx, RunLimits(30, 80, 5.0),
                              resolver=lambda h: {"juiceshop": ["172.20.0.5"]}.get(h, []))
    result = await orch.run(objective="phase3", target="http://juiceshop:3000",
                            use_llm=False, model=None, validate=True, auth_check=True, reasoning=True)

    assert result.reasoning is not None
    assert any(f.vulnerability_id.startswith("COOKIE-") for f in result.findings)

    from app.reporting.report import build_report
    report = build_report(project_name="d", objective="x", target="http://juiceshop:3000", result=result)
    assert report["reasoning"]["prioritized"], "report should carry prioritized findings"
    assert "owasp_summary" in report["reasoning"]
