"""Phase 6 — Reporting Agent (A8) tests.

Self-contained (no DB, no Docker): the executive-narrative builder (grounded, no
fabrication), the Markdown renderer, the PDF renderer, and that build_report attaches a
narrative block.
"""
from __future__ import annotations

from app.agents.orchestrator import OrchestratorResult
from app.agents.reporting import build_narrative
from app.reporting.report import build_report, render_markdown, render_pdf

_REPORT = {
    "schema_version": "1.0",
    "generated_at": "2026-10-24T00:00:00Z",
    "project": "Juice Shop Lab",
    "objective": "assess the authorized lab",
    "authorized_target": "http://172.18.0.4:3000",
    "run": {"state": "completed", "stop_reason": "objective complete",
            "tool_calls_used": 2, "cost_usd": 0.0},
    "summary": {
        "assets": 1, "findings_total": 2,
        "findings_by_status": {"suspected": 1, "lab_confirmed": 1},
        "findings_by_severity": {"high": 1, "medium": 1},
        "lab_confirmed": 1, "note": "Findings start 'suspected' ...",
    },
    "assets": [],
    "findings": [
        {"asset": "h", "vulnerability_id": "VULN-1", "cve": None, "cwe": "CWE-693",
         "severity": "high", "status": "lab_confirmed", "confidence": "firm",
         "evidence": [{"kind": "http", "summary": "missing CSP"}],
         "recommended_validation": "", "remediation": "add CSP"},
        {"asset": "h", "vulnerability_id": "VULN-2", "cve": None, "cwe": "CWE-614",
         "severity": "medium", "status": "suspected", "confidence": "tentative",
         "evidence": [{"kind": "http", "summary": "cookie without Secure"}],
         "recommended_validation": "", "remediation": "set Secure"},
    ],
    "validations": [
        {"finding": "VULN-1", "asset": "h", "environment": "lab", "reproduced": True,
         "new_status": "lab_confirmed", "evidence": [], "notes": ""}
    ],
    "reasoning": {
        "owasp_summary": {"A05:2021": 1},
        "prioritized": [
            {"vulnerability_id": "VULN-1", "cwe": "CWE-693", "severity": "high", "score": 7},
            {"vulnerability_id": "VULN-2", "cwe": "CWE-614", "severity": "medium", "score": 3},
        ],
        "risk_graph": {"nodes": [], "edges": [
            {"from": "VULN-1", "to": "VULN-2", "relation": "xss_surface_enables_session_theft"}
        ]},
        "proposed_investigations": ["Probe additional routes for a consistent CSP."],
    },
    "decisions": [],
    "audit_summary": {"executed": 2},
}


def test_narrative_is_grounded_in_the_report():
    n = build_narrative(_REPORT)
    assert "2 suspected finding" in n.headline
    assert "1 lab-confirmed" in n.headline
    # Key findings reference only real finding ids — nothing fabricated.
    real_ids = {f["vulnerability_id"] for f in _REPORT["findings"]}
    for line in n.key_findings:
        assert any(vid in line for vid in real_ids)
    assert any("VULN-1" in line for line in n.key_findings)
    assert n.risk_chains == ["VULN-1 → VULN-2: xss_surface_enables_session_theft"]
    assert any("VULN-1" in p for p in n.priorities)
    assert n.proposed_next_steps  # carried from reasoning
    assert "audit" in n.scope_and_method.lower()


def test_narrative_handles_no_findings():
    empty = {"summary": {"findings_total": 0, "findings_by_severity": {}, "lab_confirmed": 0},
             "authorized_target": "http://x", "run": {"state": "completed"},
             "findings": [], "audit_summary": {}}
    n = build_narrative(empty)
    assert "0 suspected" in n.headline
    assert "No suspected findings" in n.overview


def test_render_markdown_contains_sections_and_rows():
    md = render_markdown(_REPORT)
    assert "# Security Report — Juice Shop Lab" in md
    assert "## Executive summary" in md
    assert "## Findings" in md
    assert "| Severity | Status | Confidence | ID | CWE | Evidence |" in md
    assert "VULN-1" in md and "CWE-693" in md
    assert "## Lab validations" in md


def test_render_pdf_returns_pdf_bytes():
    pdf = render_pdf(_REPORT)
    assert isinstance(pdf, (bytes, bytearray))
    assert bytes(pdf[:5]) == b"%PDF-"
    assert len(pdf) > 500


def test_build_report_attaches_narrative():
    result = OrchestratorResult(
        state="completed", stop_reason="objective complete", recon=None,
        findings=[], decisions=[], audit=[], tool_calls_used=0, cost_usd=0.0,
    )
    report = build_report(
        project_name="P", objective="o", target="http://127.0.0.1:3000", result=result
    )
    assert "narrative" in report
    assert report["narrative"]["headline"]
    assert report["summary"]["findings_total"] == 0
    # Renderers work on a real build_report output too.
    assert "# Security Report — P" in render_markdown(report)
    assert bytes(render_pdf(report)[:5]) == b"%PDF-"
