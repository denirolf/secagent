"""Reporting Agent (Phase 1): assemble a structured JSON vulnerability report.

HTML/PDF rendering arrives with Phase 4; the JSON here is the canonical artifact and
carries everything the later formats need, including the suspected/lab_confirmed/
confirmed_authorized breakdown and an audit summary.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.agents.orchestrator import OrchestratorResult


def build_report(
    *, project_name: str, objective: str, target: str, result: OrchestratorResult
) -> dict[str, Any]:
    findings = result.findings
    by_status = Counter(f.status.value for f in findings)
    by_severity = Counter(f.severity.value for f in findings)

    recon = result.recon
    assets = []
    if recon is not None:
        assets.append({
            "host": recon.host,
            "web_url": recon.web_url,
            "open_services": [
                {"port": s["port"], "service": s["service"],
                 "product": s["product"], "version": s["version"]}
                for s in recon.services if s.get("state") == "open"
            ],
            "http": recon.http,
        })

    audit_summary = Counter(e.decision for e in result.audit)

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": project_name,
        "objective": objective,
        "authorized_target": target,
        "run": {
            "state": result.state,
            "stop_reason": result.stop_reason,
            "tool_calls_used": result.tool_calls_used,
            "cost_usd": round(result.cost_usd, 4),
        },
        "summary": {
            "assets": len(assets),
            "findings_total": len(findings),
            "findings_by_status": dict(by_status),
            "findings_by_severity": dict(by_severity),
            "note": (
                "All findings are 'suspected'. None has been reproduced in an isolated lab "
                "(lab_confirmed) or validated in the authorized environment "
                "(confirmed_authorized). A scanner/probe result is a signal, not a confirmation."
            ),
        },
        "assets": assets,
        "findings": [
            {
                "asset": f.asset,
                "vulnerability_id": f.vulnerability_id,
                "cve": f.cve,
                "cwe": f.cwe,
                "severity": f.severity.value,
                "status": f.status.value,
                "confidence": f.confidence.value,
                "evidence": [{"kind": e.kind, "summary": e.summary} for e in f.evidence],
                "recommended_validation": f.recommended_validation,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "decisions": [
            {"step": d.step, "action": d.action, "rationale": d.rationale, "at": d.at}
            for d in result.decisions
        ],
        "audit_summary": dict(audit_summary),
    }


def render_html(report: dict[str, Any]) -> str:
    """Minimal standalone HTML view of the JSON report (Phase 4 will expand this)."""
    s = report["summary"]
    rows = "".join(
        f"<tr><td>{f['severity']}</td><td>{f['status']}</td><td>{f['confidence']}</td>"
        f"<td>{f['vulnerability_id']}</td><td>{f.get('cwe') or ''}</td>"
        f"<td>{(f['evidence'][0]['summary'] if f['evidence'] else '')}</td></tr>"
        for f in report["findings"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Security Report — {report['project']}</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;font-size:14px}}
.note{{background:#fff8e1;border:1px solid #f0d98a;padding:10px;border-radius:6px}}</style></head>
<body><h1>Security Report — {report['project']}</h1>
<p><b>Authorized target:</b> {report['authorized_target']} &middot;
<b>Generated:</b> {report['generated_at']}</p>
<p class="note">{s['note']}</p>
<h2>Summary</h2><p>Assets: {s['assets']} &middot; Findings: {s['findings_total']}
&middot; By severity: {s['findings_by_severity']} &middot; By status: {s['findings_by_status']}</p>
<h2>Suspected findings</h2>
<table><tr><th>Severity</th><th>Status</th><th>Confidence</th><th>ID</th><th>CWE</th><th>Evidence</th></tr>
{rows}</table></body></html>"""
