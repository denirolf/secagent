"""Reporting: assemble a structured JSON vulnerability report and render it.

The JSON here is the canonical artifact and carries everything the other formats need,
including the suspected/lab_confirmed/confirmed_authorized breakdown and an audit summary.
`build_report` also attaches the Reporting Agent's (A8) executive `narrative`; `render_html`,
`render_markdown`, and `render_pdf` turn the same report into the shareable formats.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.agents.orchestrator import OrchestratorResult
from app.agents.reporting import build_narrative


def build_report(
    *, project_name: str, objective: str, target: str, result: OrchestratorResult
) -> dict[str, Any]:
    findings = result.findings
    # A finding's effective status reflects any Phase 2 lab validation outcome.
    outcomes = {v.finding_vuln_id: v for v in result.validations}

    def effective_status(f) -> str:
        o = outcomes.get(f.vulnerability_id)
        return o.new_status.value if o else f.status.value

    by_status = Counter(effective_status(f) for f in findings)
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

    report: dict[str, Any] = {
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
            "lab_confirmed": by_status.get("lab_confirmed", 0),
            "note": (
                "Findings start 'suspected' (a scanner/probe signal, not a confirmation). "
                "A finding becomes 'lab_confirmed' only when reproduced in the isolated lab. "
                "'confirmed_authorized' additionally requires validation in the authorized "
                "environment plus human sign-off and is never set automatically."
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
                "status": effective_status(f),
                "confidence": f.confidence.value,
                "evidence": [{"kind": e.kind, "summary": e.summary} for e in f.evidence],
                "recommended_validation": f.recommended_validation,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "validations": [
            {
                "finding": v.finding_vuln_id,
                "asset": v.asset,
                "environment": v.environment,
                "reproduced": v.reproduced,
                "new_status": v.new_status.value,
                "evidence": [{"kind": e.kind, "summary": e.summary} for e in v.evidence],
                "notes": v.notes,
            }
            for v in result.validations
        ],
        "reasoning": _reasoning_block(result),
        "decisions": [
            {"step": d.step, "action": d.action, "rationale": d.rationale, "at": d.at}
            for d in result.decisions
        ],
        "audit_summary": dict(audit_summary),
    }
    # Agent 8 (Reporting) adds a human-readable narrative grounded in the data above.
    report["narrative"] = build_narrative(report).to_dict()
    return report


def _reasoning_block(result) -> dict | None:
    r = result.reasoning
    if r is None:
        return None
    return {
        "owasp_summary": r.owasp_summary,
        "prioritized": r.prioritized,
        "risk_graph": {"nodes": r.risk_graph.nodes, "edges": r.risk_graph.edges},
        "proposed_investigations": r.proposed_investigations,
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


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as a Markdown document (executive narrative + tables)."""
    s = report["summary"]
    n = report.get("narrative") or build_narrative(report).to_dict()
    out: list[str] = [
        f"# Security Report — {report['project']}",
        "",
        f"**Authorized target:** {report['authorized_target']}  ",
        f"**Generated:** {report['generated_at']}  ",
        f"**Run state:** {report['run']['state']} ({report['run']['stop_reason']})",
        "",
    ]
    if n:
        out += [f"> {n.get('headline', '')}", "", "## Executive summary", n.get("overview", "")]
        for title, key in (
            ("Key findings", "key_findings"),
            ("Risk chains", "risk_chains"),
            ("Prioritized", "priorities"),
            ("Proposed next steps", "proposed_next_steps"),
        ):
            items = n.get(key) or []
            if items:
                out += ["", f"**{title}**", *[f"- {i}" for i in items]]
    out += [
        "",
        "## Summary",
        f"- Assets: {s['assets']}",
        f"- Findings: {s['findings_total']}",
        f"- By severity: {s['findings_by_severity']}",
        f"- By status: {s['findings_by_status']}",
        f"- Lab-confirmed: {s.get('lab_confirmed', 0)}",
        "",
        "## Findings",
        "",
        "| Severity | Status | Confidence | ID | CWE | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for f in report["findings"]:
        ev = (f["evidence"][0]["summary"] if f.get("evidence") else "").replace("|", "\\|")
        out.append(
            f"| {f['severity']} | {f['status']} | {f['confidence']} | "
            f"{f['vulnerability_id']} | {f.get('cwe') or ''} | {ev} |"
        )
    if not report["findings"]:
        out.append("| — | — | — | — | — | no suspected findings |")
    if report.get("validations"):
        out += ["", "## Lab validations"]
        for v in report["validations"]:
            out.append(
                f"- {v['finding']} @ {v['environment']}: "
                f"reproduced={v['reproduced']} → {v['new_status']}"
            )
    out += ["", "## Scope & method", n.get("scope_and_method", ""), "", f"_{s.get('note', '')}_", ""]
    return "\n".join(out)


def _pdf_safe(text: str) -> str:
    # Core PDF fonts are latin-1; map the unicode we emit, then drop anything else.
    repl = {
        "→": "->", "—": "-", "–": "-", "•": "-", "…": "...",
        "“": '"', "”": '"', "‘": "'", "’": "'", "·": "*",
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


def render_pdf(report: dict[str, Any]) -> bytes:
    """Render the report as a PDF (pure-Python via fpdf2; no system libraries)."""
    from fpdf import FPDF  # lazy import so this module stays importable without fpdf2
    from fpdf.enums import XPos, YPos

    s = report["summary"]
    n = report.get("narrative") or build_narrative(report).to_dict()
    pdf = FPDF(unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def heading(text: str, size: int = 13) -> None:
        pdf.set_font("Helvetica", "B", size)
        pdf.multi_cell(0, 8, _pdf_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    def para(text: str, size: int = 10) -> None:
        pdf.set_font("Helvetica", "", size)
        pdf.multi_cell(0, 5, _pdf_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    heading(f"Security Report - {report['project']}", 16)
    para(f"Authorized target: {report['authorized_target']}")
    para(f"Generated: {report['generated_at']}")
    para(f"Run state: {report['run']['state']} ({report['run']['stop_reason']})")
    pdf.ln(2)

    if n:
        heading("Executive summary")
        para(n.get("overview", ""))
        for title, key in (
            ("Key findings", "key_findings"),
            ("Risk chains", "risk_chains"),
            ("Prioritized", "priorities"),
            ("Proposed next steps", "proposed_next_steps"),
        ):
            items = n.get(key) or []
            if items:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 10)
                pdf.multi_cell(0, 5, _pdf_safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font("Helvetica", "", 10)
                for item in items:
                    pdf.multi_cell(0, 5, _pdf_safe(f"- {item}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    heading("Summary")
    para(f"Assets: {s['assets']}   Findings: {s['findings_total']}   "
         f"Lab-confirmed: {s.get('lab_confirmed', 0)}")
    para(f"By severity: {s['findings_by_severity']}")
    para(f"By status: {s['findings_by_status']}")
    pdf.ln(2)

    heading("Findings")
    for f in report["findings"]:
        ev = f["evidence"][0]["summary"] if f.get("evidence") else ""
        para(f"[{f['severity']}/{f['status']}] {f['vulnerability_id']} "
             f"{f.get('cwe') or ''} - {ev}")
    if not report["findings"]:
        para("No suspected findings.")
    pdf.ln(2)

    heading("Scope & method")
    para(n.get("scope_and_method", ""))
    para(s.get("note", ""))

    return bytes(pdf.output())
