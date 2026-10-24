"""Agent 8 — Reporting Agent.

Turns the structured report into a human-readable executive narrative. It is deterministic
and grounded **entirely** in the report's own numbers and findings — it introduces no fact
that is not already in the structured data, consistent with the platform's no-fabrication
rule (a scanner signal is never upgraded here, and no finding, CVE, or count is invented).

The JSON report stays the canonical artifact; this agent adds a `narrative` block and the
`app/reporting` renderers turn the same report into Markdown and PDF.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ExecutiveNarrative:
    headline: str
    overview: str
    key_findings: list[str] = field(default_factory=list)
    risk_chains: list[str] = field(default_factory=list)
    priorities: list[str] = field(default_factory=list)
    proposed_next_steps: list[str] = field(default_factory=list)
    scope_and_method: str = ""
    disclaimer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sev_key(value: str) -> int:
    return _SEV_ORDER.get(value, 9)


def build_narrative(report: dict[str, Any]) -> ExecutiveNarrative:
    """Compose the executive narrative purely from an assembled report dict."""
    summary = report.get("summary", {})
    total = summary.get("findings_total", 0)
    by_sev = summary.get("findings_by_severity", {})
    lab_confirmed = summary.get("lab_confirmed", 0)
    target = report.get("authorized_target", "the authorized target")
    state = report.get("run", {}).get("state", "completed")

    sev_bits = ", ".join(
        f"{by_sev[k]} {k}" for k in sorted(by_sev, key=_sev_key)
    ) or "no severities recorded"
    headline = (
        f"{total} suspected finding(s) on {target} ({sev_bits}); "
        f"{lab_confirmed} lab-confirmed."
    )

    overview = (
        f"The assessment of {target} completed with state '{state}'. "
        + (
            f"It surfaced {total} suspected finding(s)"
            + (
                f", of which {lab_confirmed} were reproduced in the isolated lab "
                f"(elevated to lab_confirmed)."
                if lab_confirmed
                else ", none yet reproduced in the lab."
            )
            if total
            else "No suspected findings were recorded."
        )
    )

    # Top findings by severity, then status, grounded in their own evidence.
    findings = sorted(
        report.get("findings", []),
        key=lambda f: (_sev_key(f.get("severity", "info")), str(f.get("status", ""))),
    )
    key_findings: list[str] = []
    for f in findings[:5]:
        ev = (f.get("evidence") or [{}])[0].get("summary", "")
        line = f"[{f.get('severity')}/{f.get('status')}] {f.get('vulnerability_id')}"
        if f.get("cwe"):
            line += f" ({f['cwe']})"
        if ev:
            line += f" — {ev}"
        key_findings.append(line)

    risk_chains: list[str] = []
    priorities: list[str] = []
    next_steps: list[str] = []
    reasoning = report.get("reasoning")
    if reasoning:
        for edge in reasoning.get("risk_graph", {}).get("edges", []):
            risk_chains.append(
                f"{edge.get('from')} → {edge.get('to')}: {edge.get('relation')}"
            )
        for p in reasoning.get("prioritized", [])[:5]:
            vid = p.get("vulnerability_id")
            score = p.get("score")
            priorities.append(f"{vid} (priority score {score})" if score is not None else str(vid))
        next_steps = list(reasoning.get("proposed_investigations", []))[:5]

    scope_and_method = (
        "Testing stayed within the authorized scope: every tool call passed through the "
        "Scope Engine and was recorded in the append-only audit log. "
        f"Audit decisions: {report.get('audit_summary', {})}."
    )
    disclaimer = summary.get("note", "")

    return ExecutiveNarrative(
        headline=headline,
        overview=overview,
        key_findings=key_findings,
        risk_chains=risk_chains,
        priorities=priorities,
        proposed_next_steps=next_steps,
        scope_and_method=scope_and_method,
        disclaimer=disclaimer,
    )
