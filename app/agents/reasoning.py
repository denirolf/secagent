"""Agent 7 — Security Reasoning Agent.

Correlates findings across the other agents, enriches them with the Knowledge Base
(CWE -> OWASP + remediation), builds a risk graph of how weaknesses chain together,
prioritizes them, and proposes further (safe, lab-only) investigations. It only reasons
over existing findings and reference data; it never changes permissions or runs tools.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.contracts.messages import Finding
from app.contracts.validation import ValidationOutcome
from app.knowledge.base import KnowledgeBase

_SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_CONF_WEIGHT = {"high": 2, "medium": 1, "low": 0}


@dataclass
class RiskGraph:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)


@dataclass
class ReasoningResult:
    prioritized: list[dict] = field(default_factory=list)
    risk_graph: RiskGraph = field(default_factory=RiskGraph)
    owasp_summary: dict[str, int] = field(default_factory=dict)
    proposed_investigations: list[str] = field(default_factory=list)


# Chain rules: (predicate over the set of CWEs present) -> edge description.
def _has(cwes: set[str], *needed: str) -> bool:
    return all(n in cwes for n in needed)


def run_reasoning(
    findings: list[Finding],
    validations: list[ValidationOutcome],
    kb: KnowledgeBase | None = None,
) -> ReasoningResult:
    kb = kb or KnowledgeBase()
    reproduced = {v.finding_vuln_id for v in validations if v.reproduced}
    cwes_present = {f.cwe for f in findings if f.cwe}

    # Prioritize.
    prioritized: list[dict] = []
    owasp_summary: dict[str, int] = {}
    nodes: list[dict] = []
    for f in findings:
        entry = kb.lookup(f.cwe)
        owasp = entry.owasp if entry else "unmapped"
        owasp_summary[owasp] = owasp_summary.get(owasp, 0) + 1
        score = _SEV_WEIGHT.get(f.severity.value, 1) + _CONF_WEIGHT.get(f.confidence.value, 0)
        if f.vulnerability_id in reproduced:
            score += 2  # lab-confirmed weighs more than merely suspected
        prioritized.append({
            "vulnerability_id": f.vulnerability_id, "cwe": f.cwe, "owasp": owasp,
            "severity": f.severity.value,
            "status": "lab_confirmed" if f.vulnerability_id in reproduced else "suspected",
            "score": score,
            "remediation": entry.remediation if entry else f.remediation,
        })
        nodes.append({"id": f.vulnerability_id, "cwe": f.cwe, "severity": f.severity.value,
                      "owasp": owasp})
    prioritized.sort(key=lambda x: x["score"], reverse=True)

    # Build chains (edges) from co-present weakness classes.
    edges: list[dict] = []

    def _ids_for(cwe: str) -> list[str]:
        return [f.vulnerability_id for f in findings if f.cwe == cwe]

    if _has(cwes_present, "CWE-693", "CWE-1004"):
        for a in _ids_for("CWE-693"):
            for b in _ids_for("CWE-1004"):
                edges.append({"from": a, "to": b, "relation": "xss_surface_enables_session_theft",
                              "rationale": "Missing script-restriction headers plus a cookie "
                                           "readable by script can chain XSS into session theft."})
    if _has(cwes_present, "CWE-319", "CWE-614"):
        for a in _ids_for("CWE-319"):
            for b in _ids_for("CWE-614"):
                edges.append({"from": a, "to": b, "relation": "downgrade_enables_cookie_interception",
                              "rationale": "No HSTS plus a cookie sent over plaintext allows "
                                           "an on-path attacker to capture the session."})

    in_chain = {e["from"] for e in edges} | {e["to"] for e in edges}
    for p in prioritized:
        if p["vulnerability_id"] in in_chain:
            p["score"] += 2
            p["in_risk_chain"] = True
    prioritized.sort(key=lambda x: x["score"], reverse=True)

    proposed = _proposals(cwes_present)
    return ReasoningResult(
        prioritized=prioritized, risk_graph=RiskGraph(nodes=nodes, edges=edges),
        owasp_summary=owasp_summary, proposed_investigations=proposed,
    )


def _proposals(cwes_present: set[str]) -> list[str]:
    out: list[str] = []
    if "CWE-693" in cwes_present:
        out.append("Probe additional routes for a consistent Content-Security-Policy and "
                   "verify no inline-script reliance (lab only).")
    if {"CWE-1004", "CWE-614", "CWE-1275"} & cwes_present:
        out.append("In the lab, confirm session-cookie handling with synthetic accounts "
                   "only (no real credentials); check fixation and logout invalidation.")
    out.append("Check authentication endpoints for rate limiting and lockout using "
               "synthetic lab accounts only — never real or unknown accounts.")
    return out
