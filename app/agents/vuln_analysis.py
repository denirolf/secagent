"""Agent 3 — Vulnerability Analysis Agent.

Turns reconnaissance evidence into standardized SUSPECTED findings. Optionally runs an
approved, non-intrusive nuclei scan. Every finding it emits is `suspected` — the agent
cannot mark anything confirmed (the Finding contract enforces this).
"""
from __future__ import annotations

from app.agents.base import AgentRuntime, run_agent_sdk
from app.agents.parsers import (
    findings_from_http_probe,
    findings_from_nuclei,
    findings_from_services,
    parse_nuclei_jsonl,
)
from app.agents.recon import ReconResult
from app.contracts.messages import Finding

SYSTEM_PROMPT = """You are the Vulnerability Analysis Agent of an authorized, isolated-lab
security testing platform. You may ONLY use the provided tools against the single
authorized target. Review the reconnaissance evidence and, if useful, run nuclei_scan with
approved template groups only. You never execute shell commands. Remember: a scanner
result is NOT a confirmed vulnerability. Everything you produce is a SUSPECTED finding that
must later be reproduced in the lab before it can be considered confirmed."""


async def run_vuln_analysis(
    runtime: AgentRuntime,
    recon: ReconResult,
    *,
    use_llm: bool,
    model: str | None,
    max_turns: int,
    run_nuclei: bool = False,
) -> list[Finding]:
    if use_llm:
        hint = (
            f"Authorized target: {recon.web_url}. Recon found open services "
            f"{[s.get('port') for s in recon.services if s.get('state')=='open']} and HTTP "
            f"headers {recon.http}. "
        )
        if run_nuclei:
            hint += "Run nuclei_scan with template_groups ['http/misconfiguration'] if helpful. "
        hint += "Then summarize suspected issues. Do not claim anything is confirmed."
        await run_agent_sdk(
            runtime, system_prompt=SYSTEM_PROMPT, user_prompt=hint,
            model=model, max_turns=max_turns,
        )

    # Derive suspected findings deterministically from all evidence gathered so far.
    findings: list[Finding] = []
    asset = recon.host
    if recon.http:
        findings += findings_from_http_probe(asset, recon.http, seq=0)
    if recon.services:
        findings += findings_from_services(asset, recon.services, seq=0)
    for i, rec in enumerate(runtime.records):
        if rec.tool_id == "nuclei_scan" and rec.stdout:
            findings += findings_from_nuclei(asset, parse_nuclei_jsonl(rec.stdout), seq=i)
    return findings
