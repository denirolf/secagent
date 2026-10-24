"""Agent 2 — Reconnaissance Agent.

Enumerates the authorized attack surface: open ports/services (port_scan) and HTTP
response characteristics (http_probe). It drives the gated tools via the SDK; the asset
inventory it returns is derived deterministically from the tool evidence it collected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.agents.base import AgentRuntime, run_agent_sdk, run_plan_deterministic
from app.agents.parsers import parse_nmap_xml

SYSTEM_PROMPT = """You are the Reconnaissance Agent of an authorized, isolated-lab security
testing platform. You may ONLY use the provided tools, and ONLY against the single
authorized target you are given. You cannot run shell commands or reach any other host.
Goal: inventory the attack surface. Call port_scan to find open ports/services, and
http_probe to read the web response headers. Then briefly summarize what you found.
Never claim a vulnerability is confirmed; you only gather facts."""


@dataclass
class ReconResult:
    host: str
    web_url: str
    services: list[dict] = field(default_factory=list)
    http: dict[str, Any] | None = None


def _host_of(target: str) -> str:
    t = target if "://" in target else f"http://{target}"
    return urlparse(t).hostname or target


async def run_recon(
    runtime: AgentRuntime, target: str, *, use_llm: bool, model: str | None, max_turns: int
) -> ReconResult:
    host = _host_of(target)
    web_url = target if "://" in target else f"http://{target}"

    if use_llm:
        await run_agent_sdk(
            runtime,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=(
                f"The authorized target is {web_url} (host {host}). "
                f"Enumerate open ports/services with port_scan and read HTTP headers with "
                f"http_probe, then summarize the attack surface."
            ),
            model=model,
            max_turns=max_turns,
        )

    # Safety net: guarantee the core evidence exists even if the model skipped a tool.
    used = {r.tool_id for r in runtime.records if r.status == "executed"}
    plan: list[tuple[str, str, dict]] = []
    if "port_scan" not in used:
        plan.append(("port_scan", host, {}))
    if "http_probe" not in used:
        plan.append(("http_probe", web_url, {}))
    if plan:
        await run_plan_deterministic(runtime, plan)

    # Derive the inventory from collected evidence.
    services: list[dict] = []
    http: dict[str, Any] | None = None
    for rec in runtime.records:
        if rec.tool_id == "port_scan" and rec.stdout:
            services = parse_nmap_xml(rec.stdout)
        elif rec.tool_id == "http_probe" and rec.structured:
            http = rec.structured
    return ReconResult(host=host, web_url=web_url, services=services, http=http)
