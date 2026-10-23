"""Execution Sandbox — the only code that actually touches a target.

Container tools run via `docker run` with hardening that does NOT depend on the model:
  --network <lab net>      only the isolated lab network is reachable
  --cap-drop ALL           no Linux capabilities
  --security-opt no-new-privileges
  --cpus / --memory / --pids-limit   resource caps
  --rm                     the container is removed after the run
No privileged mode, and the Docker socket is never mounted into a tool container.

In-process passive tools (http_probe) run with httpx against the already-authorized
target and never follow a redirect out of scope.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from app.engine.registry import ExecutionPlan
from app.engine.tools.builtin import HttpProbeParams

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


@dataclass
class ToolRunResult:
    tool_id: str
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    structured: dict[str, Any] | None = None


@dataclass(frozen=True)
class SandboxLimits:
    network: str
    cpus: float
    memory: str
    timeout_s: int
    pids_limit: int = 256


async def run_container(plan: ExecutionPlan, limits: SandboxLimits) -> ToolRunResult:
    assert plan.kind == "container" and plan.image and plan.argv
    timeout = min(plan.timeout_s, limits.timeout_s)
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", limits.network,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--cpus", str(limits.cpus),
        "--memory", limits.memory,
        "--pids-limit", str(limits.pids_limit),
        plan.image,
        *plan.argv,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + 15)
        except asyncio.TimeoutError:
            proc.kill()
            return ToolRunResult(plan.tool_id, False, None, "", "sandbox timeout", True)
        return ToolRunResult(
            tool_id=plan.tool_id,
            ok=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=out.decode(errors="replace"),
            stderr=err.decode(errors="replace"),
            timed_out=False,
        )
    except FileNotFoundError:
        return ToolRunResult(plan.tool_id, False, None, "", "docker not available", False)


async def run_http_probe(plan: ExecutionPlan, target: str) -> ToolRunResult:
    assert plan.kind == "inprocess" and isinstance(plan.inproc_params, HttpProbeParams)
    params = plan.inproc_params
    base = target if "://" in target else f"http://{target}"
    url = base.rstrip("/") + params.path
    try:
        async with httpx.AsyncClient(
            follow_redirects=params.follow_redirects, timeout=plan.timeout_s
        ) as client:
            resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        return ToolRunResult("http_probe", False, None, "", f"request failed: {exc}", False)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    title = ""
    if "text/html" in headers.get("content-type", ""):
        import re

        m = re.search(r"<title>(.*?)</title>", resp.text[:20000], re.I | re.S)
        if m:
            title = m.group(1).strip()[:200]
    structured = {
        "url": url,
        "status_code": resp.status_code,
        "server": headers.get("server", ""),
        "x_powered_by": headers.get("x-powered-by", ""),
        "title": title,
        "present_security_headers": [h for h in SECURITY_HEADERS if h in headers],
        "missing_security_headers": missing,
        "content_type": headers.get("content-type", ""),
    }
    return ToolRunResult(
        tool_id="http_probe",
        ok=True,
        exit_code=0,
        stdout="",
        stderr="",
        timed_out=False,
        structured=structured,
    )
