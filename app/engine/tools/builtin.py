"""Phase 1 tool specs: port_scan (nmap), http_probe (in-process), nuclei_scan.

Each tool has a strict Pydantic params model and a fixed argv builder. Targets are
passed positionally and are re-authorized by the Scope Engine before execution.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import OperationClass
from app.engine.registry import ToolSpec

# A conservative host/URL shape. Full authorization is the Scope Engine's job; this just
# rejects obviously malformed values and anything with shell metacharacters.
_SAFE = re.compile(r"^[A-Za-z0-9._:\-/]+$")


def _safe_target(v: str) -> str:
    if not _SAFE.match(v):
        raise ValueError("target contains disallowed characters")
    return v


# --------------------------------------------------------------------------- port_scan
class PortScanParams(BaseModel):
    top_ports: int = Field(default=100, ge=1, le=1000)
    service_detection: bool = True

    model_config = {"extra": "forbid"}


def _nmap_argv(params: BaseModel, target: str) -> list[str]:
    assert isinstance(params, PortScanParams)
    host = _safe_target(target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0])
    # -sT (TCP connect) needs no raw-socket capability, so the sandbox can keep
    # --cap-drop ALL. -Pn skips host discovery; service detection is optional.
    argv = ["nmap", "-sT", "-Pn", "--top-ports", str(params.top_ports), "-oX", "-"]
    if params.service_detection:
        argv.insert(1, "-sV")
    argv.append(host)
    return argv


PORT_SCAN = ToolSpec(
    tool_id="port_scan",
    description=(
        "Scan an AUTHORIZED target for open TCP ports and service/version banners using "
        "nmap. Active operation; only runs against authorized targets."
    ),
    params_model=PortScanParams,
    operation_class=OperationClass.ACTIVE_AUTHORIZED,
    kind="container",
    timeout_s=240,
    requires_approval=False,  # low-risk active op; auto at autonomy level >= 2
    input_schema={"top_ports": int, "service_detection": bool},
    build_argv=_nmap_argv,
    image="instrumentisto/nmap:latest",
)


# --------------------------------------------------------------------------- http_probe
class HttpProbeParams(BaseModel):
    path: str = Field(default="/")
    follow_redirects: bool = False  # redirects are re-authorized, never auto-followed out

    model_config = {"extra": "forbid"}

    @field_validator("path")
    @classmethod
    def _check_path(cls, v: str) -> str:
        if not v.startswith("/") or ".." in v:
            raise ValueError("path must be absolute and must not contain '..'")
        return v


HTTP_PROBE = ToolSpec(
    tool_id="http_probe",
    description=(
        "Passively read an AUTHORIZED web target's HTTP response: status code, headers, "
        "title, server banner, and which security headers are present or missing."
    ),
    params_model=HttpProbeParams,
    operation_class=OperationClass.PASSIVE,
    kind="inprocess",
    timeout_s=30,
    requires_approval=False,
    input_schema={"path": str, "follow_redirects": bool},
)


# --------------------------------------------------------------------------- nuclei_scan
class NucleiScanParams(BaseModel):
    # Only vetted, non-intrusive template groups are permitted.
    template_groups: list[str] = Field(default_factory=lambda: ["http/misconfiguration"])
    severity: list[str] = Field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])

    model_config = {"extra": "forbid"}

    _ALLOWED_GROUPS = {"http/misconfiguration", "http/technologies", "http/exposed-panels"}

    @field_validator("template_groups")
    @classmethod
    def _only_vetted(cls, v: list[str]) -> list[str]:
        bad = [g for g in v if g not in cls._ALLOWED_GROUPS]
        if bad:
            raise ValueError(f"template groups not approved: {bad}")
        return v


def _nuclei_argv(params: BaseModel, target: str) -> list[str]:
    assert isinstance(params, NucleiScanParams)
    url = _safe_target(target)
    argv = ["nuclei", "-u", url, "-jsonl", "-no-color", "-silent",
            "-severity", ",".join(params.severity)]
    for group in params.template_groups:
        argv += ["-t", group]
    return argv


NUCLEI_SCAN = ToolSpec(
    tool_id="nuclei_scan",
    description=(
        "Run nuclei against an AUTHORIZED web target using only vetted, non-intrusive "
        "template groups. Active operation; requires approval by default."
    ),
    params_model=NucleiScanParams,
    operation_class=OperationClass.ACTIVE_AUTHORIZED,
    kind="container",
    timeout_s=300,
    requires_approval=True,  # heavier active scan -> human gate unless autonomy level 3 lab
    input_schema={"template_groups": list, "severity": list},
    build_argv=_nuclei_argv,
    image="projectdiscovery/nuclei:latest",
)


ALL_PHASE1_TOOLS = [PORT_SCAN, HTTP_PROBE, NUCLEI_SCAN]
