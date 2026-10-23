"""Deterministic parsing of tool output into assets, evidence, and SUSPECTED findings.

Findings are derived here from concrete tool evidence, never invented by the model.
Every finding produced is `suspected` — scanner/probe output is a signal, not a
confirmation. Elevation beyond `suspected` happens only through the Phase 2 validation
lab plus human sign-off.
"""
from __future__ import annotations

import json
import re
from xml.etree import ElementTree as ET

from app.contracts.enums import Confidence, FindingStatus, Severity
from app.contracts.messages import Evidence, Finding

# Maps a missing security header to (severity, cwe, remediation).
_HEADER_RULES = {
    "content-security-policy": (Severity.MEDIUM, "CWE-693",
        "Define a Content-Security-Policy restricting script/style/connect sources."),
    "strict-transport-security": (Severity.MEDIUM, "CWE-319",
        "Serve HSTS over HTTPS so browsers refuse plaintext downgrades."),
    "x-frame-options": (Severity.LOW, "CWE-1021",
        "Set X-Frame-Options: DENY or a frame-ancestors CSP directive to prevent clickjacking."),
    "x-content-type-options": (Severity.LOW, "CWE-693",
        "Set X-Content-Type-Options: nosniff to stop MIME sniffing."),
    "referrer-policy": (Severity.INFO, "CWE-200",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin."),
    "permissions-policy": (Severity.INFO, "CWE-693",
        "Set a Permissions-Policy to restrict powerful browser features."),
}


def parse_nmap_xml(xml: str) -> list[dict]:
    """Return [{port, proto, state, service, product, version}] from nmap -oX output."""
    out: list[dict] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            out.append({
                "port": int(port.get("portid", "0")),
                "proto": port.get("protocol", "tcp"),
                "state": state.get("state") if state is not None else "unknown",
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            })
    return out


def parse_nuclei_jsonl(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def findings_from_http_probe(asset: str, probe: dict, seq: int) -> list[Finding]:
    findings: list[Finding] = []
    url = probe.get("url", asset)
    for i, header in enumerate(probe.get("missing_security_headers", [])):
        rule = _HEADER_RULES.get(header)
        if not rule:
            continue
        sev, cwe, remediation = rule
        findings.append(Finding(
            asset=asset,
            vulnerability_id=f"HDR-{seq}-{i}",
            cwe=cwe,
            severity=sev,
            status=FindingStatus.SUSPECTED,
            confidence=Confidence.HIGH,  # the header is objectively absent
            evidence=[Evidence(
                kind="http_response",
                summary=f"Response from {url} (status {probe.get('status_code')}) "
                        f"is missing the '{header}' header.",
            )],
            recommended_validation="Re-request the endpoint and confirm the header is absent "
                                   "across representative routes.",
            remediation=remediation,
        ))
    banner = (probe.get("server") or "") + " " + (probe.get("x_powered_by") or "")
    if banner.strip():
        findings.append(Finding(
            asset=asset,
            vulnerability_id=f"BANNER-{seq}",
            cwe="CWE-200",
            severity=Severity.INFO,
            status=FindingStatus.SUSPECTED,
            confidence=Confidence.MEDIUM,
            evidence=[Evidence(kind="banner",
                summary=f"Server discloses technology banner: {banner.strip()!r}.")],
            recommended_validation="Confirm the banner on a fresh request; correlate the "
                                   "disclosed version against NVD/CISA KEV (Phase 3).",
            remediation="Suppress or genericize Server / X-Powered-By headers.",
        ))
    return findings


_VERSIONED = re.compile(r"\d+\.\d+")


def findings_from_services(asset: str, services: list[dict], seq: int) -> list[Finding]:
    findings: list[Finding] = []
    for i, svc in enumerate(services):
        if svc.get("state") != "open":
            continue
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        if product and version and _VERSIONED.search(version):
            findings.append(Finding(
                asset=asset,
                vulnerability_id=f"SVC-{seq}-{i}",
                cwe="CWE-200",
                severity=Severity.INFO,
                status=FindingStatus.SUSPECTED,
                confidence=Confidence.MEDIUM,
                evidence=[Evidence(kind="scanner_output",
                    summary=f"Port {svc.get('port')}/{svc.get('proto')} exposes "
                            f"{product} {version}.")],
                recommended_validation="Correlate the exact product/version against NVD and "
                                       "CISA KEV, then reproduce any candidate CVE in the lab "
                                       "(Phase 2) before treating it as confirmed.",
                remediation="Restrict exposure of the service and keep it patched.",
            ))
    return findings


def findings_from_nuclei(asset: str, rows: list[dict], seq: int) -> list[Finding]:
    sev_map = {s.value: s for s in Severity}
    findings: list[Finding] = []
    for i, row in enumerate(rows):
        info = row.get("info", {})
        sev_name = str(info.get("severity", "info")).lower()
        findings.append(Finding(
            asset=asset,
            vulnerability_id=f"NUCLEI-{seq}-{i}-{row.get('template-id','tpl')}",
            cwe=None,
            severity=sev_map.get(sev_name, Severity.INFO),
            status=FindingStatus.SUSPECTED,
            confidence=Confidence.MEDIUM,
            evidence=[Evidence(kind="scanner_output",
                summary=f"nuclei template {row.get('template-id')!r} matched at "
                        f"{row.get('matched-at', asset)}: {info.get('name','')}")],
            recommended_validation="Manually reproduce the nuclei match in the lab before "
                                   "treating it as confirmed.",
            remediation=str((info.get("remediation") or "Review the matched template guidance.")),
        ))
    return findings
