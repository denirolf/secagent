"""Agent 6 — Authentication Security Agent.

Phase 3 scope is the **passive, non-destructive** part of authentication review: session
cookie flags (HttpOnly / Secure / SameSite) and related session-security posture, derived
from evidence already collected in the lab. It produces SUSPECTED findings only.

Hard boundaries (by design, matching the spec):
  - No password spraying, credential stuffing, or attempts against unknown/real accounts.
  - Any ACTIVE credential test is lab-only, uses exclusively synthetic test accounts and
    lab-generated hashes, and requires approval. Those active checks are NOT performed in
    this phase; this agent only analyzes observed session posture.
"""
from __future__ import annotations

from app.agents.recon import ReconResult
from app.contracts.enums import Confidence, FindingStatus, Severity
from app.contracts.messages import Evidence, Finding

# Cookie flag -> (cwe, severity, remediation)
_COOKIE_RULES = {
    "httponly": ("CWE-1004", Severity.MEDIUM,
                 "Set HttpOnly so client-side script cannot read the session cookie."),
    "secure": ("CWE-614", Severity.MEDIUM,
               "Set Secure so the cookie is only sent over HTTPS."),
    "samesite": ("CWE-1275", Severity.LOW,
                 "Set SameSite=Lax or Strict to reduce CSRF exposure."),
}

# Cookie names that look session/auth related (so we don't flag benign analytics cookies).
_SESSIONISH = ("session", "sess", "token", "auth", "jwt", "sid", "connect.sid")


def _is_sessionish(name: str) -> bool:
    n = name.lower()
    return any(s in n for s in _SESSIONISH)


def analyze_auth_posture(recon: ReconResult) -> list[Finding]:
    findings: list[Finding] = []
    http = recon.http or {}
    cookies = http.get("cookies", []) or []
    asset = recon.host

    for i, c in enumerate(cookies):
        name = c.get("name", "")
        if not _is_sessionish(name):
            continue
        if not c.get("httponly"):
            cwe, sev, rem = _COOKIE_RULES["httponly"]
            findings.append(_finding(asset, f"COOKIE-HTTPONLY-{i}", cwe, sev,
                f"Session-like cookie {name!r} is set without the HttpOnly flag.", rem))
        if not c.get("secure"):
            cwe, sev, rem = _COOKIE_RULES["secure"]
            findings.append(_finding(asset, f"COOKIE-SECURE-{i}", cwe, sev,
                f"Session-like cookie {name!r} is set without the Secure flag.", rem))
        if not c.get("samesite"):
            cwe, sev, rem = _COOKIE_RULES["samesite"]
            findings.append(_finding(asset, f"COOKIE-SAMESITE-{i}", cwe, sev,
                f"Session-like cookie {name!r} has no SameSite attribute.", rem))
    return findings


def _finding(asset, vid, cwe, severity, summary, remediation) -> Finding:
    return Finding(
        asset=asset, vulnerability_id=vid, cwe=cwe, severity=severity,
        status=FindingStatus.SUSPECTED, confidence=Confidence.HIGH,
        evidence=[Evidence(kind="http_response", summary=summary)],
        recommended_validation="Re-request a route that sets the cookie and confirm the "
                               "flag is absent; in the lab, confirm session fixation/theft "
                               "preconditions with synthetic accounts only.",
        remediation=remediation,
    )
