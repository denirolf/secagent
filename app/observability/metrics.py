"""Prometheus metrics.

Everything goes through the small ``observe_*`` helpers so call sites never import
prometheus_client directly, and the whole module degrades to no-ops if it is not installed
(the ``/metrics`` endpoint then serves a short notice instead of failing).
"""
from __future__ import annotations

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )

    _HAVE = True
except Exception:  # pragma: no cover - exercised only without the dependency
    _HAVE = False

if _HAVE:
    REGISTRY = CollectorRegistry()
    _HTTP = Counter(
        "secagent_http_requests_total", "HTTP requests",
        ["method", "path", "status"], registry=REGISTRY,
    )
    _LATENCY = Histogram(
        "secagent_http_request_duration_seconds", "HTTP request duration",
        ["method", "path"], registry=REGISTRY,
    )
    _TOOLS = Counter(
        "secagent_tool_calls_total", "Tool executions by decision",
        ["tool", "decision"], registry=REGISTRY,
    )
    _DENIALS = Counter(
        "secagent_scope_denials_total", "Out-of-scope denials", registry=REGISTRY,
    )
    _RUNS = Counter(
        "secagent_runs_total", "Runs by terminal state", ["state"], registry=REGISTRY,
    )
    _FINDINGS = Counter(
        "secagent_findings_total", "Findings recorded by status",
        ["status"], registry=REGISTRY,
    )
    _RATE_LIMITED = Counter(
        "secagent_rate_limited_total", "Requests rejected by the rate limiter",
        registry=REGISTRY,
    )


def available() -> bool:
    return _HAVE


def observe_http(method: str, path: str, status: int, seconds: float) -> None:
    if not _HAVE:
        return
    _HTTP.labels(method, path, str(status)).inc()
    _LATENCY.labels(method, path).observe(seconds)


def observe_tool_call(tool: str, decision: str) -> None:
    if not _HAVE:
        return
    _TOOLS.labels(tool, decision).inc()
    if decision == "denied_out_of_scope":
        _DENIALS.inc()


def observe_run(state: str) -> None:
    if _HAVE:
        _RUNS.labels(state).inc()


def observe_findings(status: str, n: int = 1) -> None:
    if _HAVE and n:
        _FINDINGS.labels(status).inc(n)


def observe_rate_limited() -> None:
    if _HAVE:
        _RATE_LIMITED.inc()


def render() -> tuple[bytes, str]:
    if not _HAVE:
        return b"# prometheus_client is not installed\n", "text/plain; charset=utf-8"
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
