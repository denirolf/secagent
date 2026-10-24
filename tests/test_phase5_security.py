"""Phase 5 — production-hardening tests.

Self-contained (no DB, no Docker): API-key hashing/roles, the RBAC dependency via a tiny
app, the token-bucket rate limiter and its middleware, and the cost/limit guard.
"""
from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.orchestration.limits import CostModel, LimitGuard, RunLimits
from app.security import auth, deps
from app.security.auth import Principal
from app.security.ratelimit import RateLimiter, RateLimitMiddleware


# --------------------------------------------------------------------------- API keys
def test_generate_parse_and_verify_roundtrip():
    gen = auth.generate_api_key(pepper="pep")
    parsed = auth.parse_token(gen.token)
    assert parsed is not None
    prefix, secret = parsed
    assert prefix == gen.prefix
    assert auth.verify_secret(secret, "pep", gen.key_hash) is True
    # Wrong secret and wrong pepper both fail.
    assert auth.verify_secret("not-it", "pep", gen.key_hash) is False
    assert auth.verify_secret(secret, "wrong-pepper", gen.key_hash) is False


def test_parse_token_rejects_malformed():
    for bad in ["", "nope", "sk-only", "xx-a-b", "sk--b", "sk-a-"]:
        assert auth.parse_token(bad) is None


def test_role_hierarchy():
    assert auth.role_satisfies("admin", "viewer")
    assert auth.role_satisfies("operator", "operator")
    assert auth.role_satisfies("viewer", "viewer")
    assert not auth.role_satisfies("viewer", "operator")
    assert not auth.role_satisfies("operator", "admin")
    assert not auth.role_satisfies("nonsense", "viewer")


# --------------------------------------------------------------------------- RBAC dependency
def _app_with_gate(minimum: str) -> FastAPI:
    app = FastAPI()

    @app.get("/x", dependencies=[Depends(deps.require_role(minimum))])
    async def x():
        return {"ok": True}

    return app


def test_rbac_disabled_allows_anyone(monkeypatch):
    class S:  # auth off → synthetic admin, no token needed
        auth_enabled = False
        api_key_pepper = ""

    monkeypatch.setattr(deps, "get_settings", lambda: S)
    client = TestClient(_app_with_gate("admin"))
    assert client.get("/x").status_code == 200


def test_rbac_enabled_enforces_token_and_role(monkeypatch):
    class S:
        auth_enabled = True
        api_key_pepper = "pep"

    monkeypatch.setattr(deps, "get_settings", lambda: S)

    async def fake_auth(session, token, pepper):
        # token carries the role we want to simulate, e.g. "viewer" / "operator" / "admin"
        return Principal(role=token) if token in auth.ROLES else None

    monkeypatch.setattr(deps, "authenticate", fake_auth)
    client = TestClient(_app_with_gate("operator"))

    # no bearer -> 401
    assert client.get("/x").status_code == 401
    # unknown key -> 401
    assert client.get("/x", headers={"Authorization": "Bearer bogus"}).status_code == 401
    # viewer lacks operator -> 403
    assert client.get("/x", headers={"Authorization": "Bearer viewer"}).status_code == 403
    # operator ok, admin (higher) ok
    assert client.get("/x", headers={"Authorization": "Bearer operator"}).status_code == 200
    assert client.get("/x", headers={"Authorization": "Bearer admin"}).status_code == 200


# --------------------------------------------------------------------------- rate limiter
def test_token_bucket_allows_burst_then_blocks_then_refills():
    now = {"t": 0.0}
    limiter = RateLimiter(capacity=2, refill_per_sec=1.0, clock=lambda: now["t"])

    assert limiter.check("k")[0] is True   # 2 -> 1
    assert limiter.check("k")[0] is True   # 1 -> 0
    allowed, retry = limiter.check("k")     # 0 -> blocked
    assert allowed is False and retry > 0

    now["t"] = 1.0                          # one token refilled
    assert limiter.check("k")[0] is True
    assert limiter.check("k")[0] is False

    # a different key has its own bucket
    assert limiter.check("other")[0] is True


def test_rate_limit_middleware_429_and_exempt():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(capacity=1, refill_per_sec=0.0))

    @app.get("/x")
    async def x():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    client = TestClient(app)
    assert client.get("/x").status_code == 200       # consumes the only token
    r = client.get("/x")
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    # exempt path is never limited
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200


# --------------------------------------------------------------------------- cost / limit guard
def test_guard_budget_ceiling_from_tool_call_estimate():
    guard = LimitGuard(
        RunLimits(max_iterations=100, max_tool_calls=100, max_budget_usd=2.5),
        CostModel(per_tool_call_usd=1.0),
    )
    guard.record_tool_calls(2)
    assert guard.exceeded() is None          # $2.00 < $2.50
    guard.record_tool_calls(3)               # +1 call -> $3.00
    assert "max_budget_usd" in (guard.exceeded() or "")


def test_guard_record_tool_calls_is_idempotent():
    guard = LimitGuard(
        RunLimits(max_iterations=100, max_tool_calls=100, max_budget_usd=0.0),
        CostModel(per_tool_call_usd=1.0),
    )
    guard.record_tool_calls(3)
    guard.record_tool_calls(3)               # no new calls -> no new cost
    assert guard.cost_usd == pytest.approx(3.0)


def test_guard_zero_budget_means_unlimited():
    guard = LimitGuard(
        RunLimits(max_iterations=100, max_tool_calls=100, max_budget_usd=0.0),
        CostModel(per_tool_call_usd=5.0),
    )
    guard.record_tool_calls(100)             # $500 accrued, but budget 0 == no ceiling
    assert guard.exceeded() is None


def test_guard_iteration_ceiling():
    guard = LimitGuard(RunLimits(max_iterations=2, max_tool_calls=100, max_budget_usd=0.0))
    guard.step()
    assert guard.exceeded() is None
    guard.step()
    assert "max_iterations" in (guard.exceeded() or "")


# --------------------------------------------------------------------------- metrics
def test_metrics_helpers_are_safe_and_render():
    from app.observability import metrics

    # Should never raise regardless of whether prometheus_client is installed.
    metrics.observe_tool_call("port_scan", "denied_out_of_scope")
    metrics.observe_run("completed")
    metrics.observe_findings("suspected", 2)
    metrics.observe_http("GET", "/health", 200, 0.01)
    metrics.observe_rate_limited()
    body, content_type = metrics.render()
    assert isinstance(body, bytes)
    assert isinstance(content_type, str)
