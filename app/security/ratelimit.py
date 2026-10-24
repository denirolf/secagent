"""Token-bucket rate limiting.

``RateLimiter`` is a pure, injectable-clock token bucket (unit tested directly).
``RateLimitMiddleware`` applies it per API key (when present) or per client IP, and returns
``429`` with a ``Retry-After`` header. For multiple API instances, back this with Redis
(see docs/DEPLOYMENT.md); the middleware interface is unchanged.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from math import ceil

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.observability import metrics
from app.security.auth import parse_token

# Never rate-limit the operational probes.
EXEMPT_PATHS = {"/health", "/ready", "/metrics"}


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, capacity: float, refill_per_sec: float, clock=time.monotonic) -> None:
        self.capacity = max(1.0, float(capacity))
        self.refill = max(0.0, float(refill_per_sec))
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str) -> tuple[bool, float]:
        """Consume one token for ``key``. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self.capacity, updated=now)
            self._buckets[key] = bucket
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill)
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True, 0.0
        retry = (1.0 - bucket.tokens) / self.refill if self.refill > 0 else 60.0
        return False, retry


def client_key(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        parsed = parse_token(header[7:].strip())
        if parsed:
            return f"key:{parsed[0]}"
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None) -> None:
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        if self.limiter is None or request.url.path in EXEMPT_PATHS:
            return await call_next(request)
        allowed, retry_after = self.limiter.check(client_key(request))
        if not allowed:
            metrics.observe_rate_limited()
            return JSONResponse(
                {"detail": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(max(1, ceil(retry_after)))},
            )
        return await call_next(request)
