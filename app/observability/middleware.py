"""Request-ID + access-logging + metrics middleware."""
from __future__ import annotations

import logging
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.observability import metrics

_log = logging.getLogger("secagent.access")


def _metric_path(request: Request) -> str:
    # Use the matched route template (bounded cardinality), not the raw path with ids.
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - start
            path = _metric_path(request)
            metrics.observe_http(request.method, path, 500, duration)
            _log.exception(
                "request failed",
                extra={
                    "request_id": request_id, "method": request.method,
                    "path": path, "status": 500,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
            raise
        duration = time.perf_counter() - start
        path = _metric_path(request)
        response.headers["x-request-id"] = request_id
        metrics.observe_http(request.method, path, response.status_code, duration)
        principal = getattr(request.state, "principal", None)
        _log.info(
            "request",
            extra={
                "request_id": request_id, "method": request.method, "path": path,
                "status": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "principal": getattr(principal, "email", None),
            },
        )
        return response
