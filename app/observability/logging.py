"""Logging configuration: human-readable by default, JSON for production.

JSON logs carry the request context (request_id, method, path, status, duration, principal)
so a log aggregator can correlate a request across the app. Enable with ``LOG_JSON=true``.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

# Fields the access middleware attaches to a record via ``extra=``.
_CONTEXT_FIELDS = ("request_id", "method", "path", "status", "duration_ms", "principal")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field in _CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
        )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # uvicorn's own access log duplicates ours; quiet it so there is one access line.
    logging.getLogger("uvicorn.access").handlers[:] = []
    logging.getLogger("uvicorn.access").propagate = False
