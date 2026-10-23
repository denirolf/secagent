"""A tiny in-process pub/sub for live run monitoring over WebSocket.

For the MVP this is in-memory per API process. Phase 5 would move it onto Redis so
multiple workers and API instances share a stream.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any
from uuid import UUID


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[UUID, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, run_id: UUID) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs[run_id].add(q)
        return q

    def unsubscribe(self, run_id: UUID, q: asyncio.Queue) -> None:
        self._subs[run_id].discard(q)

    async def publish(self, run_id: UUID, event: dict[str, Any]) -> None:
        for q in list(self._subs.get(run_id, ())):
            await q.put(event)


bus = EventBus()
