"""WebSocket endpoint for live run monitoring."""
from __future__ import annotations

import asyncio
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.orchestration.events import bus

router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def run_events(websocket: WebSocket, run_id: UUID):
    await websocket.accept()
    q = bus.subscribe(run_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue
            await websocket.send_json(event)
            if event.get("type") == "done":
                break
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(run_id, q)
