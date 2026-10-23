"""Isolated-lab helpers for Phase 2 validation.

Resetting the environment between tests is a lab-only operation: it restarts a dedicated
lab container so each validation starts from a known-good state. It is best-effort and
only ever touches the named lab container; it never operates on anything outside the lab.
"""
from __future__ import annotations

import asyncio


async def reset_lab_target(container_name: str, *, wait_ready_s: int = 20) -> bool:
    """Restart a dedicated lab container and wait briefly for it to come back.

    Returns True on success. Best-effort: returns False if Docker/the container is absent.
    """
    if not container_name:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "restart", container_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            return False
    except (asyncio.TimeoutError, FileNotFoundError):
        return False
    # Give the service a moment to re-initialize.
    await asyncio.sleep(min(wait_ready_s, 20))
    return True
