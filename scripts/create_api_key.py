#!/usr/bin/env python3
"""Create an API key and print it once.

Run by an operator in their own terminal (the secret is printed to stdout, never to the
server logs). Requires DATABASE_URL and, when AUTH_ENABLED is on, API_KEY_PEPPER.

    python scripts/create_api_key.py --role admin --name "ops laptop"

The printed ``sk-...`` token is the bearer credential; it cannot be recovered later.
"""
from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.db import models
from app.db.base import SessionLocal
from app.security.auth import ROLES, generate_api_key


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Create an API key.")
    parser.add_argument("--role", default="viewer", choices=ROLES)
    parser.add_argument("--name", default="")
    args = parser.parse_args()

    settings = get_settings()
    if settings.auth_enabled and not settings.api_key_pepper:
        print("ERROR: AUTH_ENABLED is on but API_KEY_PEPPER is not set.")
        return 2

    gen = generate_api_key(settings.api_key_pepper)
    async with SessionLocal() as session:
        session.add(models.ApiKey(
            prefix=gen.prefix, key_hash=gen.key_hash, name=args.name, role=args.role,
        ))
        await session.commit()

    print("API key created. Store this token now — it will not be shown again:\n")
    print(f"    {gen.token}\n")
    print(f"role={args.role}  prefix={gen.prefix}  name={args.name!r}")
    if not settings.api_key_pepper:
        print("\nNote: API_KEY_PEPPER was empty; set it (and AUTH_ENABLED=true) before "
              "relying on this key in production, then re-create keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
