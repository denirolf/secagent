"""API-key authentication and role-based access control (RBAC).

Design notes
------------
* API keys are shown **once** at creation. Only a SHA-256 hash of ``pepper + secret`` is
  stored, so a database leak does not reveal usable keys. Verification is constant-time.
* A key carries a role: ``viewer`` < ``operator`` < ``admin``. Read endpoints require
  ``viewer``; starting a run requires ``operator``; creating projects, seeding the
  knowledge base, and managing keys require ``admin``.
* When ``AUTH_ENABLED`` is false (the default for local dev, the test suite, and the e2e)
  the dependency returns a synthetic ``admin`` principal so existing flows keep working.
  Authorization is enforced only when an operator turns it on — it can be turned *on*, and
  no autonomy level or setting weakens the Scope Engine or sandbox, which are unrelated to
  this layer.

The hashing/parsing helpers are pure functions (no DB, no FastAPI) so they can be unit
tested directly; the FastAPI dependency wraps them.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

# Role hierarchy. Higher rank satisfies a lower-or-equal requirement.
ROLES = ("viewer", "operator", "admin")
_RANK = {name: i for i, name in enumerate(ROLES)}

_PREFIX_BYTES = 5   # 10 hex chars — the non-secret public id of a key
_SECRET_BYTES = 24  # 48 hex chars — the secret portion


def role_rank(role: str) -> int:
    return _RANK.get(role, -1)


def role_satisfies(have: str, minimum: str) -> bool:
    """True if a principal with role ``have`` meets the ``minimum`` required role."""
    return role_rank(have) >= role_rank(minimum) >= 0


def hash_secret(secret: str, pepper: str) -> str:
    return hashlib.sha256(f"{pepper}{secret}".encode()).hexdigest()


def verify_secret(secret: str, pepper: str, key_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret, pepper), key_hash)


@dataclass(frozen=True)
class GeneratedKey:
    token: str       # full key, shown to the user once
    prefix: str      # public id, stored and used to look the key up
    key_hash: str    # stored; the token is never stored


def generate_api_key(pepper: str) -> GeneratedKey:
    """Mint a new key. The returned ``token`` is the only time the secret is available."""
    prefix = secrets.token_hex(_PREFIX_BYTES)
    secret = secrets.token_hex(_SECRET_BYTES)
    return GeneratedKey(
        token=f"sk-{prefix}-{secret}",
        prefix=prefix,
        key_hash=hash_secret(secret, pepper),
    )


def parse_token(token: str) -> tuple[str, str] | None:
    """Split ``sk-<prefix>-<secret>`` into ``(prefix, secret)``; None if malformed."""
    parts = token.strip().split("-")
    if len(parts) != 3 or parts[0] != "sk" or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


@dataclass(frozen=True)
class Principal:
    role: str
    key_id: str | None = None
    user_id: str | None = None
    email: str | None = None
    auth_disabled: bool = False


# A principal used when AUTH_ENABLED is false. Full access; clearly labelled.
SYNTHETIC_ADMIN = Principal(role="admin", email="auth-disabled", auth_disabled=True)
