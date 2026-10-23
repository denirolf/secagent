"""Scope Engine — the authorization choke point.

Nothing reaches a target unless this engine allows it. The policy is deliberately
conservative and enforced here in deterministic code, never left to an agent:

A target is ALLOWED only if BOTH hold:
  (a) its hostname or IP matches at least one of the project's authorized scope
      entries, AND
  (b) its *freshly resolved* IP is authorized — either covered by an ip/cidr/
      lab_env scope, or the matched scope is a lab_env (which authorizes private
      lab addresses).

Hard structural denials that no scope can override:
  - link-local / cloud-metadata addresses (169.254.0.0/16, incl. 169.254.169.254)
  - unspecified / multicast / reserved addresses

DNS is resolved at check time, so a name that is in scope but resolves to an
out-of-scope IP (DNS-rebinding style) is denied. Redirects are re-authorized from
scratch by calling `authorize()` again on the new location, so they cannot widen scope.
Public destinations are never authorized implicitly: a public IP is allowed only when an
explicit ip/cidr scope covers it.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse
from uuid import UUID

from app.contracts.enums import ScopeKind
from app.contracts.messages import ScopeDecision

# A resolver maps a hostname to a list of IP strings. Injectable for testing.
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return list({info[4][0] for info in infos})


@dataclass(frozen=True)
class AuthorizedScope:
    id: UUID
    kind: ScopeKind
    value: str  # ip, cidr, domain, or lab hostname/cidr
    is_lab_env: bool = False


def _extract_host(target: str) -> str:
    """Pull a bare hostname/ip out of a target that may be a URL or host:port."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname or ""
    # host:port (but not an IPv6 literal)
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def _as_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_hard_denied(ip: ipaddress._BaseAddress) -> bool:
    """Addresses no authorized scope may ever permit."""
    return (
        ip.is_link_local  # 169.254.0.0/16 incl. cloud metadata endpoint
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _host_matches_domain(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


class ScopeEngine:
    def __init__(
        self,
        scopes: list[AuthorizedScope],
        resolver: Resolver | None = None,
    ) -> None:
        self._scopes = scopes
        self._resolver = resolver or _default_resolver

    def authorize(self, target: str) -> ScopeDecision:
        host = _extract_host(target)
        if not host:
            return ScopeDecision(allowed=False, target=target, reason="empty_or_unparseable_target")

        # Resolve now. If the target is already a literal IP, use it directly.
        literal = _as_ip(host)
        if literal is not None:
            resolved_ips = [str(literal)]
        else:
            try:
                resolved_ips = self._resolver(host)
            except Exception as exc:  # noqa: BLE001 - any resolution failure is a deny
                return ScopeDecision(
                    allowed=False, target=target, reason=f"dns_resolution_failed: {exc}"
                )
            if not resolved_ips:
                return ScopeDecision(allowed=False, target=target, reason="no_dns_records")

        # Evaluate EVERY resolved IP. If any one is hard-denied or unauthorized, deny the
        # whole target (a name that resolves to several addresses must have them all in scope).
        matched_scope_id: UUID | None = None
        matched_is_lab = False
        chosen_ip: str | None = None
        for ip_str in resolved_ips:
            ip = _as_ip(ip_str)
            if ip is None:
                return ScopeDecision(allowed=False, target=target, reason=f"bad_resolved_ip:{ip_str}")
            if _is_hard_denied(ip):
                return ScopeDecision(
                    allowed=False,
                    target=target,
                    resolved_ip=ip_str,
                    reason=f"hard_denied_address:{ip_str}",
                )
            scope = self._match_scope(host, ip)
            if scope is None:
                return ScopeDecision(
                    allowed=False,
                    target=target,
                    resolved_ip=ip_str,
                    reason=f"no_authorized_scope_covers:{ip_str}",
                )
            matched_scope_id = scope.id
            matched_is_lab = scope.is_lab_env or scope.kind == ScopeKind.LAB_ENV
            chosen_ip = ip_str

        return ScopeDecision(
            allowed=True,
            target=target,
            resolved_ip=chosen_ip,
            matched_scope_id=matched_scope_id,
            matched_is_lab=matched_is_lab,
            reason="authorized",
        )

    def _match_scope(
        self, host: str, ip: ipaddress._BaseAddress
    ) -> AuthorizedScope | None:
        """Return a scope that authorizes this (host, resolved ip), honoring policy (b)."""
        ip_is_private = ip.is_private or ip.is_loopback

        for scope in self._scopes:
            if scope.kind == ScopeKind.IP:
                if _as_ip(scope.value) == ip:
                    return scope  # explicit IP authorization (public or private)
            elif scope.kind == ScopeKind.CIDR:
                try:
                    if ip in ipaddress.ip_network(scope.value, strict=False):
                        return scope
                except ValueError:
                    continue
            elif scope.kind == ScopeKind.DOMAIN:
                if _host_matches_domain(host, scope.value):
                    # Name matches, but the resolved IP must still be authorized:
                    # a lab domain may resolve to a private lab IP; otherwise the
                    # IP must be covered by an explicit ip/cidr scope.
                    if scope.is_lab_env and ip_is_private:
                        return scope
                    if self._ip_covered_by_explicit(ip):
                        return scope
            elif scope.kind == ScopeKind.LAB_ENV:
                # lab_env value is either a hostname or a CIDR of the isolated lab.
                net = None
                try:
                    net = ipaddress.ip_network(scope.value, strict=False)
                except ValueError:
                    net = None
                if net is not None:
                    if ip in net:
                        return scope
                else:
                    # hostname lab target: name must match and IP must be private
                    if _host_matches_domain(host, scope.value) and ip_is_private:
                        return scope
        return None

    def _ip_covered_by_explicit(self, ip: ipaddress._BaseAddress) -> bool:
        for scope in self._scopes:
            if scope.kind == ScopeKind.IP and _as_ip(scope.value) == ip:
                return True
            if scope.kind == ScopeKind.CIDR:
                try:
                    if ip in ipaddress.ip_network(scope.value, strict=False):
                        return True
                except ValueError:
                    continue
        return False
