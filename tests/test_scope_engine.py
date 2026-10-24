"""Tests for the Scope Engine — the most security-critical component.

Covers: in-scope lab target, out-of-scope deny, DNS-rebinding (name in scope but IP
out of scope), cloud-metadata hard-deny, explicit public authorization, and
multi-address names.
"""
from uuid import uuid4

from app.contracts.enums import ScopeKind
from app.engine.scope import AuthorizedScope, ScopeEngine


def _lab_scope(value="juiceshop"):
    return AuthorizedScope(id=uuid4(), kind=ScopeKind.LAB_ENV, value=value, is_lab_env=True)


def _resolver(mapping):
    return lambda host: mapping.get(host, [])


def test_lab_hostname_resolving_private_is_allowed():
    eng = ScopeEngine([_lab_scope("juiceshop")], resolver=_resolver({"juiceshop": ["172.20.0.5"]}))
    d = eng.authorize("http://juiceshop:3000")
    assert d.allowed and d.resolved_ip == "172.20.0.5"


def test_unknown_target_is_denied():
    eng = ScopeEngine([_lab_scope()], resolver=_resolver({"evil.example": ["93.184.216.34"]}))
    d = eng.authorize("http://evil.example")
    assert not d.allowed and "no_authorized_scope" in d.reason


def test_dns_rebinding_name_in_scope_ip_out_of_scope_is_denied():
    # The lab hostname is authorized, but it resolves to a PUBLIC ip -> deny.
    eng = ScopeEngine([_lab_scope("juiceshop")], resolver=_resolver({"juiceshop": ["93.184.216.34"]}))
    d = eng.authorize("http://juiceshop")
    assert not d.allowed


def test_cloud_metadata_is_hard_denied_even_if_named_in_scope():
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.DOMAIN, value="meta.lab", is_lab_env=True)]
    eng = ScopeEngine(scopes, resolver=_resolver({"meta.lab": ["169.254.169.254"]}))
    d = eng.authorize("http://meta.lab")
    assert not d.allowed and "hard_denied" in d.reason


def test_explicit_public_ip_authorization_is_allowed():
    # Public targets are allowed ONLY when explicitly authorized by ip/cidr.
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.IP, value="93.184.216.34")]
    eng = ScopeEngine(scopes, resolver=_resolver({"owned.example": ["93.184.216.34"]}))
    d = eng.authorize("http://owned.example")
    assert d.allowed


def test_public_ip_without_explicit_scope_is_denied():
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.DOMAIN, value="owned.example", is_lab_env=False)]
    eng = ScopeEngine(scopes, resolver=_resolver({"owned.example": ["93.184.216.34"]}))
    d = eng.authorize("http://owned.example")
    # Name matches a domain scope, but no explicit ip/cidr covers the public IP -> deny.
    assert not d.allowed


def test_cidr_scope_allows_contained_ip():
    scopes = [AuthorizedScope(id=uuid4(), kind=ScopeKind.CIDR, value="172.20.0.0/16")]
    eng = ScopeEngine(scopes, resolver=_resolver({"host.lab": ["172.20.5.9"]}))
    assert eng.authorize("http://host.lab").allowed


def test_literal_private_ip_requires_scope():
    eng = ScopeEngine([_lab_scope()], resolver=_resolver({}))
    assert not eng.authorize("10.0.0.5").allowed


def test_multi_address_all_must_be_in_scope():
    # One address private+in-lab, the other public -> deny the whole target.
    scopes = [_lab_scope("multi.lab")]
    eng = ScopeEngine(scopes, resolver=_resolver({"multi.lab": ["172.20.0.5", "93.184.216.34"]}))
    assert not eng.authorize("http://multi.lab").allowed


def test_dns_failure_is_denied():
    def boom(host):
        raise OSError("nxdomain")

    eng = ScopeEngine([_lab_scope()], resolver=boom)
    d = eng.authorize("http://nope.lab")
    assert not d.allowed and "dns_resolution_failed" in d.reason
