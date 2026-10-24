"""Enumerations shared across contracts, the engine, and the DB layer.

These enums encode the platform's safety invariants as types:
- OperationClass separates passive observation from active (authorized) testing.
- FindingStatus keeps "a scanner said so" strictly distinct from "reproduced in a
  lab" and "validated in the authorized environment".
"""
from __future__ import annotations

from enum import Enum


class AgentId(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    VULN_ANALYSIS = "vuln_analysis"
    # Later phases (schemas reserve these; not wired in Phase 1):
    EXPLOIT_RESEARCH = "exploit_research"
    EXPLOIT_VALIDATION = "exploit_validation"
    AUTH_SECURITY = "auth_security"
    REASONING = "reasoning"
    REPORTING = "reporting"


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED_OUT_OF_SCOPE = "blocked_out_of_scope"


class OperationClass(str, Enum):
    """How intrusive an operation is. Drives approval requirements."""

    PASSIVE = "passive"  # OSINT, DNS, reading HTTP headers
    ACTIVE_AUTHORIZED = "active_authorized"  # port/web scan on an authorized target


class ScopeKind(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    LAB_ENV = "lab_env"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    """The three distinct states a finding can occupy. Never collapse these."""

    SUSPECTED = "suspected"  # a scanner reported it; NOT confirmed
    LAB_CONFIRMED = "lab_confirmed"  # reproduced in our isolated lab (Phase 2)
    CONFIRMED_AUTHORIZED = "confirmed_authorized"  # validated in authorized env + human sign-off


class ApprovalState(str, Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"


class AutonomyLevel(int, Enum):
    ASSISTED = 1  # every active test needs approval
    SEMI_AUTONOMOUS = 2  # passive auto; active needs approval
    AUTONOMOUS_LAB = 3  # bounded lab scenarios auto (lab targets only)
