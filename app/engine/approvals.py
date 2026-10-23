"""Approval Engine — human gate for high-impact operations.

Whether an operation needs approval is decided by the operation's own
`requires_approval` flag, the autonomy level, and whether the target is a lab
environment. The autonomy level can only ever *reduce* friction for low-risk,
in-scope operations; it can never bypass the Scope Engine or sandbox limits, and it can
never auto-approve an operation whose spec hard-requires approval outside a lab.
"""
from __future__ import annotations

from app.contracts.enums import AutonomyLevel, OperationClass


def approval_required(
    *,
    requires_approval: bool,
    operation_class: OperationClass,
    autonomy_level: AutonomyLevel,
    target_is_lab: bool,
) -> bool:
    """Return True if a human must approve before this operation runs.

    Level 1 (Assisted):        every active operation needs approval.
    Level 2 (Semi-autonomous): passive auto; active needs approval.
    Level 3 (Autonomous Lab):  active ops auto-approved ONLY against lab targets.
    A spec-level `requires_approval` always applies outside a lab environment.
    """
    if operation_class == OperationClass.PASSIVE:
        return False  # passive observation never needs approval

    # From here on the operation is active_authorized.
    if autonomy_level == AutonomyLevel.ASSISTED:
        return True
    if autonomy_level == AutonomyLevel.SEMI_AUTONOMOUS:
        return True
    # AUTONOMOUS_LAB
    if not target_is_lab:
        return True  # autonomous auto-run is permitted only inside the lab
    # Inside the lab: a spec that hard-requires approval still does, unless it is lab-run.
    # Level-3 lab autonomy is what this level is for, so auto-approve in-lab active ops.
    return False
