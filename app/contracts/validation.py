"""Phase 2 contracts: validation plans and outcomes.

The Exploit Research Agent (Agent 4) produces a `ValidationPlan` per suspected finding:
the mechanism, preconditions, impact, lab reproduction steps, and a set of **bounded,
safe, lab-only checks**. It never executes anything against a target.

The Exploit Validation Agent (Agent 5) runs those bounded checks **only inside an
isolated lab** and produces a `ValidationOutcome`. A finding is elevated from
`suspected` to `lab_confirmed` only when a check reproduces it in the lab.

Bounded checks are deliberately limited to passive, non-destructive observations
(re-reading a response, confirming a status code). There is no primitive here for
destructive exploitation, lateral movement, or data exfiltration.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.contracts.enums import FindingStatus
from app.contracts.messages import Evidence


class ValidationCheck(BaseModel):
    """A single safe, lab-only check the validation agent may run.

    kind:
      http_header_absent  - GET `path`, reproduced if `header` is absent.
      http_header_present - GET `path`, reproduced if `header` is present.
      http_status         - GET `path`, reproduced if status == `expected_status`.
    """

    kind: Literal["http_header_absent", "http_header_present", "http_status"]
    path: str = "/"
    header: str | None = None
    expected_status: int | None = None


class ValidationPlan(BaseModel):
    finding_vuln_id: str
    asset: str
    mechanism: str
    preconditions: list[str] = Field(default_factory=list)
    impact: str
    lab_reproduction_steps: list[str] = Field(default_factory=list)
    bounded_checks: list[ValidationCheck] = Field(default_factory=list)
    # If a plan ever needs an active (non-passive) step, this forces a human gate.
    requires_approval: bool = False


class ValidationOutcome(BaseModel):
    finding_vuln_id: str
    asset: str
    environment: str = "lab"
    reproduced: bool
    new_status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)
    notes: str = ""
