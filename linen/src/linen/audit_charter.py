"""Stable audit objective shared by the API, UI contract, and workers."""

from __future__ import annotations

from typing import Literal


AUDIT_CHARTER_VERSION = "security-audit-charter/v1"

AUDIT_CHARTER = (
    f"[{AUDIT_CHARTER_VERSION}] Complete a source-grounded security audit of the selected "
    "target. Discover and validate attacker-controllable behavior that causes a "
    "security-significant change: crossing an acknowledged trust boundary; violating "
    "authorization or another documented security invariant; or compromising "
    "confidentiality, integrity, or availability. A reportable finding must show attacker "
    "control, reachability, the violated invariant or boundary, and concrete impact. Treat "
    "documented intended behavior as excluded only when evidence shows that it grants no "
    "additional attacker capability under the accepted threat model; record ambiguity instead "
    "of guessing. Completion means the selected audit mode's "
    "evidence and coverage gates are satisfied, not merely that one candidate was found."
)


def project_goal(
    audit_mode: Literal["none", "hypothesis", "scope"],
    requested_goal: str | None,
) -> str:
    """Return the authoritative goal persisted in the blackboard.

    Audit projects always use the versioned charter. General blackboard projects retain
    their caller-provided goal so Linen remains useful outside source-code auditing.
    """
    if audit_mode != "none":
        return AUDIT_CHARTER
    if requested_goal is None or not requested_goal.strip():
        raise ValueError("goal is required for a general project")
    return requested_goal.strip()
