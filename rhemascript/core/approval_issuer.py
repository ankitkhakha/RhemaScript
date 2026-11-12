"""Trusted approval issuer boundary; no local credential minting.

An issuer implementation must authenticate the human operator independently,
derive actor identity from that authenticated session (never from caller input),
and return externally signed Ed25519 credentials. RhemaScript stores only
public verification keys and verifies the returned scope before any action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable


@dataclass(frozen=True)
class ApprovalScope:
    action: str
    project_id: str
    project_version: str
    request_id: str

    def __post_init__(self) -> None:
        for field in ("action", "project_id", "project_version", "request_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} is required")


@runtime_checkable
class ApprovalCredentialSource(Protocol):
    """Obtain one issuer-signed approval after the issuer authenticates a human.

    The caller deliberately supplies no actor_id, password, token, or claimed
    identity. The issuer must derive actor identity from its own authenticated
    session and enforce its own policy before returning the signed credential.
    """

    def request_approval(self, scope: ApprovalScope) -> Mapping[str, object]:
        """Return one signed credential bound to the exact supplied scope."""
        ...


def required_publish_scopes(
    *, project_id: str, project_version: str, request_id: str,
) -> tuple[ApprovalScope, ApprovalScope]:
    """Describe the two distinct approvals required for a YouTube write."""
    shared = {
        "project_id": project_id,
        "project_version": project_version,
        "request_id": request_id,
    }
    return (
        ApprovalScope(action="FINAL_ACCEPTANCE", **shared),
        ApprovalScope(action="PUBLISH", **shared),
    )
