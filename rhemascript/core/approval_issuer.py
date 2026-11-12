"""Trusted approval issuer boundary; no local credential minting.

An issuer implementation must authenticate the human operator independently,
derive actor identity from that authenticated session (never from caller input),
and return externally signed Ed25519 credentials. RhemaScript stores only
public verification keys and verifies the returned scope before any action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable
import re

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


@dataclass(frozen=True)
class ApprovalScope:
    action: str
    project_id: str
    project_version: str
    request_id: str

    def __post_init__(self) -> None:
        for field in ("action", "project_id", "project_version", "request_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError(f"{field} must be a valid non-empty identifier")


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


def request_publish_approval_credentials(
    source: ApprovalCredentialSource,
    *,
    project_id: str,
    project_version: str,
    request_id: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Request final-acceptance and publish credentials from a trusted issuer.

    The issuer independently authenticates each human actor. No actor identity
    is accepted from this caller. Signature, scope and replay checks remain the
    responsibility of ApprovalVerifier at the provider boundary.
    """
    if not isinstance(source, ApprovalCredentialSource):
        raise TypeError("a trusted ApprovalCredentialSource is required")
    scopes = required_publish_scopes(
        project_id=project_id,
        project_version=project_version,
        request_id=request_id,
    )
    credentials = []
    for scope in scopes:
        credential = source.request_approval(scope)
        if not isinstance(credential, Mapping):
            raise TypeError("approval issuer must return a credential object")
        credentials.append(dict(credential))
    return credentials[0], credentials[1]
