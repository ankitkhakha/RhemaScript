"""Trusted approval issuer boundary; no local credential minting.

An issuer implementation must authenticate the human operator independently,
derive actor identity from that authenticated session (never from caller input),
and return externally signed Ed25519 credentials. RhemaScript stores only
public verification keys and verifies the returned scope before any action.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Protocol, runtime_checkable
import re

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


@dataclass(frozen=True)
class ApprovalScope:
    action: str
    project_id: str
    project_version: str
    request_id: str
    artifact_id: str | None = None
    artifact_version: str | None = None
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = None

    def __post_init__(self) -> None:
        for field in ("action", "project_id", "project_version", "request_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError(f"{field} must be a valid non-empty identifier")
        values = (self.artifact_id, self.artifact_version, self.artifact_sha256, self.artifact_size_bytes)
        if any(value is not None for value in values):
            if (not isinstance(self.artifact_id, str) or not _ID.fullmatch(self.artifact_id)
                    or not isinstance(self.artifact_version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.artifact_version)
                    or not isinstance(self.artifact_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256)
                    or not isinstance(self.artifact_size_bytes, int)
                    or isinstance(self.artifact_size_bytes, bool) or self.artifact_size_bytes <= 0):
                raise ValueError("artifact-bound approval requires artifact ID/version/SHA-256/size")


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


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """Normalized result produced only after an identity adapter validates its IdP response."""

    identity_provider_id: str
    subject_id: str
    authn_context: str
    authenticated_at: datetime
    identity_session_id: str

    def __post_init__(self) -> None:
        for field in ("identity_provider_id", "subject_id", "authn_context", "identity_session_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError(f"{field} must be a valid issuer-controlled identifier")
        if (not isinstance(self.authenticated_at, datetime)
                or self.authenticated_at.tzinfo is None
                or self.authenticated_at.utcoffset() is None):
            raise ValueError("authenticated_at must be timezone-aware")


@dataclass(frozen=True)
class DirectoryIdentity:
    """Authoritative directory result; never construct from request/client claims."""

    subject_id: str
    actor_id: str
    active: bool
    roles: frozenset[str]
    project_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, str) or not _ID.fullmatch(self.subject_id):
            raise ValueError("directory subject_id is invalid")
        if not isinstance(self.actor_id, str) or not _ID.fullmatch(self.actor_id):
            raise ValueError("directory actor_id is invalid")
        if not isinstance(self.active, bool):
            raise ValueError("directory active status must be boolean")
        if (not isinstance(self.roles, frozenset) or not self.roles
                or any(not isinstance(role, str) or not _ID.fullmatch(role) for role in self.roles)):
            raise ValueError("directory roles must be a non-empty immutable identifier set")
        if (not isinstance(self.project_ids, frozenset)
                or any(not isinstance(project, str) or not _ID.fullmatch(project) for project in self.project_ids)):
            raise ValueError("directory project assignments must be an immutable identifier set")


@dataclass(frozen=True)
class ApprovalPolicyDecision:
    """Immutable policy result from the issuer's trusted policy decision point."""

    allowed: bool
    identity_policy_version: str
    actor_role: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("policy allowed decision must be boolean")
        if (not isinstance(self.identity_policy_version, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.identity_policy_version)):
            raise ValueError("identity policy version is invalid")
        if self.allowed and (not isinstance(self.actor_role, str) or not _ID.fullmatch(self.actor_role)):
            raise ValueError("an allowed policy decision requires a valid actor role")
        if not self.allowed and self.actor_role is not None:
            raise ValueError("a denied policy decision cannot grant an actor role")


@runtime_checkable
class IdentityProtocolAdapter(Protocol):
    """Perform direct human authentication and validate the full IdP protocol response."""

    def authenticate(self, scope: ApprovalScope) -> AuthenticatedIdentity:
        """Return normalized, cryptographically validated identity facts or fail closed."""
        ...


@runtime_checkable
class SubjectDirectoryAdapter(Protocol):
    """Resolve a validated issuer-scoped subject against an authoritative directory."""

    def resolve_subject(self, subject_id: str) -> DirectoryIdentity:
        """Return current active status, role memberships and project assignments."""
        ...


@runtime_checkable
class ApprovalPolicyEngine(Protocol):
    """Apply owner-approved action, project, assurance and separation-of-duties policy."""

    def authorize(
        self, scope: ApprovalScope, identity: AuthenticatedIdentity,
        directory_identity: DirectoryIdentity,
    ) -> ApprovalPolicyDecision:
        """Return a versioned allow/deny decision; missing policy must deny."""
        ...


@runtime_checkable
class SigningKeyProvider(Protocol):
    """Sign canonical credentials using protected key custody without exporting private keys."""

    def sign(self, canonical_payload: bytes) -> tuple[str, str]:
        """Return (key_id, signature_hex); never return or expose private key bytes."""
        ...


@runtime_checkable
class IssuanceLedger(Protocol):
    """Enforce one-time issuance and separation of human subjects for a request."""

    def reserve(
        self, approval_id: str, nonce: str, scope: ApprovalScope, subject_id: str,
    ) -> bool:
        """Atomically reserve the approval and reject replay or same-subject dual approval."""
        ...


@runtime_checkable
class IssuerAuditSink(Protocol):
    """Persist issuance and denial evidence independently of the relying application."""

    def record(self, event: Mapping[str, object]) -> None:
        """Persist an audit event or raise; issuer must fail closed if required audit fails."""
        ...


def required_publish_scopes(
    *, project_id: str, project_version: str, request_id: str,
    artifact_binding: Mapping[str, object],
) -> tuple[ApprovalScope, ApprovalScope]:
    """Describe two approvals bound to the exact final-film artifact bytes."""
    if not isinstance(artifact_binding, Mapping) or set(artifact_binding) != {
        "artifact_id", "artifact_version", "sha256", "size_bytes"
    }:
        raise ValueError("exact final-film artifact binding is required")
    shared = {
        "project_id": project_id,
        "project_version": project_version,
        "request_id": request_id,
        "artifact_id": artifact_binding["artifact_id"],
        "artifact_version": artifact_binding["artifact_version"],
        "artifact_sha256": artifact_binding["sha256"],
        "artifact_size_bytes": artifact_binding["size_bytes"],
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
    artifact_binding: Mapping[str, object],
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
        artifact_binding=artifact_binding,
    )
    credentials = []
    for scope in scopes:
        credential = source.request_approval(scope)
        if not isinstance(credential, Mapping):
            raise TypeError("approval issuer must return a credential object")
        credentials.append(dict(credential))
    return credentials[0], credentials[1]
