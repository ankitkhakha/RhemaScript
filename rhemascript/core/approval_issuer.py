"""Trusted approval issuer boundary; no local credential minting.

An issuer implementation must authenticate the human operator independently,
derive actor identity from that authenticated session (never from caller input),
and return externally signed Ed25519 credentials. RhemaScript stores only
public verification keys and verifies the returned scope before any action.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol, runtime_checkable
import json
import re
import secrets

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_SCHEMA_V3 = "RhemaScript.ApprovalCredential.v3"
_HIGH_RISK_ACTIONS = frozenset({"FINAL_ACCEPTANCE", "PUBLISH"})
_ISSUABLE_ACTIONS = _HIGH_RISK_ACTIONS | frozenset({"FINDING_SUBMIT", "FINDING_RESEARCH", "FINDING_REPRODUCE"})


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
    identity_provider_id: str
    max_authentication_age_seconds: int
    clock_skew_seconds: int
    actor_role: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("policy allowed decision must be boolean")
        if (not isinstance(self.identity_policy_version, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.identity_policy_version)):
            raise ValueError("identity policy version is invalid")
        if not isinstance(self.identity_provider_id, str) or not _ID.fullmatch(self.identity_provider_id):
            raise ValueError("identity provider ID is invalid")
        if (not isinstance(self.max_authentication_age_seconds, int)
                or isinstance(self.max_authentication_age_seconds, bool)
                or not 1 <= self.max_authentication_age_seconds <= 3600):
            raise ValueError("maximum authentication age must be between 1 and 3600 seconds")
        if (not isinstance(self.clock_skew_seconds, int)
                or isinstance(self.clock_skew_seconds, bool)
                or not 0 <= self.clock_skew_seconds <= 120):
            raise ValueError("clock skew must be between zero and 120 seconds")
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

    def active_key_id(self) -> str:
        """Return the active key identifier from the protected key registry."""
        ...

    def sign(self, key_id: str, canonical_payload: bytes) -> str:
        """Return signature hex for the named key; never export private key bytes."""
        ...


@runtime_checkable
class IssuanceLedger(Protocol):
    """Enforce one-time issuance and separation of human subjects for a request."""

    def reserve(
        self, approval_id: str, nonce: str, scope: ApprovalScope,
        subject_id: str, identity_session_id: str,
    ) -> bool:
        """Atomically reserve and reject replay, same-subject or same-session dual approval."""
        ...


@runtime_checkable
class IssuerAuditSink(Protocol):
    """Persist issuance and denial evidence independently of the relying application."""

    def record(self, event: Mapping[str, object]) -> None:
        """Persist an audit event or raise; issuer must fail closed if required audit fails."""
        ...


class ApprovalIssuerError(PermissionError):
    """A human approval could not be issued under the trusted issuer policy."""


class TrustedApprovalIssuer:
    """Vendor-neutral orchestration for V3 approvals; concrete adapters are owner-supplied.

    This class contains no IdP SDK, directory client, deployment settings or
    signing-key material. It can be exercised with deterministic test doubles;
    production use requires separately approved and independently reviewed
    adapters for every dependency.
    """

    def __init__(
        self,
        *,
        issuer_id: str,
        identity_adapter: IdentityProtocolAdapter,
        directory_adapter: SubjectDirectoryAdapter,
        policy_engine: ApprovalPolicyEngine,
        signing_key_provider: SigningKeyProvider,
        issuance_ledger: IssuanceLedger,
        audit_sink: IssuerAuditSink,
        clock=None,
        max_credential_lifetime: timedelta = timedelta(minutes=5),
    ) -> None:
        if not isinstance(issuer_id, str) or not _ID.fullmatch(issuer_id):
            raise ValueError("trusted issuer ID is required")
        for name, value, protocol in (
            ("identity_adapter", identity_adapter, IdentityProtocolAdapter),
            ("directory_adapter", directory_adapter, SubjectDirectoryAdapter),
            ("policy_engine", policy_engine, ApprovalPolicyEngine),
            ("signing_key_provider", signing_key_provider, SigningKeyProvider),
            ("issuance_ledger", issuance_ledger, IssuanceLedger),
            ("audit_sink", audit_sink, IssuerAuditSink),
        ):
            if not isinstance(value, protocol):
                raise TypeError(f"{name} does not implement its trusted issuer contract")
        if (not isinstance(max_credential_lifetime, timedelta)
                or max_credential_lifetime <= timedelta(0)
                or max_credential_lifetime > timedelta(minutes=10)):
            raise ValueError("credential lifetime must be positive and no greater than ten minutes")
        self.issuer_id = issuer_id
        self._identity = identity_adapter
        self._directory = directory_adapter
        self._policy = policy_engine
        self._signer = signing_key_provider
        self._ledger = issuance_ledger
        self._audit = audit_sink
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_lifetime = max_credential_lifetime

    @staticmethod
    def _canonical(payload: Mapping[str, object]) -> bytes:
        return json.dumps(
            dict(payload), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    def _audit_denial(self, scope: ApprovalScope, reason: str, *, subject_id=None) -> None:
        self._audit.record({
            "event": "approval_denied",
            "issuer": self.issuer_id,
            "action": scope.action,
            "project_id": scope.project_id,
            "project_version": scope.project_version,
            "request_id": scope.request_id,
            "subject_id": subject_id,
            "reason_code": reason,
        })

    def request_approval(self, scope: ApprovalScope) -> Mapping[str, object]:
        if not isinstance(scope, ApprovalScope):
            raise TypeError("approval scope must be an ApprovalScope")
        if scope.action not in _ISSUABLE_ACTIONS:
            self._audit_denial(scope, "unsupported_action")
            raise ApprovalIssuerError("trusted issuer action is not enabled by the candidate policy boundary")
        if (scope.artifact_id is None or scope.artifact_version is None
                or scope.artifact_sha256 is None or scope.artifact_size_bytes is None):
            self._audit_denial(scope, "exact_artifact_binding_required")
            raise ApprovalIssuerError("V3 high-risk approval requires exact final-artifact binding")

        identity = None
        reserved = False
        try:
            identity = self._identity.authenticate(scope)
            if not isinstance(identity, AuthenticatedIdentity):
                raise ApprovalIssuerError("identity adapter returned an invalid authentication result")
            directory = self._directory.resolve_subject(identity.subject_id)
            if (not isinstance(directory, DirectoryIdentity)
                    or directory.subject_id != identity.subject_id):
                raise ApprovalIssuerError("authoritative directory subject resolution failed")
            if not directory.active:
                raise ApprovalIssuerError("approver account is inactive")
            if scope.project_id not in directory.project_ids:
                raise ApprovalIssuerError("approver is not assigned to this project")
            decision = self._policy.authorize(scope, identity, directory)
            if not isinstance(decision, ApprovalPolicyDecision) or not decision.allowed:
                raise ApprovalIssuerError("approval policy denied the requested action")
            if (decision.identity_provider_id != identity.identity_provider_id
                    or decision.actor_role not in directory.roles):
                raise ApprovalIssuerError("identity provider or directory role does not match policy")
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise ApprovalIssuerError("issuer clock must return a timezone-aware datetime")
            now = now.astimezone(timezone.utc)
            authenticated_at = identity.authenticated_at.astimezone(timezone.utc)
            auth_age = (now - authenticated_at).total_seconds()
            if (auth_age < -decision.clock_skew_seconds
                    or auth_age > decision.max_authentication_age_seconds):
                raise ApprovalIssuerError("human authentication is stale or future-dated")
            approval_id = secrets.token_hex(16)
            nonce = secrets.token_hex(16)
            key_id = self._signer.active_key_id()
            if not isinstance(key_id, str) or not _ID.fullmatch(key_id):
                raise ApprovalIssuerError("signing service returned an invalid key identifier")
            payload = {
                "schema": _SCHEMA_V3,
                "approval_id": approval_id,
                "issuer": self.issuer_id,
                "actor_id": directory.actor_id,
                "action": scope.action,
                "project_id": scope.project_id,
                "project_version": scope.project_version,
                "request_id": scope.request_id,
                "issued_at": now.isoformat(),
                "expires_at": (now + self._max_lifetime).isoformat(),
                "nonce": nonce,
                "key_id": key_id,
                "artifact_id": scope.artifact_id,
                "artifact_version": scope.artifact_version,
                "artifact_sha256": scope.artifact_sha256,
                "artifact_size_bytes": scope.artifact_size_bytes,
                "subject_id": identity.subject_id,
                "actor_role": decision.actor_role,
                "authn_context": identity.authn_context,
                "authenticated_at": authenticated_at.isoformat(),
                "identity_session_id": identity.identity_session_id,
                "identity_policy_version": decision.identity_policy_version,
                "identity_provider_id": identity.identity_provider_id,
            }
            signature = self._signer.sign(key_id, self._canonical(payload))
            if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
                raise ApprovalIssuerError("signing service returned an invalid signature")
            credential = {**payload, "signature": signature}
            if self._ledger.reserve(approval_id, nonce, scope, identity.subject_id, identity.identity_session_id) is not True:
                raise ApprovalIssuerError("approval is replayed or violates subject separation")
            reserved = True
            self._audit.record({
                "event": "approval_issued",
                "issuer": self.issuer_id,
                "approval_id": approval_id,
                "action": scope.action,
                "project_id": scope.project_id,
                "project_version": scope.project_version,
                "request_id": scope.request_id,
                "subject_id": identity.subject_id,
                "actor_id": directory.actor_id,
                "identity_provider_id": identity.identity_provider_id,
                "identity_policy_version": decision.identity_policy_version,
                "key_id": key_id,
                "artifact_sha256": scope.artifact_sha256,
            })
            return credential
        except Exception as exc:
            if not reserved:
                try:
                    self._audit_denial(
                        scope,
                        "issuer_dependency_or_policy_failure",
                        subject_id=identity.subject_id if isinstance(identity, AuthenticatedIdentity) else None,
                    )
                except Exception:
                    raise ApprovalIssuerError("approval denied and audit sink unavailable") from None
            if isinstance(exc, ApprovalIssuerError):
                raise
            raise ApprovalIssuerError("approval issuer dependency failed; request denied") from None


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
