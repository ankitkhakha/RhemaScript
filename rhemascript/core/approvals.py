"""Verification-only, request-bound approval credentials.

The issuer and signing keys live outside RhemaScript. This module never
creates approvals. The consume_many_once callback must atomically reject
revoked or previously consumed IDs/nonces and persist every approval in a
batch, or persist none of them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json
import re
import threading
import weakref
from typing import Callable, Mapping, Sequence


class ApprovalError(PermissionError):
    """An approval credential is missing, invalid, expired, revoked, or replayed."""


_FIELDS_V1 = {
    "schema", "approval_id", "issuer", "actor_id", "action", "project_id",
    "project_version", "request_id", "issued_at", "expires_at", "nonce",
    "key_id", "signature",
}
_ARTIFACT_FIELDS = {"artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes"}
_FIELDS_V2 = _FIELDS_V1 | _ARTIFACT_FIELDS
_IDENTITY_FIELDS = {"subject_id", "actor_role", "authn_context", "authenticated_at", "identity_session_id", "identity_policy_version", "identity_provider_id"}
_FIELDS_V3 = _FIELDS_V2 | _IDENTITY_FIELDS
_SCHEMA_V1 = "RhemaScript.ApprovalCredential.v1"
_SCHEMA_V2 = "RhemaScript.ApprovalCredential.v2"
_SCHEMA_V3 = "RhemaScript.ApprovalCredential.v3"
_HIGH_RISK_ACTIONS = {"FINAL_ACCEPTANCE", "PUBLISH"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SIGNATURE_HEX = re.compile(r"^[0-9a-f]{128}$")
_VERIFIED_APPROVAL_TOKEN = object()
_VERIFIED_APPROVAL_LOCK = threading.Lock()
_VERIFIED_APPROVALS: weakref.WeakValueDictionary[int, "VerifiedApproval"] = weakref.WeakValueDictionary()



@dataclass(frozen=True)
class VerifiedApproval:
    approval_id: str
    issuer: str
    actor_id: str
    action: str
    project_id: str
    project_version: str
    request_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    artifact_id: str | None = None
    artifact_version: str | None = None
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = None
    subject_id: str | None = None
    actor_role: str | None = None
    authn_context: str | None = None
    authenticated_at: datetime | None = None
    identity_session_id: str | None = None
    identity_policy_version: str | None = None
    identity_provider_id: str | None = None
    credential_schema: str | None = None
    signature: str | None = field(default=None, repr=False, compare=False)
    _verification_token: object | None = field(default=None, repr=False, compare=False)


def is_verified_approval(value: object) -> bool:
    """Accept only the exact in-process object produced by ApprovalVerifier."""
    if not isinstance(value, VerifiedApproval) or value._verification_token is not _VERIFIED_APPROVAL_TOKEN:
        return False
    with _VERIFIED_APPROVAL_LOCK:
        return _VERIFIED_APPROVALS.get(id(value)) is value


class ApprovalVerifier:
    """Verify externally signed approvals and consume all required records atomically."""

    def __init__(
        self,
        *,
        issuer: str,
        verification_keys: Mapping[str, bytes],
        consume_many_once: Callable[[tuple[VerifiedApproval, ...]], bool],
        clock: Callable[[], datetime] | None = None,
        max_lifetime: timedelta = timedelta(minutes=10),
        clock_skew: timedelta = timedelta(seconds=30),
        identity_policies: Mapping[str, Mapping[str, object]] | None = None,
    ) -> None:
        if not isinstance(issuer, str) or not _ID.fullmatch(issuer):
            raise ValueError("trusted issuer is required")
        if not verification_keys:
            raise ValueError("at least one verification key is required")
        if any(not isinstance(k, str) or not _ID.fullmatch(k)
               or not isinstance(v, bytes) or len(v) != 32
               for k, v in verification_keys.items()):
            raise ValueError("Ed25519 verification keys require non-empty IDs and exactly 32 public-key bytes")
        if not callable(consume_many_once):
            raise ValueError("an atomic consume_many_once callback is required")
        if (not isinstance(max_lifetime, timedelta)
                or max_lifetime <= timedelta(0) or max_lifetime > timedelta(hours=1)):
            raise ValueError("max_lifetime must be positive and no greater than one hour")
        if (not isinstance(clock_skew, timedelta)
                or clock_skew < timedelta(0) or clock_skew > timedelta(minutes=2)):
            raise ValueError("clock_skew must be between zero and two minutes")
        self.issuer = issuer
        self._keys = dict(verification_keys)
        self._consume_many_once = consume_many_once
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_lifetime = max_lifetime
        self._clock_skew = clock_skew
        self._identity_policies = dict(identity_policies or {})
        for version, policy in self._identity_policies.items():
            if (not isinstance(version, str) or not _VERSION.fullmatch(version)
                    or not isinstance(policy, Mapping)
                    or not isinstance(policy.get("provider_id"), str)
                    or not isinstance(policy.get("allowed_roles_by_action"), Mapping)
                    or not isinstance(policy.get("allowed_authn_contexts"), (tuple, list, set))
                    or not isinstance(policy.get("max_authentication_age_seconds"), int)
                    or isinstance(policy.get("max_authentication_age_seconds"), bool)
                    or not 1 <= policy["max_authentication_age_seconds"] <= 3600):
                raise ValueError("identity policy registry contains an invalid policy")

    @staticmethod
    def _canonical(payload: dict) -> bytes:
        unsigned = {key: value for key, value in payload.items() if key != "signature"}
        return json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _timestamp(value: object, field: str) -> datetime:
        if not isinstance(value, str):
            raise ApprovalError(f"approval {field} is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ApprovalError(f"approval {field} is invalid") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ApprovalError(f"approval {field} must include a timezone")
        return parsed.astimezone(timezone.utc)

    def _verify_one(
        self,
        credential: object,
        *,
        action: str,
        project_id: str,
        project_version: str,
        request_id: str,
        artifact_binding: Mapping[str, object] | None = None,
    ) -> VerifiedApproval:
        if type(credential) is not dict:
            raise ApprovalError("approval credential has an invalid shape")
        token = dict(credential)
        schema = token.get("schema")
        expected_fields = (_FIELDS_V1 if schema == _SCHEMA_V1 else
                           _FIELDS_V2 if schema == _SCHEMA_V2 else
                           _FIELDS_V3 if schema == _SCHEMA_V3 else None)
        if expected_fields is None or set(token) != expected_fields:
            raise ApprovalError("approval credential has an invalid shape or unsupported schema")
        if artifact_binding is not None:
            if schema not in {_SCHEMA_V2, _SCHEMA_V3} or set(artifact_binding) != {
                "artifact_id", "artifact_version", "sha256", "size_bytes"
            }:
                raise ApprovalError("approval must bind the exact final artifact using credential schema v2")
            if (token.get("artifact_id") != artifact_binding.get("artifact_id")
                    or token.get("artifact_version") != artifact_binding.get("artifact_version")
                    or token.get("artifact_sha256") != artifact_binding.get("sha256")
                    or token.get("artifact_size_bytes") != artifact_binding.get("size_bytes")):
                raise ApprovalError("approval final-artifact binding does not match verified bytes")
        elif schema in {_SCHEMA_V2, _SCHEMA_V3}:
            raise ApprovalError("artifact-bound approval requires an exact artifact expectation")
        if schema in {_SCHEMA_V2, _SCHEMA_V3}:
            if (not isinstance(token.get("artifact_id"), str) or not _ID.fullmatch(token["artifact_id"])
                    or not isinstance(token.get("artifact_version"), str) or not _VERSION.fullmatch(token["artifact_version"])
                    or not isinstance(token.get("artifact_sha256"), str) or not _SHA256.fullmatch(token["artifact_sha256"])
                    or not isinstance(token.get("artifact_size_bytes"), int)
                    or isinstance(token.get("artifact_size_bytes"), bool)
                    or token["artifact_size_bytes"] <= 0):
                raise ApprovalError("approval final-artifact binding is invalid")
        for field in ("approval_id", "actor_id", "project_id", "project_version",
                      "request_id", "nonce", "key_id", "issuer", "action"):
            value = token.get(field)
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ApprovalError(f"approval {field} is invalid")
        if token["issuer"] != self.issuer:
            raise ApprovalError("approval issuer is not trusted")
        if token["action"] != action or token["project_id"] != project_id:
            raise ApprovalError("approval action or project scope does not match")
        if token["project_version"] != project_version or token["request_id"] != request_id:
            raise ApprovalError("approval version or request scope does not match")
        public_key = self._keys.get(token["key_id"])
        signature = token.get("signature")
        if (public_key is None or not isinstance(signature, str)
                or not _SIGNATURE_HEX.fullmatch(signature)):
            raise ApprovalError("approval signature is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                bytes.fromhex(signature), self._canonical(token)
            )
        except (InvalidSignature, ValueError, TypeError):
            raise ApprovalError("approval signature is invalid") from None

        identity = {}
        authenticated_at = None
        if token["action"] in _HIGH_RISK_ACTIONS and schema != _SCHEMA_V3:
            raise ApprovalError("high-risk approval requires credential schema v3 identity assurance")
        if schema == _SCHEMA_V3:
            for name in _IDENTITY_FIELDS:
                value = token.get(name)
                if not isinstance(value, str) or not _ID.fullmatch(value):
                    raise ApprovalError(f"approval identity claim {name} is invalid")
            policy = self._identity_policies.get(token["identity_policy_version"])
            if policy is None:
                raise ApprovalError("approval identity policy is not configured or trusted")
            if token["identity_provider_id"] != policy["provider_id"]:
                raise ApprovalError("approval identity provider does not match trusted policy")
            roles = policy["allowed_roles_by_action"].get(token["action"], ())
            if (not isinstance(roles, (tuple, list, set)) or token["actor_role"] not in roles
                    or token["authn_context"] not in policy["allowed_authn_contexts"]):
                raise ApprovalError("approval role or authentication context is not authorized")
            authenticated_at = self._timestamp(token["authenticated_at"], "authenticated_at")
            identity_age = (self._clock().astimezone(timezone.utc) - authenticated_at).total_seconds()
            if identity_age < -self._clock_skew.total_seconds() or identity_age > policy["max_authentication_age_seconds"]:
                raise ApprovalError("approval authentication is stale or future-dated")
            identity = {name: token[name] for name in _IDENTITY_FIELDS}
        issued_at = self._timestamp(token["issued_at"], "issued_at")
        expires_at = self._timestamp(token["expires_at"], "expires_at")
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ApprovalError("verifier clock must return a timezone-aware datetime")
        now = now.astimezone(timezone.utc)
        if issued_at > now + self._clock_skew:
            raise ApprovalError("approval was issued in the future")
        if expires_at <= now:
            raise ApprovalError("approval has expired")
        if expires_at <= issued_at or expires_at - issued_at > self._max_lifetime:
            raise ApprovalError("approval lifetime exceeds policy")
        if issued_at < now - self._max_lifetime - self._clock_skew:
            raise ApprovalError("approval is too old")
        verified = VerifiedApproval(
            approval_id=token["approval_id"], issuer=token["issuer"],
            actor_id=token["actor_id"], action=token["action"],
            project_id=token["project_id"], project_version=token["project_version"],
            request_id=token["request_id"], issued_at=issued_at,
            expires_at=expires_at, nonce=token["nonce"], key_id=token["key_id"],
            artifact_id=token.get("artifact_id"),
            artifact_version=token.get("artifact_version"),
            artifact_sha256=token.get("artifact_sha256"),
            artifact_size_bytes=token.get("artifact_size_bytes"),
            subject_id=identity.get("subject_id"),
            actor_role=identity.get("actor_role"),
            authn_context=identity.get("authn_context"),
            authenticated_at=authenticated_at,
            identity_session_id=identity.get("identity_session_id"),
            identity_policy_version=identity.get("identity_policy_version"),
            identity_provider_id=identity.get("identity_provider_id"),
            credential_schema=schema,
            signature=signature,
            _verification_token=_VERIFIED_APPROVAL_TOKEN,
        )
        with _VERIFIED_APPROVAL_LOCK:
            _VERIFIED_APPROVALS[id(verified)] = verified
        return verified


    def verify_persisted_record(self, record: Mapping[str, object]) -> dict[str, object]:
        """Re-verify the stored issuer signature without treating an expired credential as currently usable."""
        if not isinstance(record, Mapping):
            raise ApprovalError("persisted approval record must be an object")
        schema = record.get("credential_schema")
        if schema not in {_SCHEMA_V1, _SCHEMA_V2, _SCHEMA_V3}:
            raise ApprovalError("persisted approval credential schema is unsupported")
        required = {
            "approval_id", "issuer", "actor_id", "action", "project_id",
            "project_version", "request_id", "issued_at", "expires_at",
            "nonce", "key_id", "signature",
        }
        if not required.issubset(record):
            raise ApprovalError("persisted approval record is incomplete")
        payload = {key: record[key] for key in required if key != "signature"}
        payload["schema"] = schema
        if schema in {_SCHEMA_V2, _SCHEMA_V3}:
            artifact_fields = {
                "artifact_id": record.get("artifact_id"),
                "artifact_version": record.get("artifact_version"),
                "artifact_sha256": record.get("artifact_sha256"),
                "artifact_size_bytes": record.get("artifact_size_bytes"),
            }
            if any(value is None for value in artifact_fields.values()):
                raise ApprovalError("persisted V2 approval is missing artifact scope")
            payload.update(artifact_fields)
        elif any(record.get(key) is not None for key in (
            "artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes"
        )):
            raise ApprovalError("persisted V1 approval contains unexpected artifact scope")
        if schema == _SCHEMA_V3:
            identity_fields = {name: record.get(name) for name in _IDENTITY_FIELDS}
            if any(not isinstance(value, str) for value in identity_fields.values()):
                raise ApprovalError("persisted V3 approval is missing identity assurance claims")
            payload.update(identity_fields)
        elif any(record.get(name) is not None for name in _IDENTITY_FIELDS):
            raise ApprovalError("persisted legacy approval contains unexpected identity claims")
        signature = record.get("signature")
        key_id = record.get("key_id")
        if (not isinstance(signature, str) or not _SIGNATURE_HEX.fullmatch(signature)
                or not isinstance(key_id, str) or key_id not in self._keys
                or record.get("issuer") != self.issuer):
            raise ApprovalError("persisted approval signature or trusted issuer is invalid")
        signed_payload = {**payload, "signature": signature}
        try:
            Ed25519PublicKey.from_public_bytes(self._keys[key_id]).verify(
                bytes.fromhex(signature), self._canonical(signed_payload)
            )
        except (InvalidSignature, ValueError, TypeError):
            raise ApprovalError("persisted approval signature is invalid") from None
        issued_at = self._timestamp(record.get("issued_at"), "issued_at")
        expires_at = self._timestamp(record.get("expires_at"), "expires_at")
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ApprovalError("verifier clock must return a timezone-aware datetime")
        expired = expires_at <= now.astimezone(timezone.utc)
        return {
            "signature_valid": True,
            "issuer_trusted": True,
            "credential_schema": schema,
            "approval_id": record["approval_id"],
            "actor_id": record["actor_id"],
            "action": record["action"],
            "project_id": record["project_id"],
            "project_version": record["project_version"],
            "request_id": record["request_id"],
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expired_now": expired,
            "artifact_id": record.get("artifact_id"),
            "artifact_version": record.get("artifact_version"),
            "artifact_sha256": record.get("artifact_sha256"),
            "artifact_size_bytes": record.get("artifact_size_bytes"),
            **{name: record.get(name) for name in _IDENTITY_FIELDS},
        }

    def verify_and_consume(
        self,
        credential: object,
        *,
        action: str,
        project_id: str,
        project_version: str,
        request_id: str,
    ) -> VerifiedApproval:
        """Verify and atomically consume one credential."""
        return self.verify_many_and_consume(
            (credential,),
            ({"action": action, "project_id": project_id,
              "project_version": project_version, "request_id": request_id},),
        )[0]

    def verify_many_and_consume(
        self,
        credentials: Sequence[object],
        expectations: Sequence[Mapping[str, str]],
        *,
        require_distinct_actors: bool = True,
    ) -> tuple[VerifiedApproval, ...]:
        """Verify every credential, then atomically consume all or none.

        Expectations are ordered and each contains action, project_id,
        project_version, and request_id. This supports separately signed
        FINAL_ACCEPTANCE and PUBLISH approvals for the same exact request.
        """
        if (not isinstance(credentials, (tuple, list)) or not credentials
                or not isinstance(expectations, (tuple, list))
                or len(credentials) != len(expectations)):
            raise ApprovalError("approval batch is empty or has mismatched expectations")
        verified = []
        for credential, expected in zip(credentials, expectations):
            if (not isinstance(expected, Mapping)
                    or set(expected) not in (
                        {"action", "project_id", "project_version", "request_id"},
                        {"action", "project_id", "project_version", "request_id", "artifact_binding"},
                    )):
                raise ApprovalError("approval expectation has an invalid shape")
            scope = dict(expected)
            artifact_binding = scope.pop("artifact_binding", None)
            if any(not isinstance(scope.get(field), str) or not _ID.fullmatch(scope[field])
                   for field in ("action", "project_id", "project_version", "request_id")):
                raise ApprovalError("approval expectation contains an invalid scope value")
            result = self._verify_one(credential, artifact_binding=artifact_binding, **scope)
            verified.append(result)
        approval_ids = [item.approval_id for item in verified]
        nonces = [item.nonce for item in verified]
        if len(set(approval_ids)) != len(approval_ids) or len(set(nonces)) != len(nonces):
            raise ApprovalError("approval batch contains duplicate IDs or nonces")
        if require_distinct_actors and len({item.actor_id for item in verified}) != len(verified):
            raise ApprovalError("approval batch requires distinct authenticated actors")
        try:
            consumed = self._consume_many_once(tuple(verified))
        except Exception:
            raise ApprovalError("approval batch state could not be verified") from None
        if consumed is not True:
            raise ApprovalError("approval batch is revoked, replayed, or could not be consumed atomically")
        return tuple(verified)
