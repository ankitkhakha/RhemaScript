"""Verification-only, request-bound approval credentials.

The issuer and its signing keys live outside RhemaScript. This module never
creates approvals. The consume_once callback must atomically reject revoked
or previously consumed approval IDs/nonces and persist first use.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Callable, Mapping


class ApprovalError(PermissionError):
    """An approval credential is missing, invalid, expired, revoked, or replayed."""


_FIELDS = {
    "schema", "approval_id", "issuer", "actor_id", "action", "project_id",
    "project_version", "request_id", "issued_at", "expires_at", "nonce",
    "key_id", "signature",
}
_SCHEMA = "RhemaScript.ApprovalCredential.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")


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


class ApprovalVerifier:
    """Verify externally signed, narrowly scoped approvals; never mint tokens."""

    def __init__(
        self,
        *,
        issuer: str,
        verification_keys: Mapping[str, bytes],
        consume_once: Callable[[str, str, datetime], bool],
        clock: Callable[[], datetime] | None = None,
        max_lifetime: timedelta = timedelta(minutes=10),
        clock_skew: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("trusted issuer is required")
        if not verification_keys:
            raise ValueError("at least one verification key is required")
        if any(not isinstance(k, str) or not k.strip()
               or not isinstance(v, bytes) or len(v) < 32
               for k, v in verification_keys.items()):
            raise ValueError("verification keys require non-empty IDs and at least 32 secret bytes")
        if not callable(consume_once):
            raise ValueError("an atomic consume_once callback is required")
        if max_lifetime <= timedelta(0) or max_lifetime > timedelta(hours=1):
            raise ValueError("max_lifetime must be positive and no greater than one hour")
        if clock_skew < timedelta(0) or clock_skew > timedelta(minutes=2):
            raise ValueError("clock_skew must be between zero and two minutes")
        self.issuer = issuer
        self._keys = dict(verification_keys)
        self._consume_once = consume_once
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_lifetime = max_lifetime
        self._clock_skew = clock_skew

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

    def verify_and_consume(
        self,
        credential: object,
        *,
        action: str,
        project_id: str,
        project_version: str,
        request_id: str,
    ) -> VerifiedApproval:
        if not isinstance(credential, dict) or set(credential) != _FIELDS:
            raise ApprovalError("approval credential has an invalid shape")
        token = dict(credential)
        if token.get("schema") != _SCHEMA:
            raise ApprovalError("approval credential schema is unsupported")
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
        key = self._keys.get(token["key_id"])
        signature = token.get("signature")
        if key is None or not isinstance(signature, str) or not _HEX.fullmatch(signature):
            raise ApprovalError("approval signature is invalid")
        expected = hmac.new(key, self._canonical(token), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ApprovalError("approval signature is invalid")

        issued_at = self._timestamp(token["issued_at"], "issued_at")
        expires_at = self._timestamp(token["expires_at"], "expires_at")
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
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
        try:
            consumed = self._consume_once(token["approval_id"], token["nonce"], expires_at)
        except Exception:
            raise ApprovalError("approval state could not be verified") from None
        if consumed is not True:
            raise ApprovalError("approval is revoked or has already been consumed")
        return VerifiedApproval(
            approval_id=token["approval_id"], issuer=token["issuer"],
            actor_id=token["actor_id"], action=token["action"],
            project_id=token["project_id"], project_version=token["project_version"],
            request_id=token["request_id"], issued_at=issued_at,
            expires_at=expires_at, nonce=token["nonce"], key_id=token["key_id"],
        )
