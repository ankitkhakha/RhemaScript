"""Fail-closed, versioned approval verification-key registry contract.

Concrete adapters must authenticate registry responses, pin issuer/environment,
and enforce the declared refresh and emergency-invalidation guarantees. This
module contains no network client, key material, or production registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class VerificationKeyRecord:
    key_id: str
    issuer: str
    environment: str
    status: str
    public_key: bytes
    valid_from: datetime
    valid_until: datetime | None
    registry_revision: str
    resolved_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        import re

        identifier = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
        for name in ("key_id", "issuer", "environment", "registry_revision"):
            value = getattr(self, name)
            if not isinstance(value, str) or not identifier.fullmatch(value):
                raise ValueError(f"{name} must be a valid registry identifier")
        if self.status not in {"ACTIVE", "VERIFY_ONLY", "REVOKED"}:
            raise ValueError("verification key status is unsupported")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("Ed25519 public key must contain exactly 32 bytes")
        for name in ("valid_from", "resolved_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        for name in ("valid_until", "revoked_at"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None
            ):
                raise ValueError(f"{name} must be timezone-aware when supplied")
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("key validity interval is empty")
        if self.status == "REVOKED" and self.revoked_at is None:
            raise ValueError("revoked keys require a revocation timestamp")


@runtime_checkable
class VerificationKeyRegistry(Protocol):
    """Resolve current, authenticated key metadata; outages must raise."""

    def resolve_key(
        self, key_id: str, *, issuer: str, environment: str,
    ) -> VerificationKeyRecord:
        """Return current key state or raise; never return cached stale state."""
        ...
