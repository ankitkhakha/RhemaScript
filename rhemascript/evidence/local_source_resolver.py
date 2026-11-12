"""Offline resolver for explicitly catalogued local evidence sources.

This adapter verifies byte identity only. Catalog entries may be scoped to one
project/version; evidence-pack integration requires that scope to match exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping
from types import MappingProxyType

from .artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact


class LocalSourceResolutionError(EvidenceIntegrityError):
    """A local source reference is unknown, unsafe, stale, or out of scope."""


@dataclass(frozen=True)
class LocalSourceEntry:
    reference: str
    source_id: str
    relative_path: str
    version: str
    expected_sha256: str
    media_type: str
    catalog_revision: str
    project_id: str | None = None
    project_version: str | None = None


@dataclass(frozen=True)
class LocalSourceReceipt:
    original_reference: str
    source_id: str
    relative_path: str
    version: str
    sha256: str
    size_bytes: int
    media_type: str
    catalog_revision: str
    catalog_fingerprint: str
    project_id: str | None
    project_version: str | None
    resolved_at_utc: str
    outcome: str = "CONTENT_VERIFIED"
    source_authentication: str = "NOT_CHECKED"
    claim_relevance: str = "NOT_CHECKED"


class LocalSourceResolver:
    """Resolve exact opaque references from a caller-approved, offline catalog."""

    def __init__(self, evidence_root: str, catalog: Mapping[str, LocalSourceEntry]):
        if not isinstance(evidence_root, str) or not evidence_root.strip():
            raise LocalSourceResolutionError("evidence_root must be a non-empty path")
        if not isinstance(catalog, Mapping) or not catalog:
            raise LocalSourceResolutionError("an explicit non-empty local source catalog is required")
        copied: dict[str, LocalSourceEntry] = {}
        for key, entry in catalog.items():
            if not isinstance(key, str) or not key.strip() or not isinstance(entry, LocalSourceEntry):
                raise LocalSourceResolutionError("catalog keys and entries must be valid local source records")
            if key != entry.reference:
                raise LocalSourceResolutionError("catalog key must exactly match entry reference")
            if not re.fullmatch(r"[0-9a-fA-F]{64}", entry.expected_sha256 or ""):
                raise LocalSourceResolutionError("catalog entry requires a 64-character SHA-256 digest")
            for value in (entry.source_id, entry.version, entry.media_type, entry.catalog_revision):
                if not isinstance(value, str) or not value.strip():
                    raise LocalSourceResolutionError("catalog metadata fields must be non-empty strings")
            if (entry.project_id is None) != (entry.project_version is None):
                raise LocalSourceResolutionError("project_id and project_version must be supplied together")
            if entry.project_id is not None and (
                not isinstance(entry.project_id, str) or not entry.project_id.strip()
                or not isinstance(entry.project_version, str) or not entry.project_version.strip()
            ):
                raise LocalSourceResolutionError("project scope values must be non-empty strings")
            copied[key] = entry
        self._evidence_root = evidence_root
        self._catalog = MappingProxyType(copied)
        canonical = [
            {
                "reference": item.reference, "source_id": item.source_id,
                "relative_path": item.relative_path, "version": item.version,
                "expected_sha256": item.expected_sha256.lower(),
                "media_type": item.media_type, "catalog_revision": item.catalog_revision,
                "project_id": item.project_id, "project_version": item.project_version,
            }
            for _, item in sorted(copied.items())
        ]
        self._catalog_fingerprint = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @property
    def catalog_fingerprint(self) -> str:
        """Stable identity of this immutable-in-practice catalog snapshot."""
        return self._catalog_fingerprint

    def resolve(
        self, reference: str, *, project_id: str | None = None,
        project_version: str | None = None,
    ) -> tuple[EvidenceVersion, LocalSourceReceipt]:
        if not isinstance(reference, str) or not reference.strip():
            raise LocalSourceResolutionError("reference must be a non-empty exact identifier")
        entry = self._catalog.get(reference)
        if entry is None:
            raise LocalSourceResolutionError("reference is not present in the approved local catalog")
        if project_id is not None or project_version is not None:
            if not project_id or not project_version:
                raise LocalSourceResolutionError("both project_id and project_version are required for scoped resolution")
            if entry.project_id != project_id or entry.project_version != project_version:
                raise LocalSourceResolutionError("local source catalog entry is outside the requested project/version scope")
        try:
            verified = verify_artifact(
                self._evidence_root, entry.relative_path,
                evidence_id=entry.source_id, version=entry.version,
            )
        except EvidenceIntegrityError as exc:
            raise LocalSourceResolutionError("catalogued local source could not be safely verified") from exc
        if verified.sha256.lower() != entry.expected_sha256.lower():
            raise LocalSourceResolutionError("local source bytes do not match the catalogued SHA-256")
        receipt = LocalSourceReceipt(
            original_reference=reference, source_id=entry.source_id,
            relative_path=verified.relative_path, version=verified.version,
            sha256=verified.sha256, size_bytes=verified.size_bytes,
            media_type=entry.media_type, catalog_revision=entry.catalog_revision,
            catalog_fingerprint=self._catalog_fingerprint,
            project_id=entry.project_id, project_version=entry.project_version,
            resolved_at_utc=datetime.now(timezone.utc).isoformat(),
        )
        return verified, receipt

    def verify_receipt(
        self, receipt: LocalSourceReceipt, *, project_id: str | None = None,
        project_version: str | None = None,
    ) -> bool:
        """Re-resolve and compare a receipt against this exact catalog snapshot and current bytes."""
        if not isinstance(receipt, LocalSourceReceipt):
            return False
        if not hmac_compare(receipt.catalog_fingerprint, self._catalog_fingerprint):
            return False
        try:
            version, current = self.resolve(
                receipt.original_reference, project_id=project_id,
                project_version=project_version,
            )
        except LocalSourceResolutionError:
            return False
        fields = (
            "source_id", "relative_path", "version", "sha256", "size_bytes",
            "media_type", "catalog_revision", "catalog_fingerprint",
            "project_id", "project_version",
        )
        return (
            all(getattr(receipt, field) == getattr(current, field) for field in fields)
            and receipt.outcome == "CONTENT_VERIFIED"
            and receipt.source_authentication == "NOT_CHECKED"
            and receipt.claim_relevance == "NOT_CHECKED"
            and version.evidence_id == receipt.source_id
            and version.version == receipt.version
            and version.sha256 == receipt.sha256
        )


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time compare for fixed-size catalog fingerprints."""
    import hmac
    return hmac.compare_digest(left, right)
