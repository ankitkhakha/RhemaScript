"""Offline resolver for explicitly catalogued local evidence sources.

This adapter verifies byte identity only. A local catalog entry is not, by itself,
proof of publisher identity, authority, licensing, or claim relevance.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Mapping

from .artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact


class LocalSourceResolutionError(EvidenceIntegrityError):
    """A local source reference is unknown, unsafe, or does not match its catalog."""


@dataclass(frozen=True)
class LocalSourceEntry:
    reference: str
    source_id: str
    relative_path: str
    version: str
    expected_sha256: str
    media_type: str
    catalog_revision: str


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
    resolved_at_utc: str
    outcome: str = "CONTENT_VERIFIED"
    source_authentication: str = "NOT_CHECKED"
    claim_relevance: str = "NOT_CHECKED"


class LocalSourceResolver:
    """Resolve exact opaque references from a caller-approved, offline catalog."""

    def __init__(self, evidence_root: str, catalog: Mapping[str, LocalSourceEntry]):
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
            copied[key] = entry
        self._evidence_root = evidence_root
        self._catalog = copied

    def resolve(self, reference: str) -> tuple[EvidenceVersion, LocalSourceReceipt]:
        if not isinstance(reference, str) or not reference.strip():
            raise LocalSourceResolutionError("reference must be a non-empty exact identifier")
        entry = self._catalog.get(reference)
        if entry is None:
            raise LocalSourceResolutionError("reference is not present in the approved local catalog")
        try:
            verified = verify_artifact(
                self._evidence_root,
                entry.relative_path,
                evidence_id=entry.source_id,
                version=entry.version,
            )
        except EvidenceIntegrityError as exc:
            raise LocalSourceResolutionError("catalogued local source could not be safely verified") from exc
        if verified.sha256.lower() != entry.expected_sha256.lower():
            raise LocalSourceResolutionError("local source bytes do not match the catalogued SHA-256")
        receipt = LocalSourceReceipt(
            original_reference=reference,
            source_id=entry.source_id,
            relative_path=verified.relative_path,
            version=verified.version,
            sha256=verified.sha256,
            size_bytes=verified.size_bytes,
            media_type=entry.media_type,
            catalog_revision=entry.catalog_revision,
            resolved_at_utc=datetime.now(timezone.utc).isoformat(),
        )
        return verified, receipt
