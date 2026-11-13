"""Independent monotonic checkpoint freshness-anchor contract.

This is an adapter boundary, not a local-file implementation. Production
adapters must provide authenticated, linearizable reads and compare-and-advance
writes in an independently administered append-only or hardware-backed system.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Protocol, runtime_checkable

from rhemascript.core.approval_archive import verify_checkpoint_archive


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class CheckpointAnchorRecord:
    generation: int
    snapshot_sha256: str
    recorded_at: datetime
    resolved_at: datetime
    record_id: str

    def __post_init__(self) -> None:
        if (not isinstance(self.generation, int) or isinstance(self.generation, bool)
                or self.generation < 1):
            raise ValueError("checkpoint generation must be a positive integer")
        if not isinstance(self.snapshot_sha256, str) or not _SHA256.fullmatch(self.snapshot_sha256):
            raise ValueError("checkpoint anchor digest must be lowercase SHA-256")
        if (not isinstance(self.recorded_at, datetime) or self.recorded_at.tzinfo is None
                or self.recorded_at.utcoffset() is None):
            raise ValueError("checkpoint anchor timestamp must be timezone-aware")
        if (not isinstance(self.resolved_at, datetime) or self.resolved_at.tzinfo is None
                or self.resolved_at.utcoffset() is None):
            raise ValueError("checkpoint anchor resolution timestamp must be timezone-aware")
        if not isinstance(self.record_id, str) or not record_id_is_valid(self.record_id):
            raise ValueError("checkpoint anchor record ID is invalid")


def record_id_is_valid(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", value))


@runtime_checkable
class MonotonicCheckpointAnchor(Protocol):
    """Independently administered anchor with authenticated linearizable semantics."""

    def read_latest(self) -> CheckpointAnchorRecord | None:
        """Return the latest durable generation, or None before first registration."""
        ...

    def compare_and_advance(
        self, *, expected_generation: int, new_generation: int,
        snapshot_sha256: str,
    ) -> CheckpointAnchorRecord | None:
        """Atomically append exactly expected+1; return None on a generation conflict."""
        ...


def advance_checkpoint_anchor(
    archive_path: str, *, key: bytes, anchor: MonotonicCheckpointAnchor,
    expected_generation: int, recorded_at: datetime | None = None,
) -> CheckpointAnchorRecord:
    """Verify a generation-bound archive, then register/read it back independently."""
    if not isinstance(anchor, MonotonicCheckpointAnchor):
        raise TypeError("anchor does not implement the monotonic checkpoint contract")
    try:
        archive_result = verify_checkpoint_archive(archive_path, key=key)
    except Exception:
        raise ValueError("checkpoint archive failed local cryptographic verification") from None
    if (archive_result.get("archive_valid") is not True
            or not isinstance(archive_result.get("snapshot_sha256"), str)
            or not _SHA256.fullmatch(archive_result["snapshot_sha256"])
            or not isinstance(archive_result.get("generation"), int)
            or isinstance(archive_result.get("generation"), bool)):
        raise ValueError("a valid generation-bound checkpoint archive is required")
    generation = archive_result["generation"]
    if (not isinstance(expected_generation, int) or isinstance(expected_generation, bool)
            or expected_generation < 0 or generation != expected_generation + 1):
        raise ValueError("checkpoint generation must advance exactly one from the expected value")
    before = anchor.read_latest()
    actual_generation = before.generation if before is not None else 0
    if actual_generation != expected_generation:
        raise ValueError("independent checkpoint anchor generation changed; reconciliation required")
    result = anchor.compare_and_advance(
        expected_generation=expected_generation,
        new_generation=generation,
        snapshot_sha256=archive_result["snapshot_sha256"],
    )
    if not isinstance(result, CheckpointAnchorRecord):
        raise ValueError("independent checkpoint anchor refused or failed to persist the generation")
    latest = anchor.read_latest()
    if (not isinstance(latest, CheckpointAnchorRecord)
            or latest.generation != generation
            or latest.snapshot_sha256 != archive_result["snapshot_sha256"]
            or latest.record_id != result.record_id
            or latest.recorded_at != result.recorded_at):
        raise ValueError("independent checkpoint anchor read-back does not match the archive")
    now = recorded_at or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("anchor verification clock must be timezone-aware")
    now_utc = now.astimezone(timezone.utc)
    resolved_at = latest.resolved_at.astimezone(timezone.utc)
    if resolved_at > now_utc + timedelta(seconds=30):
        raise ValueError("independent checkpoint anchor response is future-dated")
    if now_utc - resolved_at > timedelta(seconds=30):
        raise ValueError("independent checkpoint anchor response is stale")
    if latest.recorded_at > now_utc + timedelta(seconds=30):
        raise ValueError("independent checkpoint anchor record is future-dated")
    return latest

def verify_checkpoint_against_anchor(
    archive_path: str, *, key: bytes, anchor: MonotonicCheckpointAnchor,
) -> CheckpointAnchorRecord:
    """Require a cryptographically verified archive to match the latest anchor."""
    if not isinstance(anchor, MonotonicCheckpointAnchor):
        raise TypeError("anchor does not implement the monotonic checkpoint contract")
    try:
        archive_result = verify_checkpoint_archive(archive_path, key=key)
    except Exception:
        raise ValueError("checkpoint archive failed local cryptographic verification") from None
    if (archive_result.get("archive_valid") is not True
            or not isinstance(archive_result.get("generation"), int)
            or isinstance(archive_result.get("generation"), bool)
            or not isinstance(archive_result.get("snapshot_sha256"), str)
            or not _SHA256.fullmatch(archive_result["snapshot_sha256"])):
        raise ValueError("a valid generation-bound checkpoint archive is required")
    latest = anchor.read_latest()
    if not isinstance(latest, CheckpointAnchorRecord):
        raise ValueError("independent checkpoint anchor is missing or unavailable")
    if (latest.generation != archive_result["generation"]
            or latest.snapshot_sha256 != archive_result["snapshot_sha256"]):
        raise ValueError("checkpoint archive is stale or differs from the latest independent anchor")
    now = datetime.now(timezone.utc)
    resolved_at = latest.resolved_at.astimezone(timezone.utc)
    if resolved_at > now + timedelta(seconds=30):
        raise ValueError("independent checkpoint anchor response is future-dated")
    if now - resolved_at > timedelta(seconds=30):
        raise ValueError("independent checkpoint anchor response is stale")
    return latest
