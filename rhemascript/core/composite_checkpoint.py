"""Composite, generation-bound checkpoints for RhemaScript authoritative stores.

This module binds the approval-consumption archive and RAEI readiness registry
into one authenticated recovery manifest. It is an export/verification primitive:
it never restores a database and does not claim cross-database atomicity.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from rhemascript.core.approval_archive import verify_checkpoint_archive
from rhemascript.core.approval_store import SQLiteApprovalConsumptionStore
from rhemascript.core.checkpoint_freshness import (
    CheckpointAnchorRecord, MonotonicCheckpointAnchor,
)
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry


SCHEMA = "RhemaScript.CompositeCheckpointManifest.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4 * 1024 * 1024


class CompositeCheckpointError(ValueError):
    """Composite checkpoint is invalid, inconsistent, or not safely retained."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _key(value: bytes, name: str) -> None:
    if not isinstance(value, bytes) or len(value) < 32:
        raise CompositeCheckpointError(f"{name} must contain at least 32 bytes")


def _safe_private_bytes(path: str | os.PathLike[str], limit: int) -> bytes:
    target = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError:
        raise CompositeCheckpointError("checkpoint file is missing or cannot be opened safely") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size <= 0 or info.st_size > limit):
            raise CompositeCheckpointError("checkpoint file must be bounded, owner-owned and private")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise CompositeCheckpointError("checkpoint file exceeds its size limit")
        return raw
    except OSError:
        raise CompositeCheckpointError("checkpoint file could not be read safely") from None
    finally:
        os.close(fd)


def _private_parent(path: Path) -> None:
    absolute = Path(os.path.abspath(path.parent))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CompositeCheckpointError("manifest parent must contain only real directories")
    info = absolute.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise CompositeCheckpointError("manifest parent must be owner-owned and private")


def _read_manifest(path: str | os.PathLike[str], key: bytes) -> tuple[dict[str, Any], bytes]:
    _key(key, "manifest key")
    target = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError:
        raise CompositeCheckpointError("composite manifest is missing or cannot be opened safely") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size <= 0 or info.st_size > _MAX_BYTES):
            raise CompositeCheckpointError("manifest must be a bounded, owner-owned private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise CompositeCheckpointError("composite manifest exceeds the size limit")
    except OSError:
        raise CompositeCheckpointError("composite manifest could not be read safely") from None
    finally:
        os.close(fd)
    try:
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema", "generation", "created_at", "approval_archive_sha256",
            "approval_snapshot_sha256", "readiness_checkpoint",
            "readiness_checkpoint_sha256", "hmac_sha256",
        }:
            raise ValueError
        signed = {name: value for name, value in envelope.items() if name != "hmac_sha256"}
        if envelope["schema"] != SCHEMA:
            raise ValueError
        generation = envelope["generation"]
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise ValueError
        created = datetime.fromisoformat(envelope["created_at"])
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError
        for field in ("approval_archive_sha256", "approval_snapshot_sha256",
                      "readiness_checkpoint_sha256", "hmac_sha256"):
            if not isinstance(envelope[field], str) or not _SHA256.fullmatch(envelope[field]):
                raise ValueError
        checkpoint = envelope["readiness_checkpoint"]
        if not isinstance(checkpoint, dict):
            raise ValueError
        if hashlib.sha256(_canonical(checkpoint)).hexdigest() != envelope["readiness_checkpoint_sha256"]:
            raise ValueError
        expected = hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, envelope["hmac_sha256"]):
            raise ValueError
        if _canonical(envelope) != raw:
            raise ValueError
        return envelope, raw
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        raise CompositeCheckpointError("composite manifest is malformed or authentication failed") from None


def export_composite_checkpoint_manifest(
    approval_store: SQLiteApprovalConsumptionStore,
    readiness_registry: ReadinessRunRegistry,
    approval_archive_path: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    approval_key: bytes,
    readiness_key: bytes,
    archive_key: bytes,
    manifest_key: bytes,
) -> Path:
    """Bind both stores after stable double-sampling; write a create-once manifest.

    The approval archive must already be a V2 generation-bound archive. Both
    database snapshots are sampled before and after reconciliation; any change
    aborts. This detects ordinary concurrent writes but is not a distributed
    transaction or a substitute for pausing writers during a formal backup.
    """
    if not isinstance(approval_store, SQLiteApprovalConsumptionStore):
        raise TypeError("approval_store must be SQLiteApprovalConsumptionStore")
    if not isinstance(readiness_registry, ReadinessRunRegistry):
        raise TypeError("readiness_registry must be ReadinessRunRegistry")
    for value, name in ((approval_key, "approval key"), (readiness_key, "readiness key"),
                        (archive_key, "archive key"), (manifest_key, "manifest key")):
        _key(value, name)

    approval_before = approval_store.checkpoint(approval_key)
    readiness_before = readiness_registry.checkpoint(readiness_key)
    try:
        archive = verify_checkpoint_archive(
            approval_archive_path, key=archive_key, current_store=approval_store,
        )
    except Exception:
        raise CompositeCheckpointError("approval archive failed verification against the live approval store") from None
    if (archive.get("archive_valid") is not True
            or archive.get("matches_current_state") is not True
            or archive.get("schema") != "RhemaScript.ApprovalCheckpointArchive.v2"
            or archive.get("generation") is None
            or archive.get("snapshot_sha256") != approval_before.get("snapshot_sha256")):
        raise CompositeCheckpointError("a current, generation-bound approval archive is required")

    readiness_after = readiness_registry.checkpoint(readiness_key)
    approval_after = approval_store.checkpoint(approval_key)
    if approval_before != approval_after or readiness_before != readiness_after:
        raise CompositeCheckpointError("authoritative stores changed during composite checkpoint capture")

    archive_raw = _safe_private_bytes(approval_archive_path, 64 * 1024 * 1024)
    archive_confirm = _safe_private_bytes(approval_archive_path, 64 * 1024 * 1024)
    if not hmac.compare_digest(hashlib.sha256(archive_raw).hexdigest(),
                               hashlib.sha256(archive_confirm).hexdigest()):
        raise CompositeCheckpointError("approval archive changed during composite checkpoint capture")
    try:
        archive_after = verify_checkpoint_archive(
            approval_archive_path, key=archive_key, current_store=approval_store,
        )
    except Exception:
        raise CompositeCheckpointError("approval archive changed or failed re-verification during capture") from None
    if (archive_after.get("generation") != archive.get("generation")
            or archive_after.get("snapshot_sha256") != archive.get("snapshot_sha256")
            or archive_after.get("matches_current_state") is not True):
        raise CompositeCheckpointError("approval archive changed during composite checkpoint capture")
    checkpoint_digest = hashlib.sha256(_canonical(readiness_before)).hexdigest()
    body = {
        "schema": SCHEMA,
        "generation": archive["generation"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "approval_archive_sha256": archive_file_digest,
        "approval_snapshot_sha256": archive["snapshot_sha256"],
        "readiness_checkpoint": readiness_before,
        "readiness_checkpoint_sha256": checkpoint_digest,
    }
    envelope = {**body, "hmac_sha256": hmac.new(
        manifest_key, _canonical(body), hashlib.sha256,
    ).hexdigest()}
    target = Path(destination).expanduser()
    _private_parent(target)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(_canonical(envelope))
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        dir_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except FileExistsError:
        raise CompositeCheckpointError("composite manifest destination already exists") from None
    except OSError:
        try:
            target.unlink()
        except OSError:
            pass
        raise CompositeCheckpointError("composite manifest could not be written safely") from None
    return target


def verify_composite_checkpoint_manifest(
    manifest_path: str | os.PathLike[str],
    approval_archive_path: str | os.PathLike[str],
    approval_store: SQLiteApprovalConsumptionStore,
    readiness_registry: ReadinessRunRegistry,
    *,
    approval_key: bytes,
    readiness_key: bytes,
    archive_key: bytes,
    manifest_key: bytes,
) -> dict[str, Any]:
    """Verify the manifest, both live stores, and the exact approval archive."""
    envelope, raw = _read_manifest(manifest_path, manifest_key)
    archive_raw = _safe_private_bytes(approval_archive_path, 64 * 1024 * 1024)
    if not hmac.compare_digest(
        hashlib.sha256(archive_raw).hexdigest(), envelope["approval_archive_sha256"],
    ):
        raise CompositeCheckpointError("approval archive bytes differ from the composite manifest")
    try:
        archive = verify_checkpoint_archive(
            approval_archive_path, key=archive_key, current_store=approval_store,
        )
    except Exception:
        raise CompositeCheckpointError("approval archive verification failed") from None
    archive_confirm = _safe_private_bytes(approval_archive_path, 64 * 1024 * 1024)
    if (not hmac.compare_digest(hashlib.sha256(archive_raw).hexdigest(),
                                hashlib.sha256(archive_confirm).hexdigest())
            or archive.get("archive_valid") is not True
            or archive.get("matches_current_state") is not True
            or archive.get("generation") != envelope["generation"]
            or archive.get("snapshot_sha256") != envelope["approval_snapshot_sha256"]):
        raise CompositeCheckpointError("approval archive does not match the manifest or live store")
    readiness_checkpoint = envelope["readiness_checkpoint"]
    if not readiness_registry.verify_checkpoint(readiness_checkpoint, readiness_key):
        raise CompositeCheckpointError("readiness checkpoint does not match the live registry")
    approval_checkpoint = approval_store.checkpoint(approval_key)
    readiness_checkpoint_after = readiness_registry.checkpoint(readiness_key)
    approval_checkpoint_after = approval_store.checkpoint(approval_key)
    if (approval_checkpoint.get("snapshot_sha256") != envelope["approval_snapshot_sha256"]
            or approval_checkpoint_after != approval_checkpoint):
        raise CompositeCheckpointError("approval store changed after composite checkpoint creation")
    if readiness_checkpoint_after != readiness_checkpoint:
        raise CompositeCheckpointError("readiness registry changed during composite verification")
    return {
        "manifest_valid": True,
        "generation": envelope["generation"],
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "approval_archive_sha256": envelope["approval_archive_sha256"],
        "approval_snapshot_sha256": envelope["approval_snapshot_sha256"],
        "readiness_checkpoint_sha256": envelope["readiness_checkpoint_sha256"],
        "matches_current_state": True,
        "recovery_mode": "verified-composite-export-only; no automatic restore",
    }


def advance_composite_checkpoint_anchor(
    manifest_path: str | os.PathLike[str], *, manifest_key: bytes,
    anchor: MonotonicCheckpointAnchor, expected_generation: int,
    now: datetime | None = None,
) -> CheckpointAnchorRecord:
    """Register the composite manifest digest at the independent monotonic anchor."""
    envelope, raw = _read_manifest(manifest_path, manifest_key)
    if not isinstance(anchor, MonotonicCheckpointAnchor):
        raise TypeError("anchor does not implement the monotonic checkpoint contract")
    if (not isinstance(expected_generation, int) or isinstance(expected_generation, bool)
            or expected_generation < 0
            or envelope["generation"] != expected_generation + 1):
        raise CompositeCheckpointError("composite generation must advance exactly one")
    before = anchor.read_latest()
    actual = before.generation if before is not None else 0
    if actual != expected_generation:
        raise CompositeCheckpointError("independent anchor generation changed; reconciliation required")
    digest = hashlib.sha256(raw).hexdigest()
    result = anchor.compare_and_advance(
        expected_generation=expected_generation,
        new_generation=envelope["generation"], snapshot_sha256=digest,
    )
    latest = anchor.read_latest()
    if (not isinstance(result, CheckpointAnchorRecord)
            or not isinstance(latest, CheckpointAnchorRecord)
            or latest.generation != envelope["generation"]
            or latest.snapshot_sha256 != digest
            or latest.record_id != result.record_id):
        raise CompositeCheckpointError("independent anchor rejected or failed composite read-back")
    current = now or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise CompositeCheckpointError("anchor verification time must be timezone-aware")
    age = (current.astimezone(timezone.utc) - latest.resolved_at.astimezone(timezone.utc)).total_seconds()
    if age < -30 or age > 30:
        raise CompositeCheckpointError("independent anchor response is stale or future-dated")
    if latest.recorded_at > current.astimezone(timezone.utc) + timedelta(seconds=30):
        raise CompositeCheckpointError("independent anchor record is future-dated")
    return latest


def verify_composite_checkpoint_against_anchor(
    manifest_path: str | os.PathLike[str], *, manifest_key: bytes,
    anchor: MonotonicCheckpointAnchor, now: datetime | None = None,
) -> CheckpointAnchorRecord:
    """Require the manifest digest and generation to equal the latest anchor."""
    envelope, raw = _read_manifest(manifest_path, manifest_key)
    if not isinstance(anchor, MonotonicCheckpointAnchor):
        raise TypeError("anchor does not implement the monotonic checkpoint contract")
    latest = anchor.read_latest()
    digest = hashlib.sha256(raw).hexdigest()
    if (not isinstance(latest, CheckpointAnchorRecord)
            or latest.generation != envelope["generation"]
            or not hmac.compare_digest(latest.snapshot_sha256, digest)):
        raise CompositeCheckpointError("composite manifest is stale or differs from the independent anchor")
    current = now or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise CompositeCheckpointError("anchor verification time must be timezone-aware")
    age = (current.astimezone(timezone.utc) - latest.resolved_at.astimezone(timezone.utc)).total_seconds()
    if age < -30 or age > 30:
        raise CompositeCheckpointError("independent anchor response is stale or future-dated")
    return latest
