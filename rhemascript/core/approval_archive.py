"""Owner-controlled, externally retained approval checkpoint archives.

The archive is deliberately separate from SQLite. Callers must supply a key
kept outside both the database and archive location. This module cannot prove
that a directory is on independent hardware or controlled by a different
administrator; that remains an operational responsibility.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import stat

from rhemascript.core.approval_store import ApprovalStoreError, SQLiteApprovalConsumptionStore


ARCHIVE_SCHEMA_V1 = "RhemaScript.ApprovalCheckpointArchive.v1"
ARCHIVE_SCHEMA_V2 = "RhemaScript.ApprovalCheckpointArchive.v2"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _private_directory(path: Path) -> None:
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current = current / component
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ApprovalStoreError("archive path must not contain symlinked directories")
        info = path.lstat()
        actual = path.stat()
    except ApprovalStoreError:
        raise
    except OSError:
        raise ApprovalStoreError("archive directory must already exist") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(actual.st_mode)
            or actual.st_uid != os.getuid()
            or stat.S_IMODE(actual.st_mode) & 0o077):
        raise ApprovalStoreError("archive directory must be owner-owned and private (0700 or stricter)")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("archive authentication key must contain at least 32 bytes")


def export_checkpoint_archive(
    store: SQLiteApprovalConsumptionStore,
    destination: str | os.PathLike[str],
    *,
    key: bytes,
    generation: int | None = None,
) -> Path:
    """Write a one-time authenticated snapshot; V2 binds a monotonic generation."""
    if not isinstance(store, SQLiteApprovalConsumptionStore):
        raise TypeError("store must be a SQLiteApprovalConsumptionStore")
    _validate_key(key)
    if generation is not None and (
        not isinstance(generation, int) or isinstance(generation, bool) or generation < 1
    ):
        raise ValueError("checkpoint generation must be a positive integer")
    target = Path(destination).expanduser()
    _private_directory(target.parent)
    if target.parent.resolve() == store.path.parent.resolve():
        raise ApprovalStoreError("checkpoint archive must be outside the approval database directory")
    if target.resolve(strict=False) == store.path.resolve(strict=False):
        raise ApprovalStoreError("checkpoint archive must not overwrite the approval database")

    snapshot = store._snapshot_bytes()
    digest = hashlib.sha256(snapshot).hexdigest()
    created = datetime.now(timezone.utc).isoformat()
    signed_fields = {
        "schema": ARCHIVE_SCHEMA_V2 if generation is not None else ARCHIVE_SCHEMA_V1,
        "created_at": created,
        "snapshot_sha256": digest,
        "snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
    }
    if generation is not None:
        signed_fields["generation"] = generation
    envelope = dict(signed_fields)
    envelope["hmac_sha256"] = hmac.new(key, _canonical(signed_fields), hashlib.sha256).hexdigest()
    encoded = _canonical(envelope)
    if len(encoded) > MAX_ARCHIVE_BYTES:
        raise ApprovalStoreError("checkpoint archive exceeds the permitted size")

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    except FileExistsError:
        raise ApprovalStoreError("checkpoint archive destination already exists") from None
    except (OSError, ValueError):
        try:
            target.unlink()
        except OSError:
            pass
        raise ApprovalStoreError("checkpoint archive could not be written safely") from None


def verify_checkpoint_archive(
    archive_path: str | os.PathLike[str],
    *,
    key: bytes,
    current_store: SQLiteApprovalConsumptionStore | None = None,
) -> dict[str, object]:
    """Verify archive bytes and optionally reconcile them with current SQLite state.

    This validates an archive for controlled recovery; it never writes to or
    replaces the live approval database.
    """
    _validate_key(key)
    path = Path(archive_path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise ApprovalStoreError("checkpoint archive is missing, inaccessible or a symbolic link") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size <= 0 or info.st_size > MAX_ARCHIVE_BYTES):
            raise ApprovalStoreError("checkpoint archive must be a bounded, owner-owned private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise ApprovalStoreError("checkpoint archive exceeds the permitted size")
    except OSError:
        raise ApprovalStoreError("checkpoint archive could not be read safely") from None
    finally:
        os.close(fd)
    try:
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise ValueError
        if envelope.get("schema") == ARCHIVE_SCHEMA_V1:
            expected = {"schema", "created_at", "snapshot_sha256", "snapshot_b64", "hmac_sha256"}
        elif envelope.get("schema") == ARCHIVE_SCHEMA_V2:
            expected = {"schema", "created_at", "snapshot_sha256", "snapshot_b64", "generation", "hmac_sha256"}
        else:
            raise ValueError
        if set(envelope) != expected:
            raise ValueError
        signed_fields = {name: envelope[name] for name in expected if name != "hmac_sha256"}
        if not isinstance(envelope["created_at"], str):
            raise ValueError
        if envelope["schema"] == ARCHIVE_SCHEMA_V2 and (
            not isinstance(envelope["generation"], int)
            or isinstance(envelope["generation"], bool)
            or envelope["generation"] < 1
        ):
            raise ValueError
        created_at = datetime.fromisoformat(envelope["created_at"])
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError
        if (not isinstance(envelope["snapshot_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", envelope["snapshot_sha256"])
                or not isinstance(envelope["hmac_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", envelope["hmac_sha256"])
                or not isinstance(envelope["snapshot_b64"], str)):
            raise ValueError
        snapshot = base64.b64decode(envelope["snapshot_b64"], validate=True)
        digest = hashlib.sha256(snapshot).hexdigest()
        if not hmac.compare_digest(digest, str(envelope["snapshot_sha256"])):
            raise ValueError
        expected_mac = hmac.new(key, _canonical(signed_fields), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, str(envelope["hmac_sha256"])):
            raise ValueError
        payload = json.loads(snapshot.decode("utf-8"))
        if (not isinstance(payload, dict)
                or payload.get("schema") != "RhemaScript.ApprovalStateCheckpoint.v3"
                or not isinstance(payload.get("consumed"), list)
                or not isinstance(payload.get("revoked"), list)):
            raise ValueError
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise ApprovalStoreError("checkpoint archive is malformed or authentication failed") from None

    matches_current = None
    if current_store is not None:
        if not isinstance(current_store, SQLiteApprovalConsumptionStore):
            raise TypeError("current_store must be a SQLiteApprovalConsumptionStore")
        matches_current = hmac.compare_digest(snapshot, current_store._snapshot_bytes())
    return {
        "archive_valid": True,
        "schema": envelope["schema"],
        "created_at": envelope["created_at"],
        "generation": envelope.get("generation"),
        "snapshot_sha256": digest,
        "consumed_count": len(payload["consumed"]),
        "revoked_count": len(payload["revoked"]),
        "matches_current_state": matches_current,
        "recovery_mode": "verified-export-only; no automatic database restore",
    }
