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
from pathlib import Path
import stat

from rhemascript.core.approval_store import ApprovalStoreError, SQLiteApprovalConsumptionStore


ARCHIVE_SCHEMA = "RhemaScript.ApprovalCheckpointArchive.v1"


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
) -> Path:
    """Write a one-time, owner-only authenticated snapshot outside the DB directory."""
    if not isinstance(store, SQLiteApprovalConsumptionStore):
        raise TypeError("store must be a SQLiteApprovalConsumptionStore")
    _validate_key(key)
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
        "schema": ARCHIVE_SCHEMA,
        "created_at": created,
        "snapshot_sha256": digest,
        "snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
    }
    envelope = dict(signed_fields)
    envelope["hmac_sha256"] = hmac.new(key, _canonical(signed_fields), hashlib.sha256).hexdigest()
    encoded = _canonical(envelope)

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
    try:
        info = path.lstat()
    except OSError:
        raise ApprovalStoreError("checkpoint archive is missing or inaccessible") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ApprovalStoreError("checkpoint archive must be an owner-owned private regular file")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        expected = {"schema", "created_at", "snapshot_sha256", "snapshot_b64", "hmac_sha256"}
        if not isinstance(envelope, dict) or set(envelope) != expected:
            raise ValueError
        signed_fields = {name: envelope[name] for name in (
            "schema", "created_at", "snapshot_sha256", "snapshot_b64"
        )}
        if envelope["schema"] != ARCHIVE_SCHEMA or not isinstance(envelope["created_at"], str):
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
        "schema": ARCHIVE_SCHEMA,
        "created_at": envelope["created_at"],
        "snapshot_sha256": digest,
        "consumed_count": len(payload["consumed"]),
        "revoked_count": len(payload["revoked"]),
        "matches_current_state": matches_current,
        "recovery_mode": "verified-export-only; no automatic database restore",
    }
