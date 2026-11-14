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


def _open_private_directory(path: Path) -> int:
    """Open and pin an owner-private directory without following any path symlink."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if (os.name != "posix" or os.open not in getattr(os, "supports_dir_fd", set())
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")):
        raise ApprovalStoreError("safe archive directory anchoring is unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute.anchor, flags)
    except OSError:
        raise ApprovalStoreError("archive directory is unavailable or contains a symlink") from None
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(
                component, flags, dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ApprovalStoreError(
                "archive directory must be owner-owned and private (0700 or stricter)"
            )
        return descriptor
    except ApprovalStoreError:
        os.close(descriptor)
        raise
    except OSError:
        os.close(descriptor)
        raise ApprovalStoreError("archive directory is unavailable or contains a symlink") from None
    except Exception:
        os.close(descriptor)
        raise


def _assert_private_directory_identity(
    path: Path, expected_identity: tuple[int, int],
) -> None:
    descriptor = _open_private_directory(path)
    try:
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != expected_identity:
            raise ApprovalStoreError("archive directory changed during operation")
    finally:
        os.close(descriptor)


def _private_directory(path: Path) -> None:
    """Compatibility validation wrapper for an owner-private directory."""
    descriptor = _open_private_directory(path)
    os.close(descriptor)


def _cleanup_created_archive(
    parent_fd: int, filename: str, created_identity: tuple[int, int] | None,
) -> None:
    """Remove only the exact inode created by this export, relative to its pinned parent."""
    if created_identity is None:
        return
    try:
        current = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == created_identity:
            os.unlink(filename, dir_fd=parent_fd)
            os.fsync(parent_fd)
    except OSError:
        pass

def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("archive authentication key must contain at least 32 bytes")



def _aware_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256_text(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_consumed_rows(rows: list[object]) -> None:
    identity_keys = {
        "subject_id", "actor_role", "authn_context", "authenticated_at",
        "identity_session_id", "identity_policy_version", "identity_provider_id",
    }
    approval_ids: set[str] = set()
    nonces: set[str] = set()
    for row in rows:
        if not isinstance(row, list) or len(row) != 19:
            raise ValueError
        if any(not _nonempty_text(row[index]) for index in (0, 1, 2, 3, 4, 5, 6, 7, 10)):
            raise ValueError
        if not all(_aware_timestamp(row[index]) for index in (8, 9, 11)):
            raise ValueError
        if row[0] in approval_ids or row[1] in nonces:
            raise ValueError
        approval_ids.add(row[0])
        nonces.add(row[1])

        artifact = row[12:16]
        if any(value is not None for value in artifact):
            if (not all(_nonempty_text(value) for value in artifact[:3])
                    or not _sha256_text(artifact[2])
                    or not isinstance(artifact[3], int)
                    or isinstance(artifact[3], bool) or artifact[3] <= 0):
                raise ValueError

        credential_schema, signature, identity_json = row[16:19]
        if (credential_schema is None) != (signature is None):
            raise ValueError
        if credential_schema is not None:
            if (credential_schema not in {
                "RhemaScript.ApprovalCredential.v1",
                "RhemaScript.ApprovalCredential.v2",
                "RhemaScript.ApprovalCredential.v3",
            } or not isinstance(signature, str)
                    or re.fullmatch(r"[0-9a-f]{128}", signature) is None):
                raise ValueError
        if identity_json is None:
            identity = {}
        else:
            if not isinstance(identity_json, str):
                raise ValueError
            identity = json.loads(identity_json)
            if (not isinstance(identity, dict) or set(identity) != identity_keys
                    or _canonical(identity) != identity_json.encode("utf-8")):
                raise ValueError
        if credential_schema == "RhemaScript.ApprovalCredential.v3":
            if any(not _nonempty_text(identity.get(key)) for key in identity_keys - {"authenticated_at"}):
                raise ValueError
            if not _aware_timestamp(identity.get("authenticated_at")):
                raise ValueError
        elif any(value is not None for value in identity.values()):
            raise ValueError


def _validate_revoked_rows(rows: list[object]) -> None:
    approval_ids: set[str] = set()
    nonces: set[str] = set()
    for row in rows:
        if (not isinstance(row, list) or len(row) != 5
                or not _nonempty_text(row[0]) or not _nonempty_text(row[1])
                or not _aware_timestamp(row[2]) or not _nonempty_text(row[3])
                or not _nonempty_text(row[4]) or len(row[3]) > 256 or len(row[4]) > 128
                or row[0] in approval_ids or row[1] in nonces):
            raise ValueError
        approval_ids.add(row[0])
        nonces.add(row[1])


def _validate_publish_session_rows(rows: list[object], *, schema: str) -> None:
    expected_width = 17 if schema == "RhemaScript.ApprovalStateCheckpoint.v4" else 21
    identities: set[tuple[str, str, str]] = set()
    fingerprints: set[str] = set()
    url_digests: set[str] = set()
    allowed_states = {
        "CREATING", "ACTIVE", "CHUNK_IN_FLIGHT", "RECONCILING",
        "INDETERMINATE", "COMPLETE", "FAILED",
    }
    for row in rows:
        if not isinstance(row, list) or len(row) != expected_width:
            raise ValueError
        if any(not _nonempty_text(row[index]) for index in (0, 1, 2, 4, 5)):
            raise ValueError
        identity = (row[0], row[1], row[2])
        if identity in identities:
            raise ValueError
        identities.add(identity)
        if (not _sha256_text(row[3]) or row[3] in fingerprints
                or not _sha256_text(row[6])
                or not isinstance(row[7], int) or isinstance(row[7], bool) or row[7] <= 0):
            raise ValueError
        fingerprints.add(row[3])
        if row[8] is not None:
            if not _sha256_text(row[8]) or row[8] in url_digests:
                raise ValueError
            url_digests.add(row[8])
        if row[9] not in allowed_states:
            raise ValueError
        size, offset = row[7], row[10]
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= size:
            raise ValueError
        if (row[11] is None) != (row[12] is None):
            raise ValueError
        if row[11] is not None:
            if (not isinstance(row[11], int) or isinstance(row[11], bool)
                    or not isinstance(row[12], int) or isinstance(row[12], bool)
                    or not 0 <= row[11] <= row[12] < size):
                raise ValueError
        if (row[13] is None) != (row[14] is None):
            raise ValueError
        if row[13] is not None and (not _nonempty_text(row[13]) or not _aware_timestamp(row[14])):
            raise ValueError
        if not _aware_timestamp(row[15]) or not _aware_timestamp(row[16]):
            raise ValueError
        if expected_width == 21:
            resource_id, status, audit_id, audited = row[17:21]
            if resource_id is not None and (
                not isinstance(resource_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", resource_id) is None
            ):
                raise ValueError
            if status is not None and (
                not isinstance(status, int) or isinstance(status, bool) or status not in (200, 201)
            ):
                raise ValueError
            if audit_id is not None and not _sha256_text(audit_id):
                raise ValueError
            if not isinstance(audited, int) or isinstance(audited, bool) or audited not in (0, 1):
                raise ValueError
            completion_fields = (resource_id, status, audit_id)
            if any(value is not None for value in completion_fields) and not all(
                value is not None for value in completion_fields
            ):
                raise ValueError
            if row[9] == "COMPLETE" and (
                resource_id is None or status not in (200, 201) or audit_id is None
                or offset != size
            ):
                raise ValueError
            if audited == 1 and (row[9] != "COMPLETE" or audit_id is None):
                raise ValueError


def _validate_snapshot_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError
    schema = payload.get("schema")
    if schema == "RhemaScript.ApprovalStateCheckpoint.v3":
        if set(payload) != {"schema", "consumed", "revoked"}:
            raise ValueError
    elif schema in {
        "RhemaScript.ApprovalStateCheckpoint.v4",
        "RhemaScript.ApprovalStateCheckpoint.v5",
    }:
        if set(payload) != {"schema", "consumed", "revoked", "publish_sessions"}:
            raise ValueError
    else:
        raise ValueError
    consumed, revoked = payload.get("consumed"), payload.get("revoked")
    if not isinstance(consumed, list) or not isinstance(revoked, list):
        raise ValueError
    _validate_consumed_rows(consumed)
    _validate_revoked_rows(revoked)
    if schema in {
        "RhemaScript.ApprovalStateCheckpoint.v4",
        "RhemaScript.ApprovalStateCheckpoint.v5",
    }:
        sessions = payload.get("publish_sessions")
        if not isinstance(sessions, list):
            raise ValueError
        _validate_publish_session_rows(sessions, schema=schema)
    return payload


def export_checkpoint_archive(
    store: SQLiteApprovalConsumptionStore,
    destination: str | os.PathLike[str],
    *,
    key: bytes,
    generation: int | None = None,
) -> Path:
    """Write a one-time authenticated snapshot through a pinned private directory."""
    if not isinstance(store, SQLiteApprovalConsumptionStore):
        raise TypeError("store must be a SQLiteApprovalConsumptionStore")
    _validate_key(key)
    if generation is not None and (
        not isinstance(generation, int) or isinstance(generation, bool) or generation < 1
    ):
        raise ValueError("checkpoint generation must be a positive integer")
    target = Path(os.path.abspath(os.fspath(Path(destination).expanduser())))
    if not target.name:
        raise ApprovalStoreError("checkpoint archive destination must name a file")

    parent_fd = _open_private_directory(target.parent)
    parent_info = os.fstat(parent_fd)
    parent_identity = (parent_info.st_dev, parent_info.st_ino)
    file_fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        store_parent_path = Path(os.path.abspath(os.fspath(store.path.parent)))
        if (target.parent == store_parent_path
                or store_parent_path in target.parent.parents):
            raise ApprovalStoreError(
                "checkpoint archive must be outside the approval database directory"
            )
        store_parent_fd = _open_private_directory(store_parent_path)
        try:
            store_parent = os.fstat(store_parent_fd)
            if (store_parent.st_dev, store_parent.st_ino) == parent_identity:
                raise ApprovalStoreError(
                    "checkpoint archive directory identity aliases the database directory"
                )
        finally:
            os.close(store_parent_fd)

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
        envelope["hmac_sha256"] = hmac.new(
            key, _canonical(signed_fields), hashlib.sha256
        ).hexdigest()
        encoded = _canonical(envelope)
        if len(encoded) > MAX_ARCHIVE_BYTES:
            raise ApprovalStoreError("checkpoint archive exceeds the permitted size")

        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        file_fd = os.open(target.name, flags, 0o600, dir_fd=parent_fd)
        info = os.fstat(file_fd)
        created_identity = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ApprovalStoreError("new checkpoint archive is not an owner-owned regular file")
        os.fchmod(file_fd, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("checkpoint archive write made no progress")
            view = view[written:]
        os.fsync(file_fd)
        os.fsync(parent_fd)

        _assert_private_directory_identity(target.parent, parent_identity)
        entry = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(entry.st_mode)
                or (entry.st_dev, entry.st_ino) != created_identity):
            raise ApprovalStoreError("checkpoint archive destination changed during export")
        return target
    except FileExistsError:
        _cleanup_created_archive(parent_fd, target.name, created_identity)
        raise ApprovalStoreError("checkpoint archive destination already exists") from None
    except ApprovalStoreError:
        _cleanup_created_archive(parent_fd, target.name, created_identity)
        raise
    except (OSError, ValueError):
        _cleanup_created_archive(parent_fd, target.name, created_identity)
        raise ApprovalStoreError("checkpoint archive could not be written safely") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def verify_checkpoint_archive(
    archive_path: str | os.PathLike[str],
    *,
    key: bytes,
    current_store: SQLiteApprovalConsumptionStore | None = None,
) -> dict[str, object]:
    """Verify bounded archive bytes while proving the path still names the opened inode."""
    _validate_key(key)
    path = Path(os.path.abspath(os.fspath(Path(archive_path).expanduser())))
    if not path.name:
        raise ApprovalStoreError("checkpoint archive path must name a file")
    parent_fd = _open_private_directory(path.parent)
    parent_info = os.fstat(parent_fd)
    parent_identity = (parent_info.st_dev, parent_info.st_ino)
    fd: int | None = None
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            raise ApprovalStoreError(
                "checkpoint archive is missing, inaccessible or a symbolic link"
            ) from None
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_size <= 0 or before.st_size > MAX_ARCHIVE_BYTES):
            raise ApprovalStoreError(
                "checkpoint archive must be a bounded, owner-owned private regular file"
            )
        chunks: list[bytes] = []
        remaining = MAX_ARCHIVE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise ApprovalStoreError("checkpoint archive exceeds the permitted size")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
            raise ApprovalStoreError("checkpoint archive changed while being read")
        entry = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(entry.st_mode)
                or (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino)):
            raise ApprovalStoreError("checkpoint archive destination changed during verification")
        _assert_private_directory_identity(path.parent, parent_identity)
    except ApprovalStoreError:
        raise
    except OSError:
        raise ApprovalStoreError("checkpoint archive could not be read safely") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)

    try:
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or _canonical(envelope) != raw:
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
        decoded_payload = json.loads(snapshot.decode("utf-8"))
        if _canonical(decoded_payload) != snapshot:
            raise ValueError
        payload = _validate_snapshot_payload(decoded_payload)
        payload_schema = payload["schema"]
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
        "snapshot_schema": payload_schema,
        "created_at": envelope["created_at"],
        "generation": envelope.get("generation"),
        "snapshot_sha256": digest,
        "consumed_count": len(payload["consumed"]),
        "revoked_count": len(payload["revoked"]),
        "publish_session_count": len(payload.get("publish_sessions", [])),
        "matches_current_state": matches_current,
        "recovery_mode": "verified-export-only; no automatic database restore",
    }
