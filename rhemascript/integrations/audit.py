"""Durable, local-only JSON Lines audit sink for provider gateway events.

The sink stores metadata only. It accepts a strict event schema and rejects
payloads, headers, credentials, URLs, and arbitrary caller-supplied fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX import compatibility
    fcntl = None
import json
import os
import re
import stat
import threading
import weakref
from pathlib import Path
from typing import Any


class AuditSinkError(RuntimeError):
    """Raised when an audit event cannot be safely persisted."""


_ALLOWED_FIELDS = {
    "interface_id", "provider", "request_id", "project_id", "operation",
    "method", "host", "request_fingerprint", "idempotency_key",
    "request_bytes", "response_bytes", "http_status", "phase", "error_type",
    "timestamp_utc", "provider_resource_id", "completion_event_id",
    "approval_fingerprint", "artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes", "status_reconciliation",
    "session_url_sha256", "publish_session_state", "chunk_start", "chunk_end",
    "chunk_total_bytes", "acknowledged_offset", "schema_version",
}
_REQUIRED_FIELDS = {"interface_id", "provider", "request_id", "operation", "phase"}
_ALLOWED_PHASES = {"REQUESTED", "COMPLETED", "FAILED", "INDETERMINATE"}
_SAFE_STRING_FIELDS = {
    "interface_id", "provider", "request_id", "project_id", "operation",
    "method", "host", "request_fingerprint", "idempotency_key", "phase", "error_type",
    "timestamp_utc", "provider_resource_id", "completion_event_id",
    "approval_fingerprint", "artifact_id", "artifact_version", "artifact_sha256",
    "session_url_sha256", "publish_session_state",
}
_SAFE_INTEGER_FIELDS = {
    "request_bytes", "response_bytes", "http_status", "artifact_size_bytes", "chunk_start", "chunk_end",
    "chunk_total_bytes", "acknowledged_offset", "schema_version",
}
_SAFE_BOOLEAN_FIELDS = {"status_reconciliation"}
_STRING_MAX_LENGTHS = {
    "interface_id": 64, "provider": 64, "request_id": 128, "project_id": 128,
    "operation": 64, "method": 16, "host": 253, "request_fingerprint": 64,
    "idempotency_key": 256, "phase": 16, "error_type": 128, "timestamp_utc": 64,
    "provider_resource_id": 128, "completion_event_id": 64,
    "approval_fingerprint": 64, "artifact_id": 128, "artifact_version": 128,
    "artifact_sha256": 64, "session_url_sha256": 64, "publish_session_state": 32,
}
_SHA256_FIELDS = {
    "request_fingerprint", "completion_event_id", "approval_fingerprint",
    "artifact_sha256", "session_url_sha256",
}
_ALLOWED_SESSION_STATES = {
    "CREATING", "ACTIVE", "CHUNK_IN_FLIGHT", "RECONCILING",
    "COMPLETE", "FAILED", "INDETERMINATE",
}
_AUDIT_SCHEMA_VERSION = 1


def _validate_record_schema(record: dict[str, Any], *, legacy: bool = False) -> None:
    """Validate a stored audit row under its explicit or legacy schema contract."""
    if not isinstance(record, dict) or not _REQUIRED_FIELDS.issubset(record):
        raise AuditSinkError("audit record does not match the required schema")
    if set(record) - _ALLOWED_FIELDS:
        raise AuditSinkError("audit record contains fields outside the safe schema")
    phase = record.get("phase")
    if not isinstance(phase, str) or phase not in _ALLOWED_PHASES:
        raise AuditSinkError("audit record phase is invalid")
    if not legacy and record.get("schema_version") != _AUDIT_SCHEMA_VERSION:
        raise AuditSinkError("audit record schema version is unsupported")
    if legacy and "schema_version" in record:
        raise AuditSinkError("legacy audit record unexpectedly declares a schema version")

    for key, value in record.items():
        if key in _SAFE_STRING_FIELDS:
            if not isinstance(value, str) or not value:
                raise AuditSinkError("audit record string field is invalid")
            if not legacy and len(value) > _STRING_MAX_LENGTHS[key]:
                raise AuditSinkError("audit record string field exceeds its schema bound")
            if not legacy and key in _SHA256_FIELDS and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise AuditSinkError("audit record digest field is invalid")
            if not legacy and key == "provider_resource_id" and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                raise AuditSinkError("audit record provider resource ID is invalid")
            if not legacy and key == "publish_session_state" and value not in _ALLOWED_SESSION_STATES:
                raise AuditSinkError("audit record publish-session state is invalid")
        if key in _SAFE_INTEGER_FIELDS:
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                or (not legacy and value > 2**63 - 1)
            ):
                raise AuditSinkError("audit record numeric field is invalid")
        if key in _SAFE_BOOLEAN_FIELDS and not isinstance(value, bool):
            raise AuditSinkError("audit record boolean field is invalid")

    if not legacy:
        for key, value in record.items():
            if key in _SAFE_STRING_FIELDS and (
                value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise AuditSinkError("audit record string field contains whitespace or control characters")
        if not re.fullmatch(r"[A-Z][A-Z0-9-]{0,63}", record["interface_id"]):
            raise AuditSinkError("audit record interface ID syntax is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", record["provider"]):
            raise AuditSinkError("audit record provider syntax is invalid")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", record["operation"]):
            raise AuditSinkError("audit record operation syntax is invalid")
        if "method" in record and record["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise AuditSinkError("audit record HTTP method is invalid")
        if "host" in record:
            host = record["host"]
            dns_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            if len(host) > 253 or not re.fullmatch(rf"{dns_label}(?:\.{dns_label})*\.?", host):
                raise AuditSinkError("audit record host syntax is invalid")
        if "timestamp_utc" in record:
            try:
                timestamp = datetime.fromisoformat(record["timestamp_utc"].replace("Z", "+00:00"))
            except ValueError:
                raise AuditSinkError("audit record timestamp is invalid") from None
            if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
                raise AuditSinkError("audit record timestamp must be timezone-aware UTC")

    if "completion_event_id" in record:
        event_id = record["completion_event_id"]
        resource_id = record.get("provider_resource_id")
        if (not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{64}", event_id)
                or record["phase"] not in {"COMPLETED", "INDETERMINATE"}
                or not isinstance(resource_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", resource_id)):
            raise AuditSinkError("audit record completion identity is invalid")


def _open_directory_without_symlinks(path: Path) -> int:
    """Open an absolute directory path component-by-component without following symlinks."""
    if os.name != "posix" or os.open not in getattr(os, "supports_dir_fd", set()):
        raise AuditSinkError("stable audit directory anchoring is unavailable on this platform")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise AuditSinkError("safe audit directory traversal is unavailable on this platform")
    flags = os.O_RDONLY | directory_flag
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component, flags | no_follow, dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _fsync_parent_directory(path: Path, directory_descriptor: int | None = None) -> None:
    """Persist directory-entry changes using the pinned directory when available."""
    if os.name != "posix":
        return
    if directory_descriptor is not None:
        os.fsync(directory_descriptor)
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor = os.open(path.parent, flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


class JsonlAuditSink:
    """Append-only local audit log; each event is fsynced before return.

    The parent directory must already exist and be controlled by the operator.
    The log is created with owner-only permissions (0600); existing files are
    tightened to 0600. Symlinks and non-regular files are rejected.
    """

    def __init__(self, path: str | os.PathLike[str]):
        expanded_path = Path(path).expanduser()
        if not expanded_path.name:
            raise AuditSinkError("audit log path must name a file")
        self.path = Path(os.path.abspath(os.fspath(expanded_path)))
        self._lock = threading.Lock()
        self._parent_fd: int | None = None
        self._parent_finalizer = None
        self._closed = False
        if os.name == "posix":
            try:
                self._parent_fd = _open_directory_without_symlinks(self.path.parent)
                parent_info = os.fstat(self._parent_fd)
            except (OSError, AuditSinkError):
                if self._parent_fd is not None:
                    os.close(self._parent_fd)
                    self._parent_fd = None
                raise AuditSinkError("audit log parent directory is unavailable or contains a symlink") from None
            if (not stat.S_ISDIR(parent_info.st_mode)
                    or parent_info.st_uid != os.getuid()
                    or stat.S_IMODE(parent_info.st_mode) & 0o077):
                os.close(self._parent_fd)
                self._parent_fd = None
                raise AuditSinkError("audit log parent must be an owner-controlled directory with mode 0700 or stricter")
            self._parent_finalizer = weakref.finalize(self, os.close, self._parent_fd)
        elif not self.path.parent.is_dir():
            raise AuditSinkError("audit log parent directory must already exist")

    def close(self) -> None:
        """Release the pinned audit directory descriptor."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._parent_finalizer is not None and self._parent_finalizer.alive:
                self._parent_finalizer()
            self._parent_fd = None

    def __call__(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict) or not _REQUIRED_FIELDS.issubset(event):
            raise AuditSinkError("audit event does not match the required schema")
        if "schema_version" in event:
            raise AuditSinkError("audit schema version is assigned by the sink")
        record_data = dict(event)
        record_data.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        record_data["schema_version"] = _AUDIT_SCHEMA_VERSION
        _validate_record_schema(record_data)
        try:
            record = (json.dumps(record_data, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError):
            raise AuditSinkError("audit event is not serializable") from None

        completion_event_id = record_data.get("completion_event_id")
        if completion_event_id is not None:
            if fcntl is None:
                raise AuditSinkError("idempotent completion audit requires POSIX file locking")
            if not isinstance(completion_event_id, str) or not re.fullmatch(r"[0-9a-f]{64}", completion_event_id):
                raise AuditSinkError("completion event ID must be a lowercase SHA-256 digest")
            if record_data["phase"] not in {"COMPLETED", "INDETERMINATE"}:
                raise AuditSinkError("completion event ID is only valid for completion outcomes")
            resource_id = record_data.get("provider_resource_id")
            if not isinstance(resource_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", resource_id):
                raise AuditSinkError("completed provider resource ID is invalid")
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            if self._closed:
                raise AuditSinkError("audit sink is closed")
            descriptor = None
            try:
                if self._parent_fd is not None:
                    descriptor = os.open(
                        self.path.name, flags, 0o600, dir_fd=self._parent_fd,
                    )
                else:
                    descriptor = os.open(self.path, flags, 0o600)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise AuditSinkError("audit destination must be a regular file")
                if os.name == "posix" and info.st_uid != os.getuid():
                    raise AuditSinkError("audit destination must be owned by the current user")
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                # Never append after an unterminated tail, even for non-idempotent events.
                file_size = os.fstat(descriptor).st_size
                if file_size:
                    os.lseek(descriptor, -1, os.SEEK_END)
                    if os.read(descriptor, 1) != b"\n":
                        raise AuditSinkError("audit log contains unterminated records; append is unsafe")
                    os.lseek(descriptor, 0, os.SEEK_SET)
                matching_indeterminate = False
                matching_completed = False
                # Validate the complete existing log before every append, not only
                # completion deduplication, so corruption is never extended.
                with os.fdopen(os.dup(descriptor), "rb") as existing_log:
                    for line in existing_log:
                        if not line.endswith(b"\n"):
                            raise AuditSinkError("audit log contains unterminated records; idempotent recovery is unsafe")
                        try:
                            existing = json.loads(line)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            raise AuditSinkError("audit log contains malformed records; idempotent recovery is unsafe") from None
                        if not isinstance(existing, dict):
                            raise AuditSinkError("audit log contains malformed records; idempotent recovery is unsafe")
                        try:
                            _validate_record_schema(existing, legacy="schema_version" not in existing)
                        except AuditSinkError:
                            raise AuditSinkError("audit log contains records outside the supported schema") from None
                        if completion_event_id is not None and existing.get("completion_event_id") == completion_event_id:
                            if (existing.get("provider_resource_id") != resource_id
                                    or existing.get("request_id") != record_data.get("request_id")
                                    or existing.get("project_id") != record_data.get("project_id")
                                    or existing.get("http_status") != record_data.get("http_status")):
                                raise AuditSinkError("completion event ID already exists with a different provider result")
                            existing_phase = existing.get("phase")
                            if existing_phase == "COMPLETED":
                                matching_completed = True
                            elif existing_phase == "INDETERMINATE":
                                matching_indeterminate = True
                            else:
                                raise AuditSinkError("completion event ID exists in an unexpected audit phase")
                if completion_event_id is not None and (
                    matching_completed or (
                        record_data["phase"] == "INDETERMINATE" and matching_indeterminate
                    )
                ):
                    # Scan the complete log before accepting a duplicate, then re-sync:
                    # a prior append may be visible even though its fsync failed.
                    os.fsync(descriptor)
                    _fsync_parent_directory(self.path, self._parent_fd)
                    return
                view = memoryview(record)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise AuditSinkError("audit record write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
                _fsync_parent_directory(self.path, self._parent_fd)
            except AuditSinkError:
                raise
            except OSError:
                raise AuditSinkError("audit record could not be durably persisted") from None
            finally:
                if descriptor is not None:
                    try:
                        if fcntl is not None:
                            fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    os.close(descriptor)
