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
    "chunk_total_bytes", "acknowledged_offset",
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
    "chunk_total_bytes", "acknowledged_offset",
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


class JsonlAuditSink:
    """Append-only local audit log; each event is fsynced before return.

    The parent directory must already exist and be controlled by the operator.
    The log is created with owner-only permissions (0600); existing files are
    tightened to 0600. Symlinks and non-regular files are rejected.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path).expanduser()
        if not self.path.name or not self.path.parent.is_dir():
            raise AuditSinkError("audit log parent directory must already exist")
        if os.name == "posix":
            try:
                parent_info = os.lstat(self.path.parent)
            except OSError:
                raise AuditSinkError("audit log parent directory is unavailable") from None
            if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode)
                    or parent_info.st_uid != os.getuid()
                    or stat.S_IMODE(parent_info.st_mode) & 0o077):
                raise AuditSinkError("audit log parent must be an owner-controlled directory with mode 0700 or stricter")
        self._lock = threading.Lock()

    def __call__(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict) or not _REQUIRED_FIELDS.issubset(event):
            raise AuditSinkError("audit event does not match the required schema")
        if set(event) - _ALLOWED_FIELDS:
            raise AuditSinkError("audit event contains fields outside the safe schema")
        if event.get("phase") not in _ALLOWED_PHASES:
            raise AuditSinkError("audit event phase is invalid")
        record_data = dict(event)
        record_data.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        for key, value in record_data.items():
            if key in _SAFE_STRING_FIELDS:
                if not isinstance(value, str) or not value or len(value) > _STRING_MAX_LENGTHS[key]:
                    raise AuditSinkError("audit event string field is invalid")
                if key in _SHA256_FIELDS and not re.fullmatch(r"[0-9a-f]{64}", value):
                    raise AuditSinkError("audit event digest field is invalid")
                if key == "provider_resource_id" and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                    raise AuditSinkError("audit event provider resource ID is invalid")
                if key == "publish_session_state" and value not in _ALLOWED_SESSION_STATES:
                    raise AuditSinkError("audit event publish-session state is invalid")
            if key in _SAFE_INTEGER_FIELDS and (value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2**63 - 1)):
                raise AuditSinkError("audit event numeric field is invalid")
            if key in _SAFE_BOOLEAN_FIELDS and not isinstance(value, bool):
                raise AuditSinkError("audit event boolean field is invalid")
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
            descriptor = None
            try:
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
                if completion_event_id is not None:
                    matching_indeterminate = False
                    matching_completed = False
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
                            if existing.get("completion_event_id") == completion_event_id:
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
                    if matching_completed or (
                        record_data["phase"] == "INDETERMINATE" and matching_indeterminate
                    ):
                        # Scan the complete log before accepting a duplicate, then re-sync:
                        # a prior append may be visible even though its fsync failed.
                        os.fsync(descriptor)
                        return
                view = memoryview(record)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise AuditSinkError("audit record write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
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
