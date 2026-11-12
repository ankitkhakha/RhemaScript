"""Durable, local-only JSON Lines audit sink for provider gateway events.

The sink stores metadata only. It accepts a strict event schema and rejects
payloads, headers, credentials, URLs, and arbitrary caller-supplied fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
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
    "timestamp_utc",
}
_REQUIRED_FIELDS = {"interface_id", "provider", "request_id", "operation", "phase"}
_ALLOWED_PHASES = {"REQUESTED", "COMPLETED", "FAILED"}
_SAFE_STRING_FIELDS = {
    "interface_id", "provider", "request_id", "project_id", "operation",
    "method", "host", "request_fingerprint", "idempotency_key", "phase", "error_type",
    "timestamp_utc",
}
_SAFE_INTEGER_FIELDS = {"request_bytes", "response_bytes", "http_status"}


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
            if key in _SAFE_STRING_FIELDS and (not isinstance(value, str) or not value):
                raise AuditSinkError("audit event string field is invalid")
            if key in _SAFE_INTEGER_FIELDS and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                raise AuditSinkError("audit event numeric field is invalid")
        try:
            record = (json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError):
            raise AuditSinkError("audit event is not serializable") from None

        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            descriptor = None
            try:
                descriptor = os.open(self.path, flags, 0o600)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise AuditSinkError("audit destination must be a regular file")
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
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
                    os.close(descriptor)
