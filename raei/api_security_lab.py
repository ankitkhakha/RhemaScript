"""In-memory API security lab: ownership, function/property authorization and limits.

Identity is injected as a trusted Principal by a hypothetical authentication layer.
This module deliberately does NOT authenticate credentials or expose a network server.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from threading import Lock
from time import monotonic
from typing import Any

from raei.api_contracts import AuthorizationError, Policy, Principal, RequestError, Rule


@dataclass(frozen=True)
class AuditEvent:
    actor: str
    action: str
    resource_id: str
    outcome: str


class WindowLimiter:
    """Per-subject in-memory fixed-window request limiter for a teaching lab."""
    def __init__(self, limit: int, window_seconds: float):
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit and window must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, subject: str, now: float | None = None) -> bool:
        instant = monotonic() if now is None else now
        with self._lock:
            events = self._events.setdefault(subject, deque())
            while events and instant - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(instant)
            return True


class SecureRecordAPI:
    OWNER_FIELDS = frozenset({"title", "body"})
    ADMIN_FIELDS = frozenset({"title", "body", "classification"})

    def __init__(self, policy: Policy | None = None, limiter: WindowLimiter | None = None):
        self.policy = policy or Policy((
            Rule("reader", "read", "record"),
            Rule("contributor", "read", "record"),
            Rule("contributor", "update", "record"),
            Rule("administrator", "read", "record"),
            Rule("administrator", "update", "record"),
            Rule("administrator", "delete", "record"),
        ))
        self.limiter = limiter or WindowLimiter(20, 60)
        self._records: dict[str, dict[str, Any]] = {}
        self.audit: list[AuditEvent] = []

    def create(self, record_id: str, owner: str, title: str, body: str) -> None:
        if not record_id or not owner or not title.strip():
            raise RequestError("record_id, owner and non-empty title are required")
        if record_id in self._records:
            raise RequestError("record already exists")
        self._records[record_id] = {
            "id": record_id, "owner": owner, "title": title.strip(),
            "body": body, "classification": "private", "version": 1,
        }

    def _guard(self, principal: Principal | None, action: str, record_id: str) -> dict[str, Any]:
        if principal is None or not principal.authenticated or not principal.subject.strip():
            self.audit.append(AuditEvent("anonymous", action, record_id, "denied"))
            raise AuthorizationError("access denied")
        if not self.limiter.allow(principal.subject):
            self.audit.append(AuditEvent(principal.subject, action, record_id, "rate_limited"))
            raise RequestError("request limit exceeded")
        record = self._records.get(record_id)
        if record is None:
            self.audit.append(AuditEvent(principal.subject, action, record_id, "not_found"))
            raise RequestError("record not found")
        if not self.policy.permits(principal, action, "record"):
            self.audit.append(AuditEvent(principal.subject, action, record_id, "denied"))
            raise AuthorizationError("access denied")
        if action != "delete" and "administrator" not in principal.roles:
            if action == "update" and "contributor" not in principal.roles:
                self.audit.append(AuditEvent(principal.subject, action, record_id, "denied"))
                raise AuthorizationError("access denied")
            if record["owner"] != principal.subject:
                self.audit.append(AuditEvent(principal.subject, action, record_id, "denied"))
                raise AuthorizationError("access denied")
        return record

    def read(self, principal: Principal | None, record_id: str) -> dict[str, Any]:
        record = self._guard(principal, "read", record_id)
        assert principal is not None
        if "administrator" in principal.roles:
            visible = dict(record)
        else:
            visible = {key: record[key] for key in ("id", "title", "body", "version")}
        self.audit.append(AuditEvent(principal.subject, "read", record_id, "allowed"))
        return visible

    def update(self, principal: Principal | None, record_id: str,
               changes: Any, expected_version: int) -> dict[str, Any]:
        record = self._guard(principal, "update", record_id)
        assert principal is not None
        if not isinstance(changes, dict) or not changes:
            raise RequestError("changes must be a non-empty object")
        allowed = self.ADMIN_FIELDS if "administrator" in principal.roles else self.OWNER_FIELDS
        if set(changes) - allowed:
            raise RequestError("one or more fields are not writable")
        if any(not isinstance(value, str) for value in changes.values()):
            raise RequestError("all changed values must be strings")
        if not isinstance(expected_version, int) or isinstance(expected_version, bool):
            raise RequestError("expected_version must be an integer")
        if record["version"] != expected_version:
            raise RequestError("stale version")
        record.update(changes)
        record["version"] += 1
        self.audit.append(AuditEvent(principal.subject, "update", record_id, "allowed"))
        return {"id": record_id, "version": record["version"]}

    def delete(self, principal: Principal | None, record_id: str) -> None:
        self._guard(principal, "delete", record_id)
        assert principal is not None
        del self._records[record_id]
        self.audit.append(AuditEvent(principal.subject, "delete", record_id, "allowed"))
