"""Synthetic SQLite reference model for lease/fencing state-machine tests.

This module is NOT a production authorization coordinator. It has no authenticated
service identity, independent administration, HSM-backed lease signatures, or
provider-side dispatch integration. Do not wire it to live provider transports.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3
import uuid


class LeaseStateError(RuntimeError):
    """Safe lease-state error."""


@dataclass(frozen=True)
class AuthorizationLease:
    lease_id: str
    resource_id: str
    generation: int
    dispatch_nonce: str
    request_fingerprint: str
    expires_at: str


class SQLiteLeaseStateModel:
    """Local transactional model used only to exercise lease/fence invariants."""

    def __init__(self, path: str):
        self.path = path
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS resource_fences (
                    resource_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked_approvals (
                    approval_id TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY,
                    resource_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    dispatch_nonce TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lease_approvals (
                    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
                    approval_id TEXT NOT NULL,
                    PRIMARY KEY (lease_id, approval_id)
                );
                CREATE TABLE IF NOT EXISTS accepted_dispatches (
                    dispatch_nonce TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL UNIQUE,
                    accepted_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_lease_per_approval
                    ON lease_approvals(approval_id);
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _utc(value: datetime) -> str:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("lease expiry must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat()

    def acquire(
        self, *, resource_id: str, approval_ids: tuple[str, ...],
        dispatch_nonce: str, request_fingerprint: str, expires_at: datetime,
    ) -> AuthorizationLease:
        values = (resource_id, dispatch_nonce, request_fingerprint)
        if any(not isinstance(v, str) or not v.strip() for v in values):
            raise ValueError("lease binding fields must be non-empty strings")
        if (not isinstance(approval_ids, tuple) or len(approval_ids) < 2
                or any(not isinstance(v, str) or not v.strip() for v in approval_ids)
                or len(set(approval_ids)) != len(approval_ids)):
            raise ValueError("lease requires distinct approval identifiers")
        expiry = self._utc(expires_at)
        if datetime.fromisoformat(expiry) <= datetime.now(timezone.utc):
            raise ValueError("lease expiry must be in the future")
        lease_id = str(uuid.uuid4())
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            # A writer lock may have delayed acquisition beyond the expiry
            # checked before BEGIN IMMEDIATE. Recheck after serialization.
            if datetime.fromisoformat(expiry) <= datetime.now(timezone.utc):
                db.execute("ROLLBACK")
                raise LeaseStateError("lease expired while waiting to acquire state lock")
            if any(db.execute(
                "SELECT 1 FROM revoked_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone() for approval_id in approval_ids):
                db.execute("ROLLBACK")
                raise LeaseStateError("revoked approval cannot acquire a lease")
            row = db.execute(
                "SELECT generation FROM resource_fences WHERE resource_id=?",
                (resource_id,),
            ).fetchone()
            generation = (row[0] if row else 0) + 1
            db.execute(
                """INSERT INTO resource_fences(resource_id,generation) VALUES(?,?)
                   ON CONFLICT(resource_id) DO UPDATE SET generation=excluded.generation""",
                (resource_id, generation),
            )
            db.execute(
                "INSERT INTO leases VALUES(?,?,?,?,?,?,?)",
                (lease_id, resource_id, generation, dispatch_nonce,
                 request_fingerprint, expiry, "ISSUED"),
            )
            db.executemany(
                "INSERT INTO lease_approvals VALUES(?,?)",
                [(lease_id, approval_id) for approval_id in approval_ids],
            )
            db.execute("COMMIT")
            return AuthorizationLease(
                lease_id, resource_id, generation, dispatch_nonce,
                request_fingerprint, expiry,
            )
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def revoke(self, approval_id: str) -> None:
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id must be non-empty")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO revoked_approvals VALUES(?,?)",
                (approval_id, datetime.now(timezone.utc).isoformat()),
            )
            resources = db.execute(
                """SELECT DISTINCT l.resource_id FROM leases l
                   JOIN lease_approvals a ON a.lease_id=l.lease_id
                   WHERE a.approval_id=?""", (approval_id,),
            ).fetchall()
            for (resource_id,) in resources:
                db.execute(
                    """INSERT INTO resource_fences VALUES(?,1)
                       ON CONFLICT(resource_id) DO UPDATE
                       SET generation=generation+1""", (resource_id,),
                )
            db.execute(
                """UPDATE leases SET state='REVOKED'
                   WHERE lease_id IN (
                     SELECT lease_id FROM lease_approvals WHERE approval_id=?
                   )""", (approval_id,),
            )
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise LeaseStateError("lease revocation transaction failed") from None
        finally:
            db.close()

    def accept_dispatch(
        self, lease: AuthorizationLease, *, request_fingerprint: str,
        now: datetime | None = None,
    ) -> bool:
        if not isinstance(lease, AuthorizationLease):
            return False
        # Explicit now is a deterministic test seam. Production-model calls
        # sample the clock only after acquiring the serialized lock.
        current_time = self._utc(now) if now is not None else None
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            if current_time is None:
                current_time = self._utc(datetime.now(timezone.utc))
            row = db.execute(
                """SELECT l.resource_id,l.generation,l.dispatch_nonce,
                          l.request_fingerprint,l.expires_at,l.state,
                          f.generation
                   FROM leases l JOIN resource_fences f
                     ON f.resource_id=l.resource_id
                   WHERE l.lease_id=?""", (lease.lease_id,),
            ).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                return False
            resource, generation, nonce, fingerprint, expiry, state, current_generation = row
            if (resource != lease.resource_id or generation != lease.generation
                    or nonce != lease.dispatch_nonce
                    or fingerprint != lease.request_fingerprint
                    or fingerprint != request_fingerprint
                    or expiry <= current_time or state != "ISSUED"
                    or generation != current_generation):
                db.execute("ROLLBACK")
                return False
            if db.execute(
                "SELECT 1 FROM lease_approvals a JOIN revoked_approvals r USING(approval_id) WHERE a.lease_id=?",
                (lease.lease_id,),
            ).fetchone():
                db.execute("ROLLBACK")
                return False
            db.execute(
                "INSERT INTO accepted_dispatches VALUES(?,?,?)",
                (nonce, lease.lease_id, current_time),
            )
            db.execute(
                "UPDATE leases SET state='ACCEPTED' WHERE lease_id=?", (lease.lease_id,),
            )
            db.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise LeaseStateError("dispatch acceptance transaction failed") from None
        finally:
            db.close()
