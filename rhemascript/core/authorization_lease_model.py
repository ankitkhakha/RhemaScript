"""Synthetic SQLite reference model for lease/fencing state-machine tests.

This module is NOT a production authorization coordinator. It has no authenticated
service identity, independent administration, HSM-backed lease signatures, or
provider-side dispatch integration. Do not wire it to live provider transports.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
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

    def __init__(self, path: str, *, anchor_path: str | None = None):
        self.path = path
        # Separate local database models an independently retained high-water
        # anchor. It is still synthetic and not an external trust service.
        self.anchor_path = anchor_path or (path + ".recovery-anchor.sqlite3")
        with self._anchor_connect() as anchor:
            anchor.execute("""
                CREATE TABLE IF NOT EXISTS recovery_anchor (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    sequence INTEGER NOT NULL,
                    generation_high_water INTEGER NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    checkpoint_json TEXT,
                    event_sequence_high_water INTEGER NOT NULL DEFAULT 0
                )
            """)
            anchor_columns = {
                row[1] for row in anchor.execute("PRAGMA table_info(recovery_anchor)")
            }
            if "checkpoint_json" not in anchor_columns:
                anchor.execute("ALTER TABLE recovery_anchor ADD COLUMN checkpoint_json TEXT")
            if "event_sequence_high_water" not in anchor_columns:
                anchor.execute(
                    "ALTER TABLE recovery_anchor ADD COLUMN event_sequence_high_water INTEGER NOT NULL DEFAULT 0"
                )
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
                CREATE TABLE IF NOT EXISTS event_history (
                    sequence INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dispatch_outcomes (
                    lease_id TEXT PRIMARY KEY REFERENCES leases(lease_id),
                    status TEXT NOT NULL,
                    provider_operation_id TEXT,
                    reason_code TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_lease_per_provider_operation
                    ON dispatch_outcomes(provider_operation_id)
                    WHERE provider_operation_id IS NOT NULL;
            """)

    @staticmethod
    def _append_event(db, event_type: str, subject_id: str, payload: dict[str, object]) -> None:
        previous = db.execute(
            "SELECT sequence,event_hash FROM event_history ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = previous[0] + 1 if previous else 1
        previous_hash = previous[1] if previous else "0" * 64
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        created_at = datetime.now(timezone.utc).isoformat()
        canonical = json.dumps({
            "sequence": sequence, "event_type": event_type,
            "subject_id": subject_id, "payload_json": payload_json,
            "previous_hash": previous_hash, "created_at": created_at,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        event_hash = hashlib.sha256(canonical).hexdigest()
        db.execute(
            "INSERT INTO event_history VALUES(?,?,?,?,?,?,?)",
            (sequence, event_type, subject_id, payload_json,
             previous_hash, event_hash, created_at),
        )

    def verify_event_history(self) -> bool:
        """Verify the local append-only hash chain from its genesis event."""
        db = self._connect()
        try:
            rows = db.execute(
                """SELECT sequence,event_type,subject_id,payload_json,
                          previous_hash,event_hash,created_at
                   FROM event_history ORDER BY sequence"""
            ).fetchall()
        except sqlite3.Error:
            return False
        finally:
            db.close()
        previous_hash = "0" * 64
        for expected_sequence, row in enumerate(rows, 1):
            sequence, event_type, subject_id, payload_json, stored_previous, stored_hash, created_at = row
            if sequence != expected_sequence or stored_previous != previous_hash:
                return False
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError):
                return False
            canonical = json.dumps({
                "sequence": sequence, "event_type": event_type,
                "subject_id": subject_id, "payload_json": json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ),
                "previous_hash": stored_previous, "created_at": created_at,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            calculated = hashlib.sha256(canonical).hexdigest()
            if not hmac.compare_digest(calculated, stored_hash):
                return False
            previous_hash = stored_hash
        # When a checkpoint exists, its event-history prefix is the retained
        # local reference point. This detects truncation or rewriting of any
        # event that was included in the latest checkpoint.
        anchor = self._anchor_connect()
        try:
            anchored = anchor.execute(
                "SELECT checkpoint_json FROM recovery_anchor WHERE singleton=1"
            ).fetchone()
            if anchored is not None and anchored[0] is not None:
                checkpoint = json.loads(anchored[0])
                anchored_events = checkpoint.get("state", {}).get("event_history")
                if not isinstance(anchored_events, list) or len(rows) < len(anchored_events):
                    return False
                current_prefix = [list(row) for row in rows[:len(anchored_events)]]
                if current_prefix != anchored_events:
                    return False
        except (sqlite3.Error, ValueError, TypeError, AttributeError):
            return False
        finally:
            anchor.close()
        return True

    def read_event_history(self) -> list[dict[str, object]]:
        """Return a read-only copy of the local event chain."""
        db = self._connect()
        try:
            rows = db.execute(
                """SELECT sequence,event_type,subject_id,payload_json,
                          previous_hash,event_hash,created_at
                   FROM event_history ORDER BY sequence"""
            ).fetchall()
            return [{
                "sequence": row[0], "event_type": row[1], "subject_id": row[2],
                "payload": json.loads(row[3]), "previous_hash": row[4],
                "event_hash": row[5], "created_at": row[6],
            } for row in rows]
        except (sqlite3.Error, ValueError):
            raise LeaseStateError("event history read failed") from None
        finally:
            db.close()

    def _anchor_connect(self):
        db = sqlite3.connect(self.anchor_path, timeout=5, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

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
        if (not isinstance(approval_ids, tuple) or len(approval_ids) != 2
                or any(not isinstance(v, str) or not v.strip() for v in approval_ids)
                or len(set(approval_ids)) != 2):
            raise ValueError("lease requires exactly two distinct approval identifiers")
        if not re.fullmatch(r"[0-9a-f]{64}", request_fingerprint):
            raise ValueError("request_fingerprint must be a lowercase SHA-256 hex digest")
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
            self._append_event(db, "LEASE_ISSUED", lease_id, {
                "resource_id": resource_id, "generation": generation,
                "approval_ids": list(approval_ids), "dispatch_nonce": dispatch_nonce,
                "request_fingerprint": request_fingerprint, "expires_at": expiry,
            })
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
            inserted = db.execute(
                "INSERT OR IGNORE INTO revoked_approvals VALUES(?,?)",
                (approval_id, datetime.now(timezone.utc).isoformat()),
            ).rowcount
            # A repeated revoke is an idempotent acknowledgement, not a new
            # fencing event. Only the first transition advances generations.
            if inserted:
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
                self._append_event(db, "APPROVAL_REVOKED", approval_id, {
                    "affected_resources": [item[0] for item in resources],
                })
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
            self._append_event(db, "DISPATCH_ACCEPTED", lease.lease_id, {
                "dispatch_nonce": nonce, "generation": generation,
                "request_fingerprint": fingerprint,
            })
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

    def create_recovery_checkpoint(self) -> dict[str, object]:
        """Create a state digest and advance a separate local anti-rollback anchor."""
        tables = {
            "resource_fences": "SELECT resource_id,generation FROM resource_fences ORDER BY resource_id",
            "revoked_approvals": "SELECT approval_id,revoked_at FROM revoked_approvals ORDER BY approval_id",
            "leases": "SELECT lease_id,resource_id,generation,dispatch_nonce,request_fingerprint,expires_at,state FROM leases ORDER BY lease_id",
            "lease_approvals": "SELECT lease_id,approval_id FROM lease_approvals ORDER BY lease_id,approval_id",
            "accepted_dispatches": "SELECT dispatch_nonce,lease_id,accepted_at FROM accepted_dispatches ORDER BY dispatch_nonce",
            "dispatch_outcomes": "SELECT lease_id,status,provider_operation_id,reason_code,updated_at FROM dispatch_outcomes ORDER BY lease_id",
            "event_history": "SELECT sequence,event_type,subject_id,payload_json,previous_hash,event_hash,created_at FROM event_history ORDER BY sequence",
        }
        db = self._connect()
        try:
            db.execute("BEGIN")
            state = {name: db.execute(query).fetchall() for name, query in tables.items()}
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise LeaseStateError("recovery checkpoint snapshot failed") from None
        finally:
            db.close()
        generations = [row[1] for row in state["resource_fences"]]
        generations.extend(row[2] for row in state["leases"])
        generation = max(generations, default=0)
        canonical = json.dumps(
            {"schema_version": 1, "generation_high_water": generation, "state": state},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        anchor = self._anchor_connect()
        try:
            anchor.execute("BEGIN IMMEDIATE")
            event_sequence = max(
                (row[0] for row in state["event_history"]), default=0
            )
            row = anchor.execute(
                """SELECT sequence,generation_high_water,event_sequence_high_water
                   FROM recovery_anchor WHERE singleton=1"""
            ).fetchone()
            previous_sequence, previous_generation, previous_event_sequence = (
                row if row else (0, 0, 0)
            )
            if generation < previous_generation or event_sequence < previous_event_sequence:
                anchor.execute("ROLLBACK")
                raise LeaseStateError("checkpoint state is below trusted recovery anchor")
            sequence = previous_sequence + 1
            checkpoint = {
                "schema_version": 1,
                "sequence": sequence,
                "generation_high_water": generation,
                "event_sequence_high_water": event_sequence,
                "state": state,
                "sha256": digest,
            }
            checkpoint_json = json.dumps(checkpoint, sort_keys=True, separators=(",", ":"))
            anchor.execute(
                """INSERT INTO recovery_anchor
                   (singleton,sequence,generation_high_water,checkpoint_sha256,checkpoint_json,event_sequence_high_water)
                   VALUES(1,?,?,?,?,?)
                   ON CONFLICT(singleton) DO UPDATE SET
                   sequence=excluded.sequence,
                   generation_high_water=excluded.generation_high_water,
                   checkpoint_sha256=excluded.checkpoint_sha256,
                   checkpoint_json=excluded.checkpoint_json,
                   event_sequence_high_water=excluded.event_sequence_high_water""",
                (sequence, generation, digest, checkpoint_json, event_sequence),
            )
            anchor.execute("COMMIT")
        except sqlite3.Error:
            if anchor.in_transaction:
                anchor.execute("ROLLBACK")
            raise LeaseStateError("recovery anchor update failed") from None
        finally:
            anchor.close()
        return checkpoint

    def get_latest_recovery_checkpoint(self) -> dict[str, object] | None:
        """Recover the exact checkpoint if a caller lost the post-commit response."""
        anchor = self._anchor_connect()
        try:
            row = anchor.execute(
                "SELECT checkpoint_json FROM recovery_anchor WHERE singleton=1"
            ).fetchone()
            if row is None or row[0] is None:
                return None
            checkpoint = json.loads(row[0])
            return checkpoint if self.verify_recovery_checkpoint(checkpoint) else None
        except (sqlite3.Error, ValueError, TypeError):
            return None
        finally:
            anchor.close()

    def verify_recovery_checkpoint(self, checkpoint: dict[str, object]) -> bool:
        """Verify integrity and freshness against the separate local anchor."""
        if not isinstance(checkpoint, dict) or checkpoint.get("schema_version") != 1:
            return False
        state = checkpoint.get("state")
        generation = checkpoint.get("generation_high_water")
        event_sequence = checkpoint.get("event_sequence_high_water")
        sequence = checkpoint.get("sequence")
        digest = checkpoint.get("sha256")
        if (not isinstance(state, dict) or not isinstance(generation, int)
                or not isinstance(event_sequence, int) or not isinstance(sequence, int)
                or not isinstance(digest, str)):
            return False
        canonical = json.dumps(
            {"schema_version": 1, "generation_high_water": generation, "state": state},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        calculated = hashlib.sha256(canonical).hexdigest()
        if not hmac.compare_digest(calculated, digest):
            return False
        anchor = self._anchor_connect()
        try:
            row = anchor.execute(
                """SELECT sequence,generation_high_water,event_sequence_high_water,
                          checkpoint_sha256 FROM recovery_anchor WHERE singleton=1"""
            ).fetchone()
            return row == (sequence, generation, event_sequence, digest)
        except sqlite3.Error:
            return False
        finally:
            anchor.close()

    def get_dispatch_state(self, dispatch_nonce: str) -> dict[str, str | int | None] | None:
        """Read-only local reconciliation lookup; never retries or dispatches."""
        if not isinstance(dispatch_nonce, str) or not dispatch_nonce.strip():
            raise ValueError("dispatch_nonce must be non-empty")
        db = self._connect()
        try:
            row = db.execute(
                """SELECT l.lease_id,l.resource_id,l.generation,l.request_fingerprint,
                          l.expires_at,l.state,o.status,o.provider_operation_id,o.reason_code
                   FROM leases l
                   LEFT JOIN dispatch_outcomes o ON o.lease_id=l.lease_id
                   WHERE l.dispatch_nonce=?""",
                (dispatch_nonce,),
            ).fetchone()
            if row is None:
                return None
            return {
                "lease_id": row[0],
                "resource_id": row[1],
                "generation": row[2],
                "request_fingerprint": row[3],
                "expires_at": row[4],
                "lease_state": row[5],
                "outcome_state": row[6],
                "provider_operation_id": row[7],
                "reason_code": row[8],
            }
        except sqlite3.Error:
            raise LeaseStateError("dispatch state lookup failed") from None
        finally:
            db.close()

    def mark_indeterminate(self, lease_id: str, *, reason_code: str) -> bool:
        """Record an accepted dispatch whose remote outcome is unknown; never retry it."""
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise ValueError("lease_id must be non-empty")
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise ValueError("reason_code must be non-empty")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if row is None or row[0] != "ACCEPTED":
                db.execute("ROLLBACK")
                return False
            stamp = datetime.now(timezone.utc).isoformat()
            db.execute(
                "INSERT INTO dispatch_outcomes VALUES(?,?,?,?,?)",
                (lease_id, "INDETERMINATE", None, reason_code, stamp),
            )
            db.execute("UPDATE leases SET state='INDETERMINATE' WHERE lease_id=?", (lease_id,))
            self._append_event(db, "DISPATCH_INDETERMINATE", lease_id, {
                "reason_code": reason_code,
            })
            db.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise LeaseStateError("indeterminate dispatch recording failed") from None
        finally:
            db.close()

    def reconcile_dispatch(
        self, lease_id: str, *, provider_operation_id: str, outcome: str,
    ) -> bool:
        """Resolve an indeterminate dispatch from provider evidence; this never dispatches."""
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise ValueError("lease_id must be non-empty")
        if not isinstance(provider_operation_id, str) or not provider_operation_id.strip():
            raise ValueError("provider_operation_id must be non-empty")
        if outcome not in ("SUCCEEDED", "REJECTED"):
            raise ValueError("outcome must be SUCCEEDED or REJECTED")
        terminal = "COMPLETED" if outcome == "SUCCEEDED" else "FAILED"
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,provider_operation_id FROM dispatch_outcomes WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                return False
            if row[0] in ("COMPLETED", "FAILED"):
                same = row == (terminal, provider_operation_id)
                db.execute("ROLLBACK")
                return same
            if row[0] != "INDETERMINATE":
                db.execute("ROLLBACK")
                return False
            stamp = datetime.now(timezone.utc).isoformat()
            db.execute(
                "UPDATE dispatch_outcomes SET status=?,provider_operation_id=?,updated_at=? WHERE lease_id=?",
                (terminal, provider_operation_id, stamp, lease_id),
            )
            db.execute("UPDATE leases SET state=? WHERE lease_id=?", (terminal, lease_id))
            self._append_event(db, "DISPATCH_RECONCILED", lease_id, {
                "provider_operation_id": provider_operation_id, "outcome": outcome,
            })
            db.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise LeaseStateError("dispatch reconciliation failed") from None
        finally:
            db.close()

