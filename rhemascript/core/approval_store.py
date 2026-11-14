"""Durable SQLite approval replay/revocation store.

This is a standalone approval-state database, deliberately separate from RAEI's
learning EvidenceStore and JSON ledger. It stores no credentials or signing keys.
The parent directory must already be owner-only (0700 or stricter).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import re

from rhemascript.core.approvals import VerifiedApproval, is_verified_approval


class ApprovalStoreError(RuntimeError):
    """Safe, non-secret-bearing approval persistence error."""


class SQLiteApprovalConsumptionStore:
    """Durable atomic approval consumption and revocation using SQLite."""

    def __init__(self, path: str | os.PathLike[str], *, timeout_seconds: float = 5.0):
        if os.name != "posix":
            raise ApprovalStoreError("built-in approval store requires POSIX file permissions")
        if (not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool)
                or not math.isfinite(timeout_seconds) or not 0.1 <= timeout_seconds <= 30):
            raise ValueError("timeout_seconds must be between 0.1 and 30")
        self.path = Path(path).expanduser()
        self.timeout_seconds = float(timeout_seconds)
        self._validate_parent()
        self._prepare_database()
        self._initialize_schema()

    def _validate_parent(self) -> None:
        absolute = self.path.absolute()
        current = Path(absolute.anchor)
        try:
            for component in absolute.parts[1:-1]:
                current = current / component
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise ApprovalStoreError("approval database path must not contain symlinked directories")
            info = self.path.parent.lstat()
            actual = self.path.parent.stat()
        except ApprovalStoreError:
            raise
        except OSError:
            raise ApprovalStoreError("approval database parent directory must already exist") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(actual.st_mode):
            raise ApprovalStoreError("approval database parent must be a real directory")
        if actual.st_uid != os.getuid() or stat.S_IMODE(actual.st_mode) & 0o077:
            raise ApprovalStoreError("approval database parent must be owner-owned and private (0700 or stricter)")

    def _prepare_database(self) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        except FileExistsError:
            try:
                info = self.path.lstat()
            except OSError:
                raise ApprovalStoreError("approval database is inaccessible") from None
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                raise ApprovalStoreError("approval database must be an owner-owned private regular file")
        except OSError:
            raise ApprovalStoreError("approval database could not be created safely") from None

    def _connect(self) -> sqlite3.Connection:
        self._validate_parent()
        try:
            info = self.path.lstat()
        except OSError:
            raise ApprovalStoreError("approval database is missing or inaccessible") from None
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ApprovalStoreError("approval database permissions or file type are unsafe")
        try:
            db = sqlite3.connect(
                self.path, timeout=self.timeout_seconds, isolation_level=None,
            )
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            os.chmod(self.path, 0o600)
            return db
        except (OSError, sqlite3.Error):
            raise ApprovalStoreError("approval database could not be opened safely") from None

    def _initialize_schema(self) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    approval_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    issuer TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    project_version TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    artifact_id TEXT,
                    artifact_version TEXT,
                    artifact_sha256 TEXT,
                    artifact_size_bytes INTEGER,
                    credential_schema TEXT,
                    signature TEXT,
                    identity_claims_json TEXT
                )
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(consumed_approvals)")}
            for name, sql_type in (
                ("artifact_id", "TEXT"), ("artifact_version", "TEXT"),
                ("artifact_sha256", "TEXT"), ("artifact_size_bytes", "INTEGER"),
                ("credential_schema", "TEXT"), ("signature", "TEXT"),
                ("identity_claims_json", "TEXT"),
            ):
                if name not in columns:
                    db.execute(f"ALTER TABLE consumed_approvals ADD COLUMN {name} {sql_type}")
            db.execute("""
                CREATE TABLE IF NOT EXISTS revoked_approvals (
                    approval_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    revoked_by TEXT NOT NULL
                )
            """)
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("approval database schema could not be initialized") from None
        finally:
            db.close()

    @staticmethod
    def _utc(value: datetime) -> str:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat()

    def consume_many_once(self, entries: tuple[VerifiedApproval, ...]) -> bool:
        """Consume only exact verifier-issued approval objects, atomically."""
        if not isinstance(entries, tuple) or not entries:
            return False
        if any(not is_verified_approval(item) for item in entries):
            raise ApprovalStoreError("approval consumption requires verifier-issued approval objects")
        return self._consume_many_once(entries)

    def _consume_many_once(self, entries: tuple[VerifiedApproval, ...]) -> bool:
        """Private transaction primitive; callers must use consume_many_once."""
        if not isinstance(entries, tuple) or not entries:
            return False
        normalized = []
        for item in entries:
            if not isinstance(item, VerifiedApproval):
                return False
            values = (
                item.approval_id, item.nonce, item.issuer, item.actor_id, item.action,
                item.project_id, item.project_version, item.request_id, item.key_id,
            )
            if any(not isinstance(value, str) or not value.strip() for value in values):
                return False
            try:
                issued_at = self._utc(item.issued_at)
                expires_at = self._utc(item.expires_at)
            except ValueError:
                return False
            artifact_values = (
                item.artifact_id, item.artifact_version,
                item.artifact_sha256, item.artifact_size_bytes,
            )
            if any(value is not None for value in artifact_values):
                if (not all(isinstance(value, str) and value.strip() for value in artifact_values[:3])
                        or not isinstance(artifact_values[3], int)
                        or isinstance(artifact_values[3], bool) or artifact_values[3] <= 0):
                    return False
            credential_schema, signature = item.credential_schema, item.signature
            if (credential_schema is None) != (signature is None):
                return False
            if credential_schema is not None:
                if (credential_schema not in {
                    "RhemaScript.ApprovalCredential.v1",
                    "RhemaScript.ApprovalCredential.v2",
                    "RhemaScript.ApprovalCredential.v3",
                } or not isinstance(signature, str)
                        or len(signature) != 128
                        or any(ch not in "0123456789abcdef" for ch in signature)):
                    return False
            identity_values = (
                item.subject_id, item.actor_role, item.authn_context,
                self._utc(item.authenticated_at) if item.authenticated_at is not None else None,
                item.identity_session_id, item.identity_policy_version, item.identity_provider_id,
            )
            if credential_schema == "RhemaScript.ApprovalCredential.v3":
                if any(not isinstance(value, str) or not value.strip() for value in identity_values):
                    return False
            elif any(value is not None for value in identity_values):
                return False
            identity_json = json.dumps(dict(zip((
                "subject_id", "actor_role", "authn_context", "authenticated_at",
                "identity_session_id", "identity_policy_version", "identity_provider_id",
            ), identity_values)), sort_keys=True, separators=(",", ":"))
            normalized.append((
                item.approval_id, item.nonce, item.issuer, item.actor_id, item.action,
                item.project_id, item.project_version, item.request_id, issued_at,
                expires_at, item.key_id, *artifact_values, credential_schema, signature, identity_json,
            ))
        if (len({item[0] for item in normalized}) != len(normalized)
                or len({item[1] for item in normalized}) != len(normalized)):
            return False

        now = datetime.now(timezone.utc)
        if any(datetime.fromisoformat(item[9]) <= now for item in normalized):
            return False
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            # BEGIN IMMEDIATE may wait for another writer. Recheck expiry only
            # after the write lock is acquired so a credential cannot expire
            # while queued and then be consumed using the earlier timestamp.
            transaction_now = datetime.now(timezone.utc)
            if any(datetime.fromisoformat(item[9]) <= transaction_now for item in normalized):
                db.execute("ROLLBACK")
                return False
            for entry in normalized:
                approval_id, nonce = entry[0], entry[1]
                row = db.execute(
                    "SELECT 1 FROM revoked_approvals WHERE approval_id=? OR nonce=?",
                    (approval_id, nonce),
                ).fetchone()
                if row:
                    db.execute("ROLLBACK")
                    return False
            consumed_at = self._utc(transaction_now)
            db.executemany(
                """INSERT INTO consumed_approvals(
                    approval_id, nonce, issuer, actor_id, action, project_id,
                    project_version, request_id, issued_at, expires_at, key_id,
                    consumed_at, artifact_id, artifact_version, artifact_sha256,
                    artifact_size_bytes, credential_schema, signature, identity_claims_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [( *entry[:11], consumed_at, *entry[11:] ) for entry in normalized],
            )
            db.execute("COMMIT")
            os.chmod(self.path, 0o600)
            return True
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("approval batch could not be committed atomically") from None
        finally:
            db.close()

    def revoke(self, approval_id: str, nonce: str, *, revoked_by: str, reason: str) -> None:
        """Record an actor-attributed revocation; consumed approvals remain consumed."""
        if (not isinstance(approval_id, str) or not approval_id.strip()
                or not isinstance(nonce, str) or not nonce.strip()
                or not isinstance(revoked_by, str) or not revoked_by.strip()
                or not isinstance(reason, str) or not reason.strip()
                or len(reason) > 256 or len(revoked_by) > 128):
            raise ValueError("approval ID, nonce, revoking actor and a short reason are required")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO revoked_approvals(approval_id, nonce, revoked_at, reason, revoked_by) VALUES (?, ?, ?, ?, ?)",
                (approval_id, nonce, self._utc(datetime.now(timezone.utc)), reason, revoked_by),
            )
            db.execute("COMMIT")
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("approval is already revoked or conflicts with another revocation") from None
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("approval revocation could not be committed") from None
        finally:
            db.close()


    def list_consumed_approval_records(self) -> list[dict[str, object]]:
        """Return detached persisted credential records for offline signature audit."""
        columns = (
            "approval_id", "nonce", "issuer", "actor_id", "action", "project_id",
            "project_version", "request_id", "issued_at", "expires_at", "key_id",
            "consumed_at", "artifact_id", "artifact_version", "artifact_sha256",
            "artifact_size_bytes", "credential_schema", "signature", "identity_claims_json",
        )
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT " + ", ".join(columns) + " FROM consumed_approvals ORDER BY consumed_at, approval_id"
            ).fetchall()
            records = [dict(zip(columns, row)) for row in rows]
            for record in records:
                try:
                    identity = json.loads(record.pop("identity_claims_json") or "{}")
                    if isinstance(identity, dict):
                        record.update(identity)
                except (TypeError, json.JSONDecodeError):
                    raise ApprovalStoreError("persisted identity assurance claims are malformed") from None
            return records
        except sqlite3.Error:
            raise ApprovalStoreError("persisted approval records could not be read") from None
        finally:
            db.close()

    def is_consumed(self, approval_id: str, nonce: str) -> bool:
        db = self._connect()
        try:
            return db.execute(
                "SELECT 1 FROM consumed_approvals WHERE approval_id=? OR nonce=?",
                (approval_id, nonce),
            ).fetchone() is not None
        except sqlite3.Error:
            raise ApprovalStoreError("approval consumption state could not be read") from None
        finally:
            db.close()

    def is_revoked(self, approval_id: str, nonce: str) -> bool:
        db = self._connect()
        try:
            return db.execute(
                "SELECT 1 FROM revoked_approvals WHERE approval_id=? OR nonce=?",
                (approval_id, nonce),
            ).fetchone() is not None
        except sqlite3.Error:
            raise ApprovalStoreError("approval revocation state could not be read") from None
        finally:
            db.close()

    def _snapshot_bytes(self) -> bytes:
        db = self._connect()
        try:
            # Read both state tables from one database snapshot. Without an
            # explicit transaction a concurrent consume/revoke can commit
            # between SELECTs and create a checkpoint for a mixed state.
            db.execute("BEGIN")
            consumed = db.execute(
                """SELECT approval_id, nonce, issuer, actor_id, action, project_id,
                          project_version, request_id, issued_at, expires_at, key_id,
                          consumed_at, artifact_id, artifact_version, artifact_sha256,
                          artifact_size_bytes, credential_schema, signature,
                          identity_claims_json
                   FROM consumed_approvals ORDER BY approval_id"""
            ).fetchall()
            revoked = db.execute(
                """SELECT approval_id, nonce, revoked_at, reason, revoked_by
                   FROM revoked_approvals ORDER BY approval_id"""
            ).fetchall()
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise ApprovalStoreError("approval state snapshot could not be read") from None
        finally:
            db.close()
        payload = {
            "schema": "RhemaScript.ApprovalStateCheckpoint.v3",
            "consumed": [list(row) for row in consumed],
            "revoked": [list(row) for row in revoked],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")

    def checkpoint(self, key: bytes) -> dict[str, str]:
        """Create an HMAC checkpoint; retain it outside this database."""
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        payload = self._snapshot_bytes()
        return {
            "schema": "RhemaScript.ApprovalStateCheckpoint.v3",
            "snapshot_sha256": hashlib.sha256(payload).hexdigest(),
            "hmac_sha256": hmac.new(key, payload, hashlib.sha256).hexdigest(),
        }

    def verify_checkpoint(self, checkpoint: object, key: bytes) -> bool:
        if not isinstance(key, bytes) or len(key) < 32 or not isinstance(checkpoint, dict):
            return False
        if set(checkpoint) != {"schema", "snapshot_sha256", "hmac_sha256"}:
            return False
        if checkpoint.get("schema") != "RhemaScript.ApprovalStateCheckpoint.v3":
            return False
        try:
            expected = self.checkpoint(key)
        except (ApprovalStoreError, ValueError):
            return False
        return (
            hmac.compare_digest(str(checkpoint.get("snapshot_sha256", "")), expected["snapshot_sha256"])
            and hmac.compare_digest(str(checkpoint.get("hmac_sha256", "")), expected["hmac_sha256"])
        )

    def backup_to(self, destination: str | os.PathLike[str]) -> Path:
        """Create an owner-only SQLite backup in an already-private directory."""
        target = Path(destination).expanduser()
        try:
            absolute = target.absolute()
            current = Path(absolute.anchor)
            for component in absolute.parts[1:-1]:
                current = current / component
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise ApprovalStoreError("backup path must not contain symlinked directories")
            parent_info = target.parent.lstat()
            parent_stat = target.parent.stat()
        except ApprovalStoreError:
            raise
        except OSError:
            raise ApprovalStoreError("backup parent directory must already exist") from None
        if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077):
            raise ApprovalStoreError("backup parent directory must be owner-owned and private")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        except OSError:
            raise ApprovalStoreError("approval backup destination could not be created safely") from None
        source = self._connect()
        destination_db = None
        try:
            destination_db = sqlite3.connect(target)
            source.backup(destination_db)
            destination_db.close()
            destination_db = None
            os.chmod(target, 0o600)
            return target
        except (OSError, sqlite3.Error):
            if destination_db is not None:
                destination_db.close()
            try:
                target.unlink()
            except OSError:
                pass
            raise ApprovalStoreError("approval database backup failed") from None
        finally:
            source.close()


class SQLitePublishSessionRegistry(SQLiteApprovalConsumptionStore):
    """Durable one-session-per-request registry sharing the approval-state database.

    Only the SHA-256 digest of the provider's bearer session URL is persisted.
    All transitions are serialized with BEGIN IMMEDIATE and included in the
    V4 approval-state checkpoint.
    """

    _SESSION_COLUMNS = (
        "project_id", "project_version", "request_id", "approval_fingerprint",
        "artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes",
        "session_url_sha256", "state", "acknowledged_offset", "inflight_start",
        "inflight_end", "inflight_owner", "lease_expires_at", "created_at", "updated_at",
    )
    _SESSION_STATES = {
        "CREATING", "ACTIVE", "CHUNK_IN_FLIGHT", "RECONCILING",
        "INDETERMINATE", "COMPLETE", "FAILED",
    }

    @staticmethod
    def _digest_text(value: object, field: str) -> str:
        if (not isinstance(value, str) or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)):
            raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _session_identity(project_id: str, project_version: str, request_id: str,
                          approval_fingerprint: str, artifact_id: str,
                          artifact_version: str, artifact_sha256: str,
                          artifact_size_bytes: int) -> tuple:
        values = (project_id, project_version, request_id, artifact_id, artifact_version)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("publish-session identity fields must be non-empty strings")
        fingerprint = SQLitePublishSessionRegistry._digest_text(
            approval_fingerprint, "approval_fingerprint"
        )
        digest = SQLitePublishSessionRegistry._digest_text(artifact_sha256, "artifact_sha256")
        if (not isinstance(artifact_size_bytes, int) or isinstance(artifact_size_bytes, bool)
                or artifact_size_bytes <= 0):
            raise ValueError("artifact_size_bytes must be a positive integer")
        return (*values[:3], fingerprint, *values[3:], digest, artifact_size_bytes)

    def _initialize_schema(self) -> None:
        super()._initialize_schema()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                CREATE TABLE IF NOT EXISTS publish_sessions (
                    project_id TEXT NOT NULL,
                    project_version TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    approval_fingerprint TEXT NOT NULL UNIQUE,
                    artifact_id TEXT NOT NULL,
                    artifact_version TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    artifact_size_bytes INTEGER NOT NULL CHECK (artifact_size_bytes > 0),
                    session_url_sha256 TEXT UNIQUE,
                    state TEXT NOT NULL CHECK (state IN (
                        'CREATING', 'ACTIVE', 'CHUNK_IN_FLIGHT', 'RECONCILING',
                        'INDETERMINATE', 'COMPLETE', 'FAILED'
                    )),
                    acknowledged_offset INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_offset >= 0),
                    inflight_start INTEGER,
                    inflight_end INTEGER,
                    inflight_owner TEXT,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, project_version, request_id)
                )
            """)
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session registry schema could not be initialized") from None
        finally:
            db.close()

    def reserve_publish_session(self, *, project_id: str, project_version: str,
                                request_id: str, approval_fingerprint: str,
                                artifact_id: str, artifact_version: str,
                                artifact_sha256: str, artifact_size_bytes: int,
                                owner_id: str, lease_seconds: float = 60.0) -> bool:
        identity = self._session_identity(
            project_id, project_version, request_id, approval_fingerprint,
            artifact_id, artifact_version, artifact_sha256, artifact_size_bytes,
        )
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id must be non-empty")
        if (not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool)
                or not math.isfinite(lease_seconds) or not 1 <= lease_seconds <= 600):
            raise ValueError("lease_seconds must be finite and between 1 and 600")
        now = datetime.now(timezone.utc)
        created = self._utc(now)
        lease = self._utc(now + timedelta(seconds=lease_seconds))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                INSERT INTO publish_sessions(
                    project_id, project_version, request_id, approval_fingerprint,
                    artifact_id, artifact_version, artifact_sha256, artifact_size_bytes,
                    session_url_sha256, state, acknowledged_offset, inflight_start,
                    inflight_end, inflight_owner, lease_expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'CREATING', 0, NULL, NULL, ?, ?, ?, ?)
            """, (*identity, owner_id, lease, created, created))
            db.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish session could not be reserved atomically") from None
        finally:
            db.close()

    def bind_publish_session(self, *, project_id: str, project_version: str,
                             request_id: str, approval_fingerprint: str,
                             artifact_id: str, artifact_version: str,
                             artifact_sha256: str, artifact_size_bytes: int,
                             session_url_sha256: str, owner_id: str) -> bool:
        identity = self._session_identity(
            project_id, project_version, request_id, approval_fingerprint,
            artifact_id, artifact_version, artifact_sha256, artifact_size_bytes,
        )
        url_digest = self._digest_text(session_url_sha256, "session_url_sha256")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id must be non-empty")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("""
                UPDATE publish_sessions
                   SET session_url_sha256=?, state='ACTIVE',
                       updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
                   AND approval_fingerprint=? AND artifact_id=? AND artifact_version=?
                   AND artifact_sha256=? AND artifact_size_bytes=?
                   AND state='CREATING' AND inflight_owner=?
            """, (url_digest, self._utc(datetime.now(timezone.utc)), *identity, owner_id))
            db.execute("COMMIT")
            return cursor.rowcount == 1
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.execute("ROLLBACK")
            return False
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish session URL binding could not be committed") from None
        finally:
            db.close()

    def _begin_session_operation(self, *, project_id: str, project_version: str,
                                 request_id: str, approval_fingerprint: str,
                                 artifact_id: str, artifact_version: str,
                                 artifact_sha256: str, artifact_size_bytes: int,
                                 session_url_sha256: str, owner_id: str,
                                 lease_seconds: float, start: int | None,
                                 end: int | None, reconciliation: bool) -> bool:
        identity = self._session_identity(
            project_id, project_version, request_id, approval_fingerprint,
            artifact_id, artifact_version, artifact_sha256, artifact_size_bytes,
        )
        url_digest = self._digest_text(session_url_sha256, "session_url_sha256")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id must be non-empty")
        if (not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool)
                or not math.isfinite(lease_seconds) or not 1 <= lease_seconds <= 600):
            raise ValueError("lease_seconds must be finite and between 1 and 600")
        if reconciliation:
            if start is not None or end is not None:
                raise ValueError("status reconciliation must not include a chunk range")
        elif (not isinstance(start, int) or isinstance(start, bool)
              or not isinstance(end, int) or isinstance(end, bool)
              or start < 0 or end < start or end >= artifact_size_bytes):
            raise ValueError("chunk byte range is invalid")
        now = datetime.now(timezone.utc)
        now_text = self._utc(now)
        lease = self._utc(now + timedelta(seconds=lease_seconds))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT state, session_url_sha256, acknowledged_offset,
                       inflight_start, inflight_end, lease_expires_at, inflight_owner
                  FROM publish_sessions
                 WHERE project_id=? AND project_version=? AND request_id=?
                   AND approval_fingerprint=? AND artifact_id=? AND artifact_version=?
                   AND artifact_sha256=? AND artifact_size_bytes=?
            """, identity).fetchone()
            if row is None or row[1] != url_digest:
                db.execute("ROLLBACK")
                return False
            state, _stored_url, acknowledged, old_start, old_end, old_lease, old_owner = row
            if reconciliation:
                stale = False
                if state in {"CHUNK_IN_FLIGHT", "RECONCILING"} and old_lease:
                    try:
                        stale = datetime.fromisoformat(old_lease) <= now
                    except ValueError:
                        stale = False
                stale_active_owner = False
                if state == "ACTIVE" and old_owner is not None and old_lease:
                    try:
                        stale_active_owner = datetime.fromisoformat(old_lease) <= now
                    except ValueError:
                        stale_active_owner = False
                active_idle = (
                    state == "ACTIVE" and old_owner is None
                    and old_start is None and old_end is None
                )
                if (state != "INDETERMINATE" and not stale and not active_idle
                        and not stale_active_owner):
                    db.execute("ROLLBACK")
                    return False
                new_state, new_start, new_end = "RECONCILING", old_start, old_end
            else:
                if (state != "ACTIVE" or start != acknowledged
                        or old_owner is not None or old_start is not None or old_end is not None):
                    db.execute("ROLLBACK")
                    return False
                new_state, new_start, new_end = "CHUNK_IN_FLIGHT", start, end
            db.execute("""
                UPDATE publish_sessions
                   SET state=?, inflight_start=?, inflight_end=?, inflight_owner=?,
                       lease_expires_at=?, updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
            """, (new_state, new_start, new_end, owner_id, lease, now_text, *identity[:3]))
            db.execute("COMMIT")
            return True
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session operation could not be claimed atomically") from None
        finally:
            db.close()

    def begin_publish_chunk(self, *, project_id: str, project_version: str,
                            request_id: str, approval_fingerprint: str,
                            artifact_id: str, artifact_version: str,
                            artifact_sha256: str, artifact_size_bytes: int,
                            session_url_sha256: str, owner_id: str,
                            start: int, end: int, total: int,
                            body_size: int, lease_seconds: float = 60.0) -> bool:
        if total != artifact_size_bytes or body_size != end - start + 1:
            return False
        return self._begin_session_operation(
            project_id=project_id, project_version=project_version, request_id=request_id,
            approval_fingerprint=approval_fingerprint, artifact_id=artifact_id,
            artifact_version=artifact_version, artifact_sha256=artifact_sha256,
            artifact_size_bytes=artifact_size_bytes, session_url_sha256=session_url_sha256,
            owner_id=owner_id, lease_seconds=lease_seconds, start=start, end=end,
            reconciliation=False,
        )

    def begin_publish_reconciliation(self, *, project_id: str, project_version: str,
                                     request_id: str, approval_fingerprint: str,
                                     artifact_id: str, artifact_version: str,
                                     artifact_sha256: str, artifact_size_bytes: int,
                                     session_url_sha256: str, owner_id: str,
                                     total: int, lease_seconds: float = 60.0) -> bool:
        if total != artifact_size_bytes:
            return False
        return self._begin_session_operation(
            project_id=project_id, project_version=project_version, request_id=request_id,
            approval_fingerprint=approval_fingerprint, artifact_id=artifact_id,
            artifact_version=artifact_version, artifact_sha256=artifact_sha256,
            artifact_size_bytes=artifact_size_bytes, session_url_sha256=session_url_sha256,
            owner_id=owner_id, lease_seconds=lease_seconds, start=None, end=None,
            reconciliation=True,
        )

    def record_publish_response(self, *, project_id: str, project_version: str,
                                request_id: str, owner_id: str, status: int,
                                range_header: str | None = None) -> bool:
        if (not isinstance(status, int) or isinstance(status, bool)
                or not 100 <= status <= 599):
            raise ValueError("provider status must be an HTTP status integer")
        if range_header is not None and not isinstance(range_header, str):
            raise ValueError("provider Range header must be a string")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT state, acknowledged_offset, inflight_start, inflight_end,
                       artifact_size_bytes, inflight_owner
                  FROM publish_sessions
                 WHERE project_id=? AND project_version=? AND request_id=?
            """, (project_id, project_version, request_id)).fetchone()
            if row is None or row[5] != owner_id or row[0] not in {"CHUNK_IN_FLIGHT", "RECONCILING"}:
                db.execute("ROLLBACK")
                return False
            state, acknowledged, start, end, total, _owner = row
            new_offset = acknowledged
            new_state = "ACTIVE"
            if status in (200, 201):
                new_state, new_offset = "COMPLETE", total
            elif status == 308:
                if range_header:
                    match = re.fullmatch(r"bytes=0-(\d+)", range_header.strip())
                    if match is None:
                        new_state = "INDETERMINATE"
                    else:
                        new_offset = int(match.group(1)) + 1
                        if (new_offset < acknowledged or new_offset > total
                                or (end is not None and new_offset > end + 1)
                                or (end is None and new_offset != acknowledged)):
                            new_state, new_offset = "INDETERMINATE", acknowledged
                if new_state != "INDETERMINATE":
                    new_state = "ACTIVE"
            elif status in (404, 410):
                new_state = "FAILED"
            elif status >= 500:
                new_state = "INDETERMINATE"
            retained_owner = None if new_state == "INDETERMINATE" else owner_id
            retain_range = new_state in {"ACTIVE", "INDETERMINATE"}
            retained_start = start if retain_range else None
            retained_end = end if retain_range else None
            db.execute("""
                UPDATE publish_sessions
                   SET state=?, acknowledged_offset=?, inflight_start=?,
                       inflight_end=?, inflight_owner=?,
                       lease_expires_at=CASE WHEN ?='INDETERMINATE' THEN NULL ELSE lease_expires_at END,
                       updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
            """, (new_state, new_offset, retained_start, retained_end, retained_owner,
                  new_state, self._utc(datetime.now(timezone.utc)), project_id, project_version, request_id))
            db.execute("COMMIT")
            return new_state != "INDETERMINATE"
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session acknowledgement could not be committed") from None
        finally:
            db.close()

    def mark_publish_session_indeterminate(self, *, project_id: str,
                                           project_version: str, request_id: str,
                                           owner_id: str) -> bool:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("""
                UPDATE publish_sessions
                   SET state='INDETERMINATE', inflight_owner=NULL,
                       lease_expires_at=NULL, updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
                   AND inflight_owner=? AND state IN ('CREATING','ACTIVE','CHUNK_IN_FLIGHT','RECONCILING')
            """, (self._utc(datetime.now(timezone.utc)), project_id, project_version,
                  request_id, owner_id))
            db.execute("COMMIT")
            return cursor.rowcount == 1
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session indeterminate state could not be recorded") from None
        finally:
            db.close()

    def finalize_publish_session_operation(self, *, project_id: str,
                                            project_version: str, request_id: str,
                                            owner_id: str) -> bool:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("""
                UPDATE publish_sessions
                   SET inflight_start=NULL, inflight_end=NULL,
                       inflight_owner=NULL, lease_expires_at=NULL, updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
                   AND inflight_owner=? AND state IN ('ACTIVE','COMPLETE','FAILED')
            """, (self._utc(datetime.now(timezone.utc)), project_id, project_version,
                  request_id, owner_id))
            db.execute("COMMIT")
            return cursor.rowcount == 1
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session operation finalization failed") from None
        finally:
            db.close()

    def mark_publish_session_failed(self, *, project_id: str,
                                    project_version: str, request_id: str,
                                    owner_id: str) -> bool:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("""
                UPDATE publish_sessions
                   SET state='FAILED', inflight_owner=NULL, lease_expires_at=NULL,
                       updated_at=?
                 WHERE project_id=? AND project_version=? AND request_id=?
                   AND inflight_owner=? AND state='CREATING'
            """, (self._utc(datetime.now(timezone.utc)), project_id, project_version,
                  request_id, owner_id))
            db.execute("COMMIT")
            return cursor.rowcount == 1
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("publish-session failure state could not be recorded") from None
        finally:
            db.close()

    def get_publish_session(self, *, project_id: str,
                            project_version: str, request_id: str) -> dict[str, object] | None:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT " + ", ".join(self._SESSION_COLUMNS)
                + " FROM publish_sessions WHERE project_id=? AND project_version=? AND request_id=?",
                (project_id, project_version, request_id),
            ).fetchone()
            return dict(zip(self._SESSION_COLUMNS, row)) if row else None
        except sqlite3.Error:
            raise ApprovalStoreError("publish-session state could not be read") from None
        finally:
            db.close()

    def list_publish_session_records(self) -> list[dict[str, object]]:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT " + ", ".join(self._SESSION_COLUMNS)
                + " FROM publish_sessions ORDER BY created_at, request_id"
            ).fetchall()
            return [dict(zip(self._SESSION_COLUMNS, row)) for row in rows]
        except sqlite3.Error:
            raise ApprovalStoreError("publish-session records could not be read") from None
        finally:
            db.close()

    def _snapshot_bytes(self) -> bytes:
        """Read approvals, revocations and publish sessions from one SQLite snapshot."""
        db = self._connect()
        try:
            db.execute("BEGIN")
            consumed = db.execute(
                """SELECT approval_id, nonce, issuer, actor_id, action, project_id,
                          project_version, request_id, issued_at, expires_at, key_id,
                          consumed_at, artifact_id, artifact_version, artifact_sha256,
                          artifact_size_bytes, credential_schema, signature,
                          identity_claims_json
                   FROM consumed_approvals ORDER BY approval_id"""
            ).fetchall()
            revoked = db.execute(
                """SELECT approval_id, nonce, revoked_at, reason, revoked_by
                   FROM revoked_approvals ORDER BY approval_id"""
            ).fetchall()
            sessions = db.execute(
                "SELECT " + ", ".join(self._SESSION_COLUMNS)
                + " FROM publish_sessions ORDER BY project_id, project_version, request_id"
            ).fetchall()
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise ApprovalStoreError("approval and publish-session checkpoint snapshot could not be read") from None
        finally:
            db.close()
        payload = {
            "schema": "RhemaScript.ApprovalStateCheckpoint.v4",
            "consumed": [list(row) for row in consumed],
            "revoked": [list(row) for row in revoked],
            "publish_sessions": [list(row) for row in sessions],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")

    def checkpoint(self, key: bytes) -> dict[str, str]:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        payload = self._snapshot_bytes()
        return {
            "schema": "RhemaScript.ApprovalStateCheckpoint.v4",
            "snapshot_sha256": hashlib.sha256(payload).hexdigest(),
            "hmac_sha256": hmac.new(key, payload, hashlib.sha256).hexdigest(),
        }

    def verify_checkpoint(self, checkpoint: object, key: bytes) -> bool:
        if not isinstance(key, bytes) or len(key) < 32 or not isinstance(checkpoint, dict):
            return False
        if (set(checkpoint) != {"schema", "snapshot_sha256", "hmac_sha256"}
                or checkpoint.get("schema") != "RhemaScript.ApprovalStateCheckpoint.v4"):
            return False
        try:
            expected = self.checkpoint(key)
        except (ApprovalStoreError, ValueError):
            return False
        return (
            hmac.compare_digest(str(checkpoint.get("snapshot_sha256", "")), expected["snapshot_sha256"])
            and hmac.compare_digest(str(checkpoint.get("hmac_sha256", "")), expected["hmac_sha256"])
        )
