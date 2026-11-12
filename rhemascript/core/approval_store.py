"""Durable SQLite approval replay/revocation store.

This is a standalone approval-state database, deliberately separate from RAEI's
learning EvidenceStore and JSON ledger. It stores no credentials or signing keys.
The parent directory must already be owner-only (0700 or stricter).
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import stat

from rhemascript.core.approvals import VerifiedApproval


class ApprovalStoreError(RuntimeError):
    """Safe, non-secret-bearing approval persistence error."""


class SQLiteApprovalConsumptionStore:
    """Durable atomic approval consumption and revocation using SQLite."""

    def __init__(self, path: str | os.PathLike[str], *, timeout_seconds: float = 5.0):
        if os.name != "posix":
            raise ApprovalStoreError("built-in approval store requires POSIX file permissions")
        if not isinstance(timeout_seconds, (int, float)) or not 0.1 <= timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0.1 and 30")
        self.path = Path(path).expanduser()
        self.timeout_seconds = float(timeout_seconds)
        self._validate_parent()
        self._prepare_database()
        self._initialize_schema()

    def _validate_parent(self) -> None:
        try:
            info = self.path.parent.lstat()
            actual = self.path.parent.stat()
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
                    consumed_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS revoked_approvals (
                    approval_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL
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
        """Atomically persist every verified approval and its audit attribution, or none."""
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
            normalized.append((
                item.approval_id, item.nonce, item.issuer, item.actor_id, item.action,
                item.project_id, item.project_version, item.request_id, issued_at,
                expires_at, item.key_id,
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
            for approval_id, nonce, _ in normalized:
                row = db.execute(
                    "SELECT 1 FROM revoked_approvals WHERE approval_id=? OR nonce=?",
                    (approval_id, nonce),
                ).fetchone()
                if row:
                    db.execute("ROLLBACK")
                    return False
            consumed_at = self._utc(now)
            db.executemany(
                """INSERT INTO consumed_approvals(
                    approval_id, nonce, issuer, actor_id, action, project_id,
                    project_version, request_id, issued_at, expires_at, key_id,
                    consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(*entry, consumed_at) for entry in normalized],
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

    def revoke(self, approval_id: str, nonce: str, *, reason: str = "revoked") -> None:
        """Record a revocation; a consumed approval remains consumed permanently."""
        if (not isinstance(approval_id, str) or not approval_id.strip()
                or not isinstance(nonce, str) or not nonce.strip()
                or not isinstance(reason, str) or not reason.strip()
                or len(reason) > 256):
            raise ValueError("approval ID, nonce and a short reason are required")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO revoked_approvals(approval_id, nonce, revoked_at, reason) VALUES (?, ?, ?, ?)",
                (approval_id, nonce, self._utc(datetime.now(timezone.utc)), reason),
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
