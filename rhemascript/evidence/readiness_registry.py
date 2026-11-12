"""Durable registry for read-only readiness runs and exact byte evidence.

SQLite is local persistence, not tamper-proof storage. HMAC checkpoints must be
retained independently from this database and the key kept secret.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any


class ReadinessReplayError(ValueError):
    """A run ID was reused with a different readiness result or evidence set."""


class ReadinessRunRegistry:
    def __init__(self, database: str | Path):
        self.database = Path(database).expanduser()
        if self.database.exists() and self.database.is_symlink():
            raise ValueError("readiness database must not be a symlink")
        if not self.database.parent.is_dir():
            raise ValueError("readiness database parent directory must exist")
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS readiness_runs (
                run_id TEXT PRIMARY KEY,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _normalise(value: Any) -> Any:
        if is_dataclass(value):
            return asdict(value)
        if isinstance(value, dict):
            return {str(k): ReadinessRunRegistry._normalise(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [ReadinessRunRegistry._normalise(v) for v in value]
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise TypeError(f"unsupported readiness payload value: {type(value).__name__}")

    def record(
        self, run_id: str, report: dict[str, Any], evidence_versions: tuple[Any, ...],
        source_resolution_receipts: tuple[Any, ...] = (),
    ) -> bool:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        payload = {
            "run_id": run_id,
            "report": self._normalise(report),
            "byte_verified_evidence": self._normalise(evidence_versions),
            "source_resolution_receipts": self._normalise(source_resolution_receipts),
            "assessment_is_approval": False,
            "assessment_is_execution_authorisation": False,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload_sha256,payload_json FROM readiness_runs WHERE run_id=?",
                             (run_id,)).fetchone()
            if row:
                if row != (digest, encoded):
                    db.rollback()
                    raise ReadinessReplayError("run_id already exists with different readiness data or evidence")
                db.commit()
                return False
            db.execute("INSERT INTO readiness_runs(run_id,payload_sha256,payload_json) VALUES(?,?,?)",
                       (run_id, digest, encoded))
            db.commit()
        return True

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload_json FROM readiness_runs WHERE run_id=?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def _snapshot_digest(self) -> tuple[int, str]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT run_id,payload_sha256,payload_json FROM readiness_runs ORDER BY run_id"
            ).fetchall()
        canonical_rows = [
            {"run_id": run_id, "payload_sha256": digest, "payload_json": encoded}
            for run_id, digest, encoded in rows
        ]
        encoded = json.dumps(canonical_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return len(rows), hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT payload_sha256,payload_json FROM readiness_runs").fetchall()
        return all(hashlib.sha256(encoded.encode("utf-8")).hexdigest() == digest
                   for digest, encoded in rows)

    def checkpoint(self, key: bytes) -> dict[str, Any]:
        """Create an HMAC checkpoint for independent retention outside the database."""
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        if not self.verify():
            raise ValueError("cannot checkpoint an invalid readiness registry")
        count, snapshot = self._snapshot_digest()
        body = {"schema": "rhemascript-readiness-checkpoint-v1",
                "record_count": count, "registry_sha256": snapshot}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        return {**body, "algorithm": "HMAC-SHA256", "signature": signature}

    def verify_checkpoint(self, checkpoint: dict[str, Any], key: bytes) -> bool:
        """Compare current registry contents with an independently retained checkpoint."""
        if not isinstance(checkpoint, dict) or not isinstance(key, bytes) or len(key) < 32:
            return False
        if checkpoint.get("schema") != "rhemascript-readiness-checkpoint-v1":
            return False
        if checkpoint.get("algorithm") != "HMAC-SHA256":
            return False
        body = {name: checkpoint.get(name) for name in ("schema", "record_count", "registry_sha256")}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(checkpoint.get("signature", "")), expected):
            return False
        if not self.verify():
            return False
        count, snapshot = self._snapshot_digest()
        return count == body["record_count"] and hmac.compare_digest(snapshot, str(body["registry_sha256"]))

    def backup_to(self, destination: str | Path) -> Path:
        """Create a consistent backup atomically without replacing an existing path.

        The temporary database is created in the destination directory, then
        hard-linked into place (which fails if any file or symlink already exists).
        """
        requested = Path(destination).expanduser()
        if not requested.name or requested.name in {".", ".."}:
            raise ValueError("backup destination must name a file")
        parent = requested.parent
        # Reject symlinked directory components rather than silently following them.
        absolute_parent = Path(os.path.abspath(parent))
        current = Path(absolute_parent.anchor)
        for part in absolute_parent.parts[1:]:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("backup destination parent must contain only real directories")
        resolved_parent = absolute_parent.resolve(strict=True)
        target = resolved_parent / requested.name
        if target.exists() or target.is_symlink():
            raise ValueError("backup destination must not already exist")

        fd, temporary_name = tempfile.mkstemp(prefix=".rhemascript-backup-", suffix=".sqlite3",
                                              dir=resolved_parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with self._connect() as source:
                backup = sqlite3.connect(temporary)
                try:
                    backup.execute("PRAGMA synchronous=FULL")
                    source.backup(backup)
                finally:
                    backup.close()
            os.chmod(temporary, 0o600)
            # link() is atomic and does not overwrite an existing destination.
            os.link(temporary, target, follow_symlinks=False)
            return target
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
