"""Durable registry for read-only readiness runs and exact byte evidence.

This registry records assessments, not approvals or execution authority. SQLite is
local persistence, not tamper-proof or independently anchored storage.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import json
import sqlite3
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

    def record(self, run_id: str, report: dict[str, Any], evidence_versions: tuple[Any, ...]) -> bool:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        payload = {
            "run_id": run_id,
            "report": self._normalise(report),
            "byte_verified_evidence": self._normalise(evidence_versions),
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

    def verify(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT payload_sha256,payload_json FROM readiness_runs").fetchall()
        return all(hashlib.sha256(encoded.encode("utf-8")).hexdigest() == digest
                   for digest, encoded in rows)
