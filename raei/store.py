"""Local SQLite transactional evidence store for RAEI engineering practicals.

Learning prototype only. It does not certify competence or grant production authority.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StoreError(ValueError):
    """Raised when a store operation violates the evidence contract."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise StoreError(f"value is not canonical JSON data: {exc}") from exc


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _required_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise StoreError(f"{field} must be a non-empty string")


class EvidenceStore:
    """SQLite-backed store with atomic writes, optimistic versions and idempotency."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialise(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS units (
                    unit_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
                    status TEXT NOT NULL CHECK(status IN
                        ('not_started','in_progress','needs_correction','passed','blocked')),
                    score INTEGER CHECK(score IS NULL OR score BETWEEN 0 AND 4),
                    evidence_ref TEXT,
                    evidence_status TEXT CHECK(evidence_status IS NULL OR evidence_status IN
                        ('verified','reported_unverified','planned')),
                    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS prerequisites (
                    unit_id TEXT NOT NULL REFERENCES units(unit_id) ON DELETE RESTRICT,
                    prerequisite_id TEXT NOT NULL REFERENCES units(unit_id) ON DELETE RESTRICT,
                    PRIMARY KEY(unit_id, prerequisite_id),
                    CHECK(unit_id <> prerequisite_id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    unit_id TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL REFERENCES events(sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_prerequisites_unit ON prerequisites(unit_id);
            """)

    def _append_event(self, db: sqlite3.Connection, action: str, unit_id: str | None,
                      payload: dict[str, Any]) -> int:
        previous = db.execute(
            "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "GENESIS"
        timestamp = _timestamp()
        event_body = {"timestamp": timestamp, "action": action, "unit_id": unit_id,
                      "payload": payload, "previous_hash": previous_hash}
        event_hash = _hash(event_body)
        cursor = db.execute(
            """INSERT INTO events(timestamp,action,unit_id,payload,previous_hash,event_hash)
               VALUES(?,?,?,?,?,?)""",
            (timestamp, action, unit_id, _canonical(payload), previous_hash, event_hash),
        )
        return int(cursor.lastrowid)

    def _idempotent_replay(self, db: sqlite3.Connection, key: str | None,
                           request: dict[str, Any]) -> dict[str, Any] | None:
        if key is None:
            return None
        _required_text(key, "idempotency_key")
        row = db.execute(
            "SELECT request_hash,response_json,event_sequence FROM idempotency WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != _hash(request):
            raise StoreError("idempotency key was already used for a different request")
        sequence = row["event_sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise StoreError("stored idempotency event reference is invalid")
        event = db.execute("SELECT sequence FROM events WHERE sequence=?", (sequence,)).fetchone()
        if event is None:
            raise StoreError("stored idempotency event reference is missing")
        try:
            response = json.loads(row["response_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise StoreError("stored idempotency response is invalid JSON") from exc
        if not isinstance(response, dict):
            raise StoreError("stored idempotency response must be an object")
        return response

    def _save_idempotency(self, db: sqlite3.Connection, key: str | None,
                          request: dict[str, Any], response: dict[str, Any],
                          event_sequence: int) -> None:
        if key is not None:
            db.execute(
                """INSERT INTO idempotency(idempotency_key,request_hash,response_json,event_sequence)
                   VALUES(?,?,?,?)""",
                (key, _hash(request), _canonical(response), event_sequence),
            )

    def create_unit(self, unit_id: str, title: str, prerequisites: list[str] | None = None,
                    idempotency_key: str | None = None) -> dict[str, Any]:
        _required_text(unit_id, "unit_id")
        _required_text(title, "title")
        if prerequisites is None:
            prerequisites = []
        if not isinstance(prerequisites, list):
            raise StoreError("prerequisites must be a list")
        for item in prerequisites:
            _required_text(item, "each prerequisite")
        if len(prerequisites) != len(set(prerequisites)):
            raise StoreError("prerequisites must be a unique list")
        if unit_id in prerequisites:
            raise StoreError("unit cannot depend on itself")
        if idempotency_key is not None:
            _required_text(idempotency_key, "idempotency_key")
        request = {"action": "create_unit", "unit_id": unit_id, "title": title,
                   "prerequisites": prerequisites}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idempotent_replay(db, idempotency_key, request)
            if replay is not None:
                db.rollback()
                return replay
            for prerequisite in prerequisites:
                row = db.execute("SELECT status FROM units WHERE unit_id=?", (prerequisite,)).fetchone()
                if row is None:
                    raise StoreError(f"prerequisite does not exist: {prerequisite}")
            now = _timestamp()
            db.execute(
                "INSERT INTO units(unit_id,title,status,created_at,updated_at) VALUES(?,?,'not_started',?,?)",
                (unit_id, title, now, now),
            )
            for prerequisite in prerequisites:
                db.execute("INSERT INTO prerequisites(unit_id,prerequisite_id) VALUES(?,?)",
                           (unit_id, prerequisite))
            event = self._append_event(db, "unit_created", unit_id,
                                       {"title": title, "prerequisites": prerequisites})
            response = {"unit_id": unit_id, "status": "not_started", "version": 1}
            self._save_idempotency(db, idempotency_key, request, response, event)
            db.commit()
            return response

    def assess(self, unit_id: str, score: int, evidence_ref: str, evidence_status: str,
               expected_version: int, idempotency_key: str | None = None) -> dict[str, Any]:
        _required_text(unit_id, "unit_id")
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 4:
            raise StoreError("score must be an integer from 0 to 4")
        if not isinstance(evidence_status, str) or evidence_status not in {
            "verified", "reported_unverified", "planned"
        }:
            raise StoreError("invalid evidence status")
        if evidence_status == "verified":
            _required_text(evidence_ref, "verified evidence_ref")
        elif evidence_ref is not None and not isinstance(evidence_ref, str):
            raise StoreError("evidence_ref must be a string or null")
        if (not isinstance(expected_version, int) or isinstance(expected_version, bool)
                or expected_version < 1):
            raise StoreError("expected_version must be a positive integer")
        if idempotency_key is not None:
            _required_text(idempotency_key, "idempotency_key")
        request = {"action": "assess", "unit_id": unit_id, "score": score,
                   "evidence_ref": evidence_ref, "evidence_status": evidence_status,
                   "expected_version": expected_version}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idempotent_replay(db, idempotency_key, request)
            if replay is not None:
                db.rollback()
                return replay
            row = db.execute("SELECT * FROM units WHERE unit_id=?", (unit_id,)).fetchone()
            if row is None:
                raise StoreError(f"unknown unit: {unit_id}")
            if row["status"] == "passed":
                raise StoreError("passed units are immutable; create a versioned unit for reassessment")
            if row["version"] != expected_version:
                raise StoreError(f"stale version: expected {expected_version}, current {row['version']}")
            incomplete = db.execute(
                """SELECT p.prerequisite_id FROM prerequisites p JOIN units u
                   ON u.unit_id=p.prerequisite_id
                   WHERE p.unit_id=? AND u.status <> 'passed' LIMIT 1""",
                (unit_id,),
            ).fetchone()
            if incomplete:
                raise StoreError(f"prerequisite is not passed: {incomplete['prerequisite_id']}")
            status = "passed" if score >= 3 and evidence_status == "verified" else "needs_correction"
            updated = _timestamp()
            cursor = db.execute(
                """UPDATE units SET status=?,score=?,evidence_ref=?,evidence_status=?,
                   version=version+1,updated_at=? WHERE unit_id=? AND version=?""",
                (status, score, evidence_ref, evidence_status, updated, unit_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise StoreError("concurrent update detected")
            event = self._append_event(db, "assessment_recorded", unit_id,
                {"score": score, "evidence_ref": evidence_ref, "evidence_status": evidence_status,
                 "result": status, "version": expected_version + 1})
            response = {"unit_id": unit_id, "status": status, "score": score,
                        "version": expected_version + 1}
            self._save_idempotency(db, idempotency_key, request, response, event)
            db.commit()
            return response

    def get_unit(self, unit_id: str) -> dict[str, Any]:
        _required_text(unit_id, "unit_id")
        with self._connect() as db:
            row = db.execute("SELECT * FROM units WHERE unit_id=?", (unit_id,)).fetchone()
            if row is None:
                raise StoreError(f"unknown unit: {unit_id}")
            result = dict(row)
            result["prerequisites"] = [r["prerequisite_id"] for r in db.execute(
                "SELECT prerequisite_id FROM prerequisites WHERE unit_id=? ORDER BY prerequisite_id",
                (unit_id,),
            )]
            return result

    def verify_event_chain(self) -> bool:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        previous = "GENESIS"
        for row in rows:
            try:
                payload = json.loads(row["payload"])
                body = {"timestamp": row["timestamp"], "action": row["action"],
                        "unit_id": row["unit_id"], "payload": payload,
                        "previous_hash": previous}
                if row["previous_hash"] != previous or row["event_hash"] != _hash(body):
                    return False
            except (json.JSONDecodeError, StoreError, TypeError, ValueError):
                return False
            previous = row["event_hash"]
        return True

    def backup_to(self, destination: str | Path) -> None:
        """Create a consistent SQLite backup using SQLite's online backup API."""
        destination_path = Path(destination)
        if destination_path.resolve() == Path(self.path).resolve():
            raise StoreError("backup destination must differ from the live database")
        if destination_path.exists():
            raise StoreError("backup destination already exists; refusing to overwrite")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        source = self._connect()
        target = sqlite3.connect(str(destination_path), timeout=10)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()

    @staticmethod
    def _validate_backup(path: Path) -> None:
        """Validate the source DB before copying or initializing a restore target."""
        if not path.is_file():
            raise StoreError("backup file does not exist")
        uri = path.resolve().as_uri() + "?mode=ro"
        try:
            source = sqlite3.connect(uri, uri=True, timeout=10)
            source.row_factory = sqlite3.Row
            try:
                integrity = source.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise StoreError("backup failed SQLite integrity check")
                foreign_key_errors = source.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_key_errors:
                    raise StoreError("backup contains foreign-key violations")
                tables = {
                    row[0] for row in source.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                required = {"units", "prerequisites", "events", "idempotency"}
                if not required.issubset(tables):
                    raise StoreError("backup is missing required evidence-store tables")
                expected_columns = {
                    "units": {"unit_id", "title", "status", "version"},
                    "prerequisites": {"unit_id", "prerequisite_id"},
                    "events": {"sequence", "timestamp", "action", "unit_id", "payload",
                               "previous_hash", "event_hash"},
                    "idempotency": {"idempotency_key", "request_hash", "response_json",
                                    "event_sequence"},
                }
                for table, expected in expected_columns.items():
                    actual = {row[1] for row in source.execute(f"PRAGMA table_info({table})")}
                    if not expected.issubset(actual):
                        raise StoreError(f"backup table is incomplete: {table}")
                previous = "GENESIS"
                for row in source.execute("SELECT * FROM events ORDER BY sequence"):
                    try:
                        payload = json.loads(row["payload"])
                        body = {"timestamp": row["timestamp"], "action": row["action"],
                                "unit_id": row["unit_id"], "payload": payload,
                                "previous_hash": previous}
                        if (row["previous_hash"] != previous
                                or row["event_hash"] != _hash(body)):
                            raise StoreError("backup failed audit-chain verification")
                    except (json.JSONDecodeError, TypeError, ValueError) as exc:
                        if isinstance(exc, StoreError):
                            raise
                        raise StoreError("backup contains malformed audit events") from exc
                    previous = row["event_hash"]
            finally:
                source.close()
        except sqlite3.Error as exc:
            raise StoreError("backup is not a readable evidence-store database") from exc

    @staticmethod
    def restore_from(backup: str | Path, destination: str | Path) -> "EvidenceStore":
        """Restore a validated backup to a new path; never overwrite existing data."""
        backup_path, destination_path = Path(backup), Path(destination)
        if not backup_path.is_file():
            raise StoreError(f"backup file does not exist: {backup_path}")
        if destination_path.exists():
            raise StoreError("restore destination already exists; refusing to overwrite")
        if backup_path.resolve() == destination_path.resolve():
            raise StoreError("restore source and destination must differ")
        EvidenceStore._validate_backup(backup_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(str(backup_path), timeout=10)
        target = sqlite3.connect(str(destination_path), timeout=10)
        try:
            source.backup(target)
        except sqlite3.Error as exc:
            destination_path.unlink(missing_ok=True)
            raise StoreError("backup restore copy failed") from exc
        finally:
            target.close()
            source.close()
        try:
            restored = EvidenceStore(destination_path)
            if not restored.verify_event_chain():
                raise StoreError("restored database failed audit-chain verification")
            return restored
        except Exception:
            destination_path.unlink(missing_ok=True)
            raise

    def event_count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
