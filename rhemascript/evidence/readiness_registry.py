"""Durable registry for readiness runs, exact evidence and hash-chained activity events.

SQLite is local persistence, not tamper-proof storage. HMAC checkpoints must be
retained independently from this database and the key kept secret.
"""
from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
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


_ACTIVITY_EVENT_TYPES = {
    "READINESS_RUN_RECORDED", "LEGACY_READINESS_RECORD_IMPORTED",
    "FINDING_CAPTURED", "FINDING_RESEARCHED", "FINDING_REPRODUCED",
    "FINDING_DISPOSITIONED", "KNOWLEDGE_REVIEWED", "DECISION_RECORDED", "REQUIREMENT_RECORDED",
    "CHANGE_RECORDED", "TASK_RECORDED", "IMPLEMENTATION_RECORDED",
    "TEST_RECORDED", "DEFECT_RECORDED", "LESSON_RECORDED",
    "HANDOVER_RECORDED",
}
_INTERNAL_EVENT_TYPES = {"READINESS_RUN_RECORDED", "LEGACY_READINESS_RECORD_IMPORTED"}


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
            db.execute("""CREATE TABLE IF NOT EXISTS activity_events (
                sequence INTEGER NOT NULL UNIQUE,
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                project_id TEXT,
                subject_id TEXT,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL
            )""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS activity_events_no_update
                BEFORE UPDATE ON activity_events
                BEGIN SELECT RAISE(ABORT, 'activity events are append-only'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS activity_events_no_delete
                BEFORE DELETE ON activity_events
                BEGIN SELECT RAISE(ABORT, 'activity events are append-only'); END""")
        self._migrate_legacy_readiness_records()

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _canonical(value: Any) -> str:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )

    @staticmethod
    def _event_digest(body: dict[str, Any]) -> str:
        encoded = ReadinessRunRegistry._canonical(body).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _append_event_tx(
        self, db: sqlite3.Connection, event_id: str, event_type: str,
        payload: dict[str, Any], project_id: str | None, subject_id: str | None,
    ) -> str:
        last = db.execute(
            "SELECT sequence,event_hash FROM activity_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = (last[0] + 1) if last else 1
        previous_hash = last[1] if last else "GENESIS"
        payload_json = self._canonical(payload)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        recorded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        body = {
            "sequence": sequence,
            "event_id": event_id,
            "event_type": event_type,
            "project_id": project_id,
            "subject_id": subject_id,
            "payload_json": payload_json,
            "payload_sha256": payload_sha256,
            "previous_hash": previous_hash,
            "recorded_at_utc": recorded_at,
        }
        event_hash = self._event_digest(body)
        db.execute(
            """INSERT INTO activity_events
            (sequence,event_id,event_type,project_id,subject_id,payload_json,
             payload_sha256,previous_hash,event_hash,recorded_at_utc)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (sequence,event_id,event_type,project_id,subject_id,payload_json,
             payload_sha256,previous_hash,event_hash,recorded_at),
        )
        return event_hash

    def _migrate_legacy_readiness_records(self) -> None:
        """Record a clearly labelled import event for pre-event-table readiness rows."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            event_count = db.execute("SELECT COUNT(*) FROM activity_events").fetchone()[0]
            if event_count == 0:
                rows = db.execute(
                    "SELECT run_id,payload_sha256,created_at FROM readiness_runs ORDER BY created_at,rowid"
                ).fetchall()
                for run_id, payload_sha256, created_at in rows:
                    self._append_event_tx(
                        db,
                        f"LEGACY-READINESS:{run_id}",
                        "LEGACY_READINESS_RECORD_IMPORTED",
                        {
                            "run_id": run_id,
                            "payload_sha256": payload_sha256,
                            "source_created_at": created_at,
                            "migration": "READINESS_EVENT_CHAIN_V1",
                        },
                        None,
                        run_id,
                    )
            db.commit()

    def append_activity_event(
        self, event_id: str, event_type: str, payload: dict[str, Any],
        *, project_id: str | None = None, subject_id: str | None = None,
    ) -> bool:
        """Append one idempotent, hash-chained activity event to this registry."""
        if not isinstance(event_id, str) or not event_id.strip() or event_id != event_id.strip():
            raise ValueError("event_id must be a non-empty trimmed string")
        if not isinstance(event_type, str) or event_type not in _ACTIVITY_EVENT_TYPES - _INTERNAL_EVENT_TYPES:
            raise ValueError("unsupported external activity event type")
        if event_type in {"FINDING_DISPOSITIONED", "KNOWLEDGE_REVIEWED"}:
            raise ValueError("governed review events require append_governed_activity_event")
        for name, value in (("project_id", project_id), ("subject_id", subject_id)):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be null or a non-empty string")
        if not isinstance(payload, dict):
            raise TypeError("activity event payload must be an object")
        normalised = self._normalise(payload)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT event_type,project_id,subject_id,payload_json
                FROM activity_events WHERE event_id=?""",
                (event_id,),
            ).fetchone()
            if row:
                if row != (event_type, project_id, subject_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("event_id already exists with different event data")
                db.commit()
                return False
            self._append_event_tx(db, event_id, event_type, normalised, project_id, subject_id)
            db.commit()
        return True

    def append_governed_activity_event(
        self, event_id: str, event_type: str, payload: dict[str, Any], *,
        project_id: str, project_version: str, subject_id: str,
        request_id: str, approvals: tuple[Any, ...], expected_actions: tuple[str, ...],
    ) -> bool:
        """Append a reviewed finding/knowledge decision backed by consumed signed approvals.

        Approval credentials must already have been signature-verified, scope-checked,
        and atomically consumed by ApprovalVerifier. This registry independently checks
        the in-process verification capability, exact scope, expiry and distinct actors.
        """
        from datetime import datetime, timezone
        from rhemascript.core.approvals import is_verified_approval

        if event_type not in {"FINDING_DISPOSITIONED", "KNOWLEDGE_REVIEWED"}:
            raise ValueError("unsupported governed event type")
        for name, value in (
            ("event_id", event_id), ("project_id", project_id),
            ("project_version", project_version), ("subject_id", subject_id),
            ("request_id", request_id),
        ):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty trimmed text")
        if not isinstance(payload, dict) or "authorization" in payload:
            raise ValueError("governed event payload must be an object without caller-supplied authorization")
        if not isinstance(approvals, tuple) or len(approvals) != 2:
            raise ValueError("exactly two independently signed approvals are required")
        required_actions = (
            ("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM")
            if event_type == "FINDING_DISPOSITIONED"
            else ("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM")
        )
        if expected_actions != required_actions:
            raise ValueError("governed event approval actions do not match the event policy")
        if any(not is_verified_approval(item) for item in approvals):
            raise ValueError("governed events require verifier-issued, consumed approvals")
        actors = [item.actor_id for item in approvals]
        if (len(set(actors)) != 2
                or len({item.approval_id for item in approvals}) != 2
                or len({item.issuer for item in approvals}) != 1):
            raise ValueError("governed review requires two distinct actors and approval IDs from one trusted issuer")
        now = datetime.now(timezone.utc)
        for item, action in zip(approvals, expected_actions):
            if (item.action != action or item.project_id != project_id
                    or item.project_version != project_version or item.request_id != request_id
                    or item.expires_at <= now):
                raise ValueError("approval action, project, version, request or expiry does not match")
        if event_type == "FINDING_DISPOSITIONED":
            required = {"finding_id", "finding_version", "disposition", "rationale", "evidence_binding"}
            decisions = {"ACCEPTED", "REJECTED", "DUPLICATE", "DEFERRED", "WITHDRAWN"}
            identity_field, version_field = "finding_id", "finding_version"
        else:
            required = {"knowledge_id", "knowledge_version", "decision", "rationale", "evidence_binding"}
            decisions = {"APPROVED", "REJECTED"}
            identity_field, version_field = "knowledge_id", "knowledge_version"
        if set(payload) != required:
            raise ValueError("governed review payload has an invalid field set")
        if payload.get(identity_field) != subject_id:
            raise ValueError("governed review subject does not match its payload")
        version = payload.get(version_field)
        if not isinstance(version, str) or not version.strip():
            raise ValueError("governed review subject version is required")
        decision_field = "disposition" if event_type == "FINDING_DISPOSITIONED" else "decision"
        if payload.get(decision_field) not in decisions:
            raise ValueError("governed review decision is unsupported")
        rationale = payload.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 4000:
            raise ValueError("governed review rationale must be non-empty and at most 4000 characters")
        binding = payload.get("evidence_binding")
        if (not isinstance(binding, dict)
                or set(binding) != {"evidence_id", "evidence_version", "sha256", "size_bytes"}
                or any(not isinstance(binding.get(key), str) or not binding[key].strip()
                       for key in ("evidence_id", "evidence_version"))
                or not isinstance(binding.get("sha256"), str)
                or len(binding["sha256"]) != 64
                or any(ch not in "0123456789abcdef" for ch in binding["sha256"])
                or not isinstance(binding.get("size_bytes"), int)
                or isinstance(binding.get("size_bytes"), bool) or binding["size_bytes"] < 0):
            raise ValueError("governed review requires an exact evidence ID/version/SHA-256/size binding")
        enriched = dict(payload)
        enriched["authorization"] = {
            "issuer": approvals[0].issuer,
            "actor_ids": actors,
            "approval_ids": [item.approval_id for item in approvals],
            "actions": [item.action for item in approvals],
            "project_id": project_id,
            "project_version": project_version,
            "request_id": request_id,
            "authenticated_at_utc": now.isoformat(),
        }
        normalised = self._normalise(enriched)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT event_type,project_id,subject_id,payload_json
                FROM activity_events WHERE event_id=?""", (event_id,),
            ).fetchone()
            if row:
                if row != (event_type, project_id, subject_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("event_id already exists with different governed review data")
                db.commit()
                return False
            self._append_event_tx(db, event_id, event_type, normalised, project_id, subject_id)
            db.commit()
        return True

    def list_activity_events(self) -> list[dict[str, Any]]:
        """Return detached activity events in sequence order after chain verification."""
        if not self.verify():
            raise ValueError("activity history integrity verification failed")
        with self._connect() as db:
            rows = db.execute(
                """SELECT sequence,event_id,event_type,project_id,subject_id,payload_json,
                payload_sha256,previous_hash,event_hash,recorded_at_utc
                FROM activity_events ORDER BY sequence"""
            ).fetchall()
        return [
            {
                "sequence": row[0], "event_id": row[1], "event_type": row[2],
                "project_id": row[3], "subject_id": row[4],
                "payload": json.loads(row[5]), "payload_sha256": row[6],
                "previous_hash": row[7], "event_hash": row[8],
                "recorded_at_utc": row[9],
            }
            for row in rows
        ]

    @staticmethod
    def _normalise(value: Any) -> Any:
        if is_dataclass(value):
            # Internal verification tokens are process-local capabilities, not persisted data.
            return {
                item.name: ReadinessRunRegistry._normalise(getattr(value, item.name))
                for item in fields(value) if not item.name.startswith("_")
            }
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise TypeError("readiness payload object keys must be strings")
            return {key: ReadinessRunRegistry._normalise(v) for key, v in value.items()}
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
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if not self.verify():
            raise ValueError("cannot record into an invalid readiness/activity registry")
        evidence_refs = [
            {
                "evidence_id": item.get("evidence_id"),
                "relative_path": item.get("relative_path"),
                "version": item.get("version"),
                "sha256": item.get("sha256"),
                "size_bytes": item.get("size_bytes"),
            }
            for item in payload["byte_verified_evidence"]
            if isinstance(item, dict)
            and {"evidence_id", "relative_path", "version", "sha256", "size_bytes"}.issubset(item)
        ]
        project_id = payload["report"].get("project_id")
        if not isinstance(project_id, str) or not project_id.strip():
            project_id = None
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
            self._append_event_tx(
                db, f"READINESS:{run_id}", "READINESS_RUN_RECORDED",
                {"run_id": run_id, "payload_sha256": digest, "evidence_refs": evidence_refs},
                project_id, run_id,
            )
            db.commit()
        return True

    def list_all(self) -> list[dict[str, Any]]:
        """Return detached records in durable insertion order after integrity validation."""
        if not self.verify():
            raise ValueError("readiness registry integrity verification failed")
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload_json FROM readiness_runs ORDER BY created_at, rowid"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload_json FROM readiness_runs WHERE run_id=?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def _legacy_readiness_snapshot_digest(self) -> tuple[int, str]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT run_id,payload_sha256,payload_json FROM readiness_runs ORDER BY run_id"
            ).fetchall()
        canonical_rows = [
            {"run_id": run_id, "payload_sha256": digest, "payload_json": encoded}
            for run_id, digest, encoded in rows
        ]
        encoded = self._canonical(canonical_rows)
        return len(rows), hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _snapshot_digest(self) -> tuple[int, int, str, str]:
        with self._connect() as db:
            readiness_rows = db.execute(
                "SELECT run_id,payload_sha256,payload_json FROM readiness_runs ORDER BY run_id"
            ).fetchall()
            event_rows = db.execute(
                """SELECT sequence,event_id,event_type,project_id,subject_id,payload_json,
                payload_sha256,previous_hash,event_hash,recorded_at_utc
                FROM activity_events ORDER BY sequence"""
            ).fetchall()
        readiness = [
            {"run_id": run_id, "payload_sha256": digest, "payload_json": encoded}
            for run_id, digest, encoded in readiness_rows
        ]
        events = [
            {"sequence": row[0], "event_id": row[1], "event_type": row[2],
             "project_id": row[3], "subject_id": row[4], "payload_json": row[5],
             "payload_sha256": row[6], "previous_hash": row[7],
             "event_hash": row[8], "recorded_at_utc": row[9]}
            for row in event_rows
        ]
        encoded = self._canonical({"readiness_runs": readiness, "activity_events": events})
        head_hash = event_rows[-1][8] if event_rows else "GENESIS"
        return len(readiness_rows), len(event_rows), hashlib.sha256(encoded.encode("utf-8")).hexdigest(), head_hash

    def verify(self) -> bool:
        try:
            with self._connect() as db:
                readiness_rows = db.execute(
                    "SELECT run_id,payload_sha256,payload_json FROM readiness_runs ORDER BY created_at,rowid"
                ).fetchall()
                event_rows = db.execute(
                    """SELECT sequence,event_id,event_type,project_id,subject_id,payload_json,
                    payload_sha256,previous_hash,event_hash,recorded_at_utc
                    FROM activity_events ORDER BY sequence"""
                ).fetchall()
                triggers = {
                    row[0] for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    ).fetchall()
                }
        except sqlite3.Error:
            return False

        for run_id, digest, encoded in readiness_rows:
            if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != digest:
                return False
            try:
                parsed = json.loads(encoded)
                if self._canonical(parsed) != encoded or parsed.get("run_id") != run_id:
                    return False
            except (TypeError, ValueError, AttributeError):
                return False

        if not {"activity_events_no_update", "activity_events_no_delete"}.issubset(triggers):
            return False

        previous = "GENESIS"
        readiness_links = {}
        for index, row in enumerate(event_rows, start=1):
            sequence,event_id,event_type,project_id,subject_id,payload_json,payload_sha256,previous_hash,event_hash,recorded_at = row
            if sequence != index or previous_hash != previous:
                return False
            if event_type not in _ACTIVITY_EVENT_TYPES:
                return False
            if not isinstance(event_id, str) or not event_id or event_id.strip() != event_id:
                return False
            try:
                payload = json.loads(payload_json)
                if not isinstance(payload, dict) or self._canonical(payload) != payload_json:
                    return False
            except (TypeError, ValueError):
                return False
            if hashlib.sha256(payload_json.encode("utf-8")).hexdigest() != payload_sha256:
                return False
            body = {
                "sequence": sequence, "event_id": event_id, "event_type": event_type,
                "project_id": project_id, "subject_id": subject_id,
                "payload_json": payload_json, "payload_sha256": payload_sha256,
                "previous_hash": previous_hash, "recorded_at_utc": recorded_at,
            }
            expected_hash = self._event_digest(body)
            if not hmac.compare_digest(str(event_hash), expected_hash):
                return False
            if event_type in _INTERNAL_EVENT_TYPES:
                run_id = payload.get("run_id")
                run_digest = payload.get("payload_sha256")
                if not isinstance(run_id, str) or not isinstance(run_digest, str) or run_id in readiness_links:
                    return False
                readiness_links[run_id] = run_digest
            previous = event_hash

        stored_links = {run_id: digest for run_id, digest, _ in readiness_rows}
        if readiness_links != stored_links:
            return False
        return True

    def verify_artifacts(self, evidence_root: str | Path) -> bool:
        """Re-hash every retained evidence artefact before using recorded progress."""
        root = Path(evidence_root).expanduser()
        try:
            root_info = root.lstat()
            if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
                return False
            root.resolve(strict=True)
        except OSError:
            return False
        if not self.verify():
            return False
        from .artifact_verification import EvidenceIntegrityError, verify_artifact
        try:
            evidence_collections = [
                record.get("byte_verified_evidence") for record in self.list_all()
            ]
            evidence_collections.extend(
                event["payload"].get("evidence_refs", [])
                for event in self.list_activity_events()
            )
            for evidence_items in evidence_collections:
                if not isinstance(evidence_items, list):
                    return False
                for item in evidence_items:
                    if not isinstance(item, dict):
                        return False
                    required = {"evidence_id", "relative_path", "version", "sha256", "size_bytes"}
                    if not required.issubset(item):
                        return False
                    verified = verify_artifact(
                        root, item["relative_path"],
                        evidence_id=item["evidence_id"], version=item["version"],
                    )
                    if verified.sha256 != item["sha256"] or verified.size_bytes != item["size_bytes"]:
                        return False
        except (EvidenceIntegrityError, KeyError, TypeError, ValueError):
            return False
        return True

    def checkpoint(self, key: bytes) -> dict[str, Any]:
        """Create an HMAC checkpoint for independent retention outside the database."""
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("checkpoint key must contain at least 32 bytes")
        if not self.verify():
            raise ValueError("cannot checkpoint an invalid readiness registry")
        record_count, event_count, snapshot, head_hash = self._snapshot_digest()
        body = {
            "schema": "rhemascript-registry-checkpoint-v2",
            "record_count": record_count,
            "event_count": event_count,
            "registry_sha256": snapshot,
            "event_head_hash": head_hash,
        }
        encoded = self._canonical(body).encode("utf-8")
        signature = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        return {**body, "algorithm": "HMAC-SHA256", "signature": signature}

    def verify_checkpoint(self, checkpoint: dict[str, Any], key: bytes) -> bool:
        """Compare readiness records and the event-chain head with an independently retained checkpoint."""
        if not isinstance(checkpoint, dict) or not isinstance(key, bytes) or len(key) < 32:
            return False
        if checkpoint.get("algorithm") != "HMAC-SHA256" or not self.verify():
            return False
        if checkpoint.get("schema") == "rhemascript-readiness-checkpoint-v1":
            if self.list_activity_events():
                return False
            body = {name: checkpoint.get(name) for name in ("schema", "record_count", "registry_sha256")}
            encoded = self._canonical(body).encode("utf-8")
            expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(checkpoint.get("signature", "")), expected):
                return False
            count, snapshot = self._legacy_readiness_snapshot_digest()
            return count == body["record_count"] and hmac.compare_digest(snapshot, str(body["registry_sha256"]))
        if checkpoint.get("schema") != "rhemascript-registry-checkpoint-v2":
            return False
        names = ("schema", "record_count", "event_count", "registry_sha256", "event_head_hash")
        body = {name: checkpoint.get(name) for name in names}
        encoded = self._canonical(body).encode("utf-8")
        expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(checkpoint.get("signature", "")), expected):
            return False
        record_count, event_count, snapshot, head_hash = self._snapshot_digest()
        return (
            record_count == body["record_count"]
            and event_count == body["event_count"]
            and hmac.compare_digest(snapshot, str(body["registry_sha256"]))
            and hmac.compare_digest(head_hash, str(body["event_head_hash"]))
        )

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
