"""Experimental local assessment store; not an authoritative RAEI history ledger.

This standalone helper has no independent checkpoint or external trust anchor.
Its ``verify`` method checks internal row consistency only; a database editor can
rewrite both columns and the duplicated JSON payload. Production lifecycle and
governed assessment history must use ReadinessRunRegistry activity events and
its independently retained HMAC checkpoint. Keep this helper isolated until it
is explicitly integrated and independently reviewed.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .artifact_verification import (
    AssessmentBinding, EvidenceIntegrityError, is_verified_assessment_binding,
)


class AssessmentReplayError(EvidenceIntegrityError):
    pass


class AssessmentRegistry:
    def __init__(self, database: str | Path):
        self.database = Path(database).expanduser()
        if self.database.exists() and self.database.is_symlink():
            raise EvidenceIntegrityError("assessment database must not be a symlink")
        if not self.database.parent.is_dir():
            raise EvidenceIntegrityError("assessment database parent directory must exist")
        self._initialise()

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialise(self):
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                evidence_version TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 4),
                binding_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def record(self, binding: AssessmentBinding) -> bool:
        if not is_verified_assessment_binding(binding):
            raise EvidenceIntegrityError("record requires an assessment binding issued by bind_assessment")
        payload: dict[str, Any] = {
            "assessment_id": binding.assessment_id,
            "evidence_id": binding.evidence_id,
            "evidence_version": binding.evidence_version,
            "evidence_sha256": binding.evidence_sha256,
            "score": binding.score,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT binding_json FROM assessments WHERE assessment_id=?",
                (binding.assessment_id,),
            ).fetchone()
            if row:
                if row[0] != encoded:
                    db.rollback()
                    raise AssessmentReplayError("assessment_id already exists with different evidence or score")
                db.commit()
                return False
            db.execute(
                """INSERT INTO assessments
                (assessment_id,evidence_id,evidence_version,evidence_sha256,score,binding_json)
                VALUES (?,?,?,?,?,?)""",
                (binding.assessment_id, binding.evidence_id, binding.evidence_version,
                 binding.evidence_sha256, binding.score, encoded),
            )
            db.commit()
            return True

    def get(self, assessment_id: str) -> AssessmentBinding | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT assessment_id,evidence_id,evidence_version,evidence_sha256,score
                FROM assessments WHERE assessment_id=?""",
                (assessment_id,),
            ).fetchone()
        return AssessmentBinding(*row) if row else None

    def verify(self) -> bool:
        """Check internal row/JSON consistency, not authenticity or tamper resistance."""
        with self._connect() as db:
            rows = db.execute(
                """SELECT assessment_id,evidence_id,evidence_version,evidence_sha256,score,binding_json
                FROM assessments ORDER BY created_at, assessment_id"""
            ).fetchall()
        for assessment_id, evidence_id, version, digest, score, encoded in rows:
            expected = json.dumps({
                "assessment_id": assessment_id, "evidence_id": evidence_id,
                "evidence_version": version, "evidence_sha256": digest, "score": score,
            }, sort_keys=True, separators=(",", ":"))
            if encoded != expected:
                return False
        return True
