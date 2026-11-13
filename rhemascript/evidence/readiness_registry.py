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
    "FINDING_CAPTURED", "FINDING_RESEARCHED", "FINDING_REPRODUCED", "FINDING_PLANNED",
    "FINDING_DISPOSITIONED", "FINDING_CLOSED", "FINDING_REOPENED", "KNOWLEDGE_REVIEWED", "DECISION_RECORDED", "REQUIREMENT_RECORDED",
    "CHANGE_RECORDED", "TASK_RECORDED", "IMPLEMENTATION_RECORDED",
    "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED",
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
        if event_type in {"FINDING_DISPOSITIONED", "FINDING_CLOSED", "FINDING_REOPENED", "KNOWLEDGE_REVIEWED"}:
            raise ValueError("governed review events require append_governed_activity_event")
        if event_type in {"FINDING_RESEARCHED", "FINDING_REPRODUCED", "FINDING_PLANNED", "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED"}:
            raise ValueError("authenticated finding lifecycle events require append_authenticated_finding_lifecycle_event")
        for name, value in (("project_id", project_id), ("subject_id", subject_id)):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be null or a non-empty string")
        if not isinstance(payload, dict):
            raise TypeError("activity event payload must be an object")
        if (event_type == "FINDING_CAPTURED"
                and (payload.get("identity_authentication_status") == "VERIFIED"
                     or "submitter_identity" in payload or "submitter_authorization" in payload)):
            raise ValueError("authenticated finding capture requires append_authenticated_finding_capture_event")
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

    def append_authenticated_finding_capture_event(
        self, event_id: str, payload: dict[str, Any], *,
        project_id: str, project_version: str, request_id: str, approval: Any,
    ) -> bool:
        """Append a finding capture bound to one consumed, verifier-issued V3 submitter approval."""
        from datetime import datetime, timezone
        from rhemascript.core.approvals import is_consumed_verified_approval

        if (not isinstance(event_id, str) or not event_id.strip() or event_id != event_id.strip()
                or not isinstance(project_id, str) or not project_id.strip()
                or not isinstance(project_version, str) or not project_version.strip()
                or not isinstance(request_id, str) or not request_id.strip()):
            raise ValueError("authenticated finding capture scope must be non-empty and trimmed")
        if not is_consumed_verified_approval(approval):
            raise ValueError("authenticated finding capture requires a verifier-issued approval")
        if (approval.credential_schema != "RhemaScript.ApprovalCredential.v3"
                or approval.action != "FINDING_SUBMIT"
                or approval.project_id != project_id
                or approval.project_version != project_version
                or approval.request_id != request_id
                or approval.expires_at <= datetime.now(timezone.utc)):
            raise ValueError("submitter approval schema, action, scope or expiry is invalid")
        if not isinstance(payload, dict) or "submitter_identity" in payload or "submitter_authorization" in payload:
            raise ValueError("finding capture payload must not contain caller-supplied identity claims")
        finding_id = payload.get("finding_id")
        version = payload.get("version")
        primary = payload.get("observation_evidence")
        if (not isinstance(finding_id, str) or not finding_id.strip()
                or not isinstance(version, str) or not version.strip()
                or event_id != f"FINDING:{finding_id}@{version}"
                or payload.get("project_id") != project_id
                or payload.get("identity_authentication_status") != "UNVERIFIED"
                or not isinstance(primary, dict)
                or not {"evidence_id", "version", "sha256", "size_bytes"}.issubset(primary)):
            raise ValueError("finding capture payload is incomplete or already asserts authenticated identity")
        if (approval.artifact_id != primary.get("evidence_id")
                or approval.artifact_version != primary.get("version")
                or approval.artifact_sha256 != primary.get("sha256")
                or approval.artifact_size_bytes != primary.get("size_bytes")
                or not approval.subject_id or not approval.actor_id
                or not approval.actor_role or not approval.authn_context
                or not approval.identity_session_id or not approval.identity_policy_version
                or not approval.identity_provider_id or approval.authenticated_at is None):
            raise ValueError("submitter approval is not bound to the exact observation evidence or identity claims")
        enriched = dict(payload)
        enriched["identity_authentication_status"] = "VERIFIED"
        enriched["submitter_identity"] = {
            "actor_id": approval.actor_id,
            "subject_id": approval.subject_id,
            "actor_role": approval.actor_role,
            "authn_context": approval.authn_context,
            "authenticated_at": approval.authenticated_at.isoformat(),
            "identity_session_id": approval.identity_session_id,
            "identity_policy_version": approval.identity_policy_version,
            "identity_provider_id": approval.identity_provider_id,
        }
        enriched["submitter_authorization"] = {
            "issuer": approval.issuer,
            "approval_id": approval.approval_id,
            "action": approval.action,
            "project_id": approval.project_id,
            "project_version": approval.project_version,
            "request_id": approval.request_id,
            "artifact_sha256": approval.artifact_sha256,
            "artifact_size_bytes": approval.artifact_size_bytes,
            "signature_sha256": hashlib.sha256((approval.signature or "").encode("ascii")).hexdigest(),
        }
        normalised = self._normalise(enriched)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT event_type,project_id,subject_id,payload_json FROM activity_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row:
                if row != ("FINDING_CAPTURED", project_id, finding_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("event_id already exists with different authenticated finding data")
                db.commit()
                return False
            supersedes = normalised.get("supersedes", [])
            if supersedes:
                if (not isinstance(supersedes, list) or len(supersedes) != 1
                        or not isinstance(supersedes[0], str)
                        or not supersedes[0].startswith(f"{finding_id}@")):
                    db.rollback()
                    raise ValueError("authenticated resumed capture must supersede exactly one prior version of the same finding")
                prior_version = supersedes[0].rsplit("@", 1)[-1]
                prior_rows = db.execute(
                    """SELECT event_id,event_type,payload_json FROM activity_events
                    WHERE project_id=? AND subject_id=?
                    AND event_type IN ('FINDING_CLOSED','FINDING_REOPENED') ORDER BY sequence""",
                    (project_id, finding_id),
                ).fetchall()
                prior_closures = [
                    (eid, json.loads(raw)) for eid, kind, raw in prior_rows
                    if kind == "FINDING_CLOSED"
                    and json.loads(raw).get("finding_version") == prior_version
                ]
                prior_reopenings = [
                    (eid, json.loads(raw)) for eid, kind, raw in prior_rows
                    if kind == "FINDING_REOPENED"
                    and json.loads(raw).get("finding_version") == prior_version
                ]
                if len(prior_closures) != 1 or len(prior_reopenings) != 1:
                    db.rollback()
                    raise ValueError("resumed capture requires exactly one prior closure and reopening in this project")
                closure_id, closure_payload = prior_closures[0]
                reopen_id, reopen_payload = prior_reopenings[0]
                closure_auth = closure_payload.get("authorization", {})
                reopen_auth = reopen_payload.get("authorization", {})
                if (reopen_payload.get("closure_event_id") != closure_id
                        or reopen_payload.get("new_finding_version") != version
                        or reopen_payload.get("reopen_decision") != "REOPENED"
                        or reopen_auth.get("project_version") != project_version
                        or closure_auth.get("project_version") != project_version
                        or approval.project_version != project_version):
                    db.rollback()
                    raise ValueError("resumed capture does not match the exact prior closure and reopening project scope")
                prior_capture_count = db.execute(
                    """SELECT COUNT(*) FROM activity_events
                    WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?""",
                    (project_id, finding_id),
                ).fetchone()[0]
                if prior_capture_count < 1:
                    db.rollback()
                    raise ValueError("resumed capture requires the original finding capture")
                fork_rows = db.execute(
                    """SELECT payload_json FROM activity_events
                    WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?""",
                    (project_id, finding_id),
                ).fetchall()
                if any(
                    version == json.loads(raw).get("version")
                    or supersedes[0] in json.loads(raw).get("supersedes", [])
                    for (raw,) in fork_rows
                ):
                    db.rollback()
                    raise ValueError("resumed finding version or supersession edge already exists")
            elif any(
                json.loads(raw).get("version") == version
                for (raw,) in db.execute(
                    """SELECT payload_json FROM activity_events
                    WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?""",
                    (project_id, finding_id),
                ).fetchall()
            ):
                db.rollback()
                raise ValueError("finding version already has a captured submission")
            self._append_event_tx(
                db, event_id, "FINDING_CAPTURED", normalised, project_id, finding_id,
            )
            db.commit()
        return True

    def append_authenticated_finding_lifecycle_event(
        self, event_id: str, event_type: str, payload: dict[str, Any], *,
        project_id: str, project_version: str, request_id: str, approval: Any,
    ) -> bool:
        """Append V3-authenticated research/reproduction evidence with ordered state checks."""
        from datetime import datetime, timezone
        from rhemascript.core.approvals import is_consumed_verified_approval

        actions = {
            "FINDING_RESEARCHED": "FINDING_RESEARCH",
            "FINDING_REPRODUCED": "FINDING_REPRODUCE",
            "FINDING_PLANNED": "FINDING_PLAN",
        }
        if event_type not in actions:
            raise ValueError("unsupported authenticated finding lifecycle event")
        for name, value in (
            ("event_id", event_id), ("project_id", project_id),
            ("project_version", project_version), ("request_id", request_id),
        ):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty trimmed text")
        if not is_consumed_verified_approval(approval):
            raise ValueError("finding lifecycle requires a verifier-issued, consumed approval")
        if (approval.credential_schema != "RhemaScript.ApprovalCredential.v3"
                or approval.action != actions[event_type]
                or approval.project_id != project_id
                or approval.project_version != project_version
                or approval.request_id != request_id
                or approval.expires_at <= datetime.now(timezone.utc)):
            raise ValueError("finding lifecycle approval schema, action, scope or expiry is invalid")
        if not isinstance(payload, dict) or "authorization" in payload:
            raise ValueError("finding lifecycle payload must be an object without caller authorization")
        finding_id = payload.get("finding_id")
        finding_version = payload.get("finding_version")
        if (not isinstance(finding_id, str) or not finding_id.strip()
                or not isinstance(finding_version, str) or not finding_version.strip()
                or event_id != f"{event_type}:{finding_id}@{finding_version}:{request_id}"):
            raise ValueError("finding lifecycle subject, version or event ID is invalid")
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
            raise ValueError("finding lifecycle requires exact evidence ID/version/SHA-256/size")
        evidence_refs = payload.get("evidence_refs")
        if (not isinstance(evidence_refs, list) or len(evidence_refs) != 1
                or not isinstance(evidence_refs[0], dict)):
            raise ValueError("finding lifecycle requires exactly one byte-verifiable evidence reference")
        ref = evidence_refs[0]
        if (ref.get("evidence_id") != binding["evidence_id"]
                or ref.get("version") != binding["evidence_version"]
                or ref.get("sha256") != binding["sha256"]
                or ref.get("size_bytes") != binding["size_bytes"]
                or not isinstance(ref.get("relative_path"), str) or not ref["relative_path"].strip()):
            raise ValueError("finding lifecycle evidence reference does not match its exact binding")
        if (approval.artifact_id != binding["evidence_id"]
                or approval.artifact_version != binding["evidence_version"]
                or approval.artifact_sha256 != binding["sha256"]
                or approval.artifact_size_bytes != binding["size_bytes"]
                or not approval.subject_id or not approval.actor_id
                or not approval.actor_role or not approval.authn_context
                or not approval.identity_session_id or not approval.identity_policy_version
                or not approval.identity_provider_id or approval.authenticated_at is None):
            raise ValueError("finding lifecycle approval is not bound to its evidence or identity claims")
        if event_type == "FINDING_RESEARCHED":
            required = {
                "schema", "finding_id", "finding_version", "research_question", "methodology",
                "findings", "knowledge_gaps", "limitations", "evidence_id", "evidence_version",
                "evidence_binding", "evidence_refs", "created_at_utc",
            }
            if set(payload) != required or payload.get("schema") != "raei-finding-research-v1":
                raise ValueError("research event payload has an invalid field set or schema")
            for field in ("research_question", "methodology", "created_at_utc"):
                if not isinstance(payload.get(field), str) or not payload[field].strip():
                    raise ValueError(f"{field} must be non-empty text")
            for field in ("findings", "knowledge_gaps", "limitations"):
                if (not isinstance(payload.get(field), list)
                        or any(not isinstance(item, str) or not item.strip() for item in payload[field])):
                    raise ValueError(f"{field} must be a list of non-empty strings")
        elif event_type == "FINDING_REPRODUCED":
            required = {
                "schema", "finding_id", "finding_version", "outcome", "environment", "steps",
                "expected_behavior", "observed_behavior", "evidence_id", "evidence_version",
                "evidence_binding", "evidence_refs", "created_at_utc",
            }
            if set(payload) != required or payload.get("schema") != "raei-finding-reproduction-v1":
                raise ValueError("reproduction event payload has an invalid field set or schema")
            if payload.get("outcome") not in {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"}:
                raise ValueError("reproduction outcome is unsupported")
            for field in ("environment", "expected_behavior", "observed_behavior", "created_at_utc"):
                if not isinstance(payload.get(field), str) or not payload[field].strip():
                    raise ValueError(f"{field} must be non-empty text")
            if (not isinstance(payload.get("steps"), list) or not payload["steps"]
                    or any(not isinstance(item, str) or not item.strip() for item in payload["steps"])):
                raise ValueError("reproduction steps must be a non-empty list of strings")
        else:
            required = {
                "schema", "finding_id", "finding_version", "plan_objective", "scope",
                "tasks", "milestones", "acceptance_criteria", "dependencies", "risks",
                "rollback_plan", "evidence_id", "evidence_version", "evidence_binding",
                "evidence_refs", "created_at_utc",
            }
            if set(payload) != required or payload.get("schema") != "raei-finding-plan-v1":
                raise ValueError("plan event payload has an invalid field set or schema")
            for field in ("plan_objective", "scope", "rollback_plan", "created_at_utc"):
                if not isinstance(payload.get(field), str) or not payload[field].strip():
                    raise ValueError(f"{field} must be non-empty text")
            for field in ("tasks", "milestones", "acceptance_criteria", "dependencies", "risks"):
                if (not isinstance(payload.get(field), list)
                        or (field in {"tasks", "milestones", "acceptance_criteria"} and not payload[field])
                        or any(not isinstance(item, str) or not item.strip() for item in payload[field])):
                    raise ValueError(f"{field} must be a valid list of non-empty strings")
        if (payload.get("evidence_id") != binding["evidence_id"]
                or payload.get("evidence_version") != binding["evidence_version"]):
            raise ValueError("finding lifecycle evidence ID/version does not match its binding")
        enriched = dict(payload)
        enriched["authorization"] = {
            "issuer": approval.issuer,
            "approval_id": approval.approval_id,
            "actor_id": approval.actor_id,
            "subject_id": approval.subject_id,
            "actor_role": approval.actor_role,
            "action": approval.action,
            "identity_provider_id": approval.identity_provider_id,
            "identity_policy_version": approval.identity_policy_version,
            "identity_session_id": approval.identity_session_id,
            "authenticated_at_utc": approval.authenticated_at.isoformat(),
            "project_id": project_id,
            "project_version": project_version,
            "request_id": request_id,
            "artifact_sha256": binding["sha256"],
            "artifact_size_bytes": binding["size_bytes"],
            "signature_sha256": hashlib.sha256((approval.signature or "").encode("ascii")).hexdigest(),
        }
        normalised = self._normalise(enriched)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT event_type,project_id,subject_id,payload_json FROM activity_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if existing:
                if existing != (event_type, project_id, finding_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("finding lifecycle event ID was replayed with different data")
                db.commit()
                return False
            captured_rows = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (project_id, finding_id),
            ).fetchall()
            captured = next(
                (json.loads(row[0]) for row in captured_rows
                 if json.loads(row[0]).get("version") == finding_version),
                None,
            )
            if not captured:
                db.rollback()
                raise ValueError("finding lifecycle requires the exact captured finding version")
            prior_research = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type='FINDING_RESEARCHED' AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (project_id, finding_id),
            ).fetchall()
            prior_reproduction = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type='FINDING_REPRODUCED' AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (project_id, finding_id),
            ).fetchall()
            prior_disposition = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type='FINDING_DISPOSITIONED' AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (project_id, finding_id),
            ).fetchall()
            prior_plans = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type='FINDING_PLANNED' AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (project_id, finding_id),
            ).fetchall()
            def matches_version(rows):
                return [json.loads(row[0]) for row in rows
                        if json.loads(row[0]).get("finding_version") == finding_version]
            research_for_version = matches_version(prior_research)
            reproduction_for_version = matches_version(prior_reproduction)
            disposition_for_version = matches_version(prior_disposition)
            plans_for_version = matches_version(prior_plans)
            if disposition_for_version and event_type in {"FINDING_RESEARCHED", "FINDING_REPRODUCED"}:
                db.rollback()
                raise ValueError("a finding cannot be researched or reproduced after disposition")
            if event_type == "FINDING_RESEARCHED":
                if research_for_version or reproduction_for_version:
                    db.rollback()
                    raise ValueError("finding research is already recorded for this version")
            elif event_type == "FINDING_REPRODUCED":
                if not research_for_version:
                    db.rollback()
                    raise ValueError("finding reproduction requires prior research for this version")
                if reproduction_for_version:
                    db.rollback()
                    raise ValueError("finding reproduction is already recorded for this version")
                research_auth = research_for_version[-1].get("authorization", {})
                researcher = research_auth.get("subject_id")
                research_session = research_auth.get("identity_session_id")
                submitter_identity = captured.get("submitter_identity", {})
                submitter = submitter_identity.get("subject_id")
                submitter_session = submitter_identity.get("identity_session_id")
                if (approval.subject_id == researcher
                        or approval.identity_session_id == research_session
                        or (submitter and approval.subject_id == submitter)
                        or (submitter_session and approval.identity_session_id == submitter_session)):
                    db.rollback()
                    raise ValueError("reproduction requires an independent human subject and session")
                if (approval.identity_provider_id != research_auth.get("identity_provider_id")
                        or approval.identity_policy_version != research_auth.get("identity_policy_version")
                        or (submitter_identity and (
                            approval.identity_provider_id != submitter_identity.get("identity_provider_id")
                            or approval.identity_policy_version != submitter_identity.get("identity_policy_version")
                        ))):
                    db.rollback()
                    raise ValueError("reproduction identity provider and policy must match the original trusted identity domain")
            else:
                if not research_for_version or not reproduction_for_version:
                    db.rollback()
                    raise ValueError("finding plan requires prior research and reproduction")
                if reproduction_for_version[-1].get("outcome") != "REPRODUCED":
                    db.rollback()
                    raise ValueError("finding plan requires a REPRODUCED outcome")
                if not disposition_for_version or disposition_for_version[-1].get("disposition") != "ACCEPTED":
                    db.rollback()
                    raise ValueError("finding plan requires an accepted governed disposition")
                if plans_for_version:
                    db.rollback()
                    raise ValueError("finding plan is already recorded for this version")
                research_auth = research_for_version[-1].get("authorization", {})
                reproduction_auth = reproduction_for_version[-1].get("authorization", {})
                submitter_identity = captured.get("submitter_identity", {})
                prior_identities = [research_auth, reproduction_auth]
                if submitter_identity:
                    prior_identities.append(submitter_identity)
                if any(
                    approval.subject_id == item.get("subject_id")
                    or approval.identity_session_id == item.get("identity_session_id")
                    or approval.identity_provider_id != item.get("identity_provider_id")
                    or approval.identity_policy_version != item.get("identity_policy_version")
                    for item in prior_identities
                ):
                    db.rollback()
                    raise ValueError("finding plan requires an independent planner in the same trusted identity domain")
            self._append_event_tx(db, event_id, event_type, normalised, project_id, finding_id)
            db.commit()
        return True

    def append_authenticated_finding_implementation_event(
        self, event_id: str, payload: dict[str, Any], *,
        project_id: str, project_version: str, request_id: str, approval: Any,
    ) -> bool:
        """Append an implementation report bound to the exact previously accepted plan."""
        from datetime import datetime, timezone
        from rhemascript.core.approvals import is_consumed_verified_approval

        if not is_consumed_verified_approval(approval):
            raise ValueError("implementation requires a verifier-issued, consumed approval")
        if (approval.credential_schema != "RhemaScript.ApprovalCredential.v3"
                or approval.action != "FINDING_IMPLEMENT"
                or approval.project_id != project_id
                or approval.project_version != project_version
                or approval.request_id != request_id
                or approval.expires_at <= datetime.now(timezone.utc)):
            raise ValueError("implementation approval schema, action, scope or expiry is invalid")
        for name, value in (("event_id", event_id), ("project_id", project_id),
                            ("project_version", project_version), ("request_id", request_id)):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty trimmed text")
        if not isinstance(payload, dict) or "authorization" in payload:
            raise ValueError("implementation payload must be an object without caller authorization")
        required = {
            "schema", "finding_id", "finding_version", "plan_event_id", "plan_evidence_binding",
            "implementation_summary", "changes", "test_results", "deviations", "rollback_reference",
            "evidence_id", "evidence_version", "evidence_binding", "evidence_refs", "created_at_utc",
        }
        if set(payload) != required or payload.get("schema") != "raei-finding-implementation-v1":
            raise ValueError("implementation report has an invalid field set or schema")
        for field in ("finding_id", "finding_version", "plan_event_id", "implementation_summary",
                      "rollback_reference", "evidence_id", "evidence_version", "created_at_utc"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise ValueError(f"{field} must be non-empty text")
        for field in ("changes", "test_results", "deviations"):
            if (not isinstance(payload.get(field), list)
                    or (field in {"changes", "test_results"} and not payload[field])
                    or any(not isinstance(item, str) or not item.strip() for item in payload[field])):
                raise ValueError(f"{field} must be a valid list of non-empty strings")
        binding = payload.get("evidence_binding")
        plan_binding = payload.get("plan_evidence_binding")
        if (not isinstance(binding, dict)
                or set(binding) != {"evidence_id", "evidence_version", "sha256", "size_bytes"}
                or not isinstance(plan_binding, dict)
                or set(plan_binding) != {"evidence_id", "evidence_version", "sha256", "size_bytes"}):
            raise ValueError("implementation requires exact implementation and plan evidence bindings")
        for item in (binding, plan_binding):
            if (not isinstance(item.get("evidence_id"), str) or not item["evidence_id"].strip()
                    or not isinstance(item.get("evidence_version"), str) or not item["evidence_version"].strip()
                    or not isinstance(item.get("sha256"), str)
                    or len(item["sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in item["sha256"])
                    or not isinstance(item.get("size_bytes"), int)
                    or isinstance(item.get("size_bytes"), bool) or item["size_bytes"] < 0):
                raise ValueError("implementation evidence binding is malformed")
        refs = payload.get("evidence_refs")
        if (payload.get("evidence_id") != binding["evidence_id"]
                or payload.get("evidence_version") != binding["evidence_version"]
                or not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict)
                or any(refs[0].get(k) != binding[v] for k, v in (
                    ("evidence_id", "evidence_id"), ("version", "evidence_version"),
                    ("sha256", "sha256"), ("size_bytes", "size_bytes")))
                or not isinstance(refs[0].get("relative_path"), str)
                or not refs[0]["relative_path"].strip()):
            raise ValueError("implementation evidence reference does not match its exact binding")
        if (approval.artifact_id != binding["evidence_id"]
                or approval.artifact_version != binding["evidence_version"]
                or approval.artifact_sha256 != binding["sha256"]
                or approval.artifact_size_bytes != binding["size_bytes"]
                or not all((approval.subject_id, approval.actor_id, approval.actor_role,
                            approval.authn_context, approval.identity_session_id,
                            approval.identity_policy_version, approval.identity_provider_id,
                            approval.authenticated_at))):
            raise ValueError("implementation approval is not bound to evidence or identity claims")
        finding_id, finding_version = payload["finding_id"], payload["finding_version"]
        if event_id != f"FINDING_IMPLEMENTED:{finding_id}@{finding_version}:{request_id}":
            raise ValueError("implementation event ID is invalid")
        enriched = dict(payload)
        enriched["authorization"] = {
            "issuer": approval.issuer, "approval_id": approval.approval_id,
            "actor_id": approval.actor_id, "subject_id": approval.subject_id,
            "actor_role": approval.actor_role, "action": approval.action,
            "identity_provider_id": approval.identity_provider_id,
            "identity_policy_version": approval.identity_policy_version,
            "identity_session_id": approval.identity_session_id,
            "authenticated_at_utc": approval.authenticated_at.isoformat(),
            "project_id": project_id, "project_version": project_version,
            "request_id": request_id, "artifact_sha256": binding["sha256"],
            "artifact_size_bytes": binding["size_bytes"],
            "signature_sha256": hashlib.sha256((approval.signature or "").encode("ascii")).hexdigest(),
        }
        normalised = self._normalise(enriched)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT event_type,project_id,subject_id,payload_json FROM activity_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if existing:
                if existing != ("FINDING_IMPLEMENTED", project_id, finding_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("implementation event ID was replayed with different data")
                db.commit()
                return False
            captured_rows = db.execute(
                "SELECT payload_json FROM activity_events WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?",
                (project_id, finding_id),
            ).fetchall()
            captured = next((json.loads(row[0]) for row in captured_rows
                             if json.loads(row[0]).get("version") == finding_version), None)
            plans = db.execute(
                "SELECT event_id,payload_json FROM activity_events WHERE event_type='FINDING_PLANNED' AND project_id=? AND subject_id=? ORDER BY sequence",
                (project_id, finding_id),
            ).fetchall()
            plan = next(((eid, json.loads(raw)) for eid, raw in plans
                         if json.loads(raw).get("finding_version") == finding_version), None)
            if not captured or not plan:
                db.rollback()
                raise ValueError("implementation requires the exact captured finding and approved plan")
            plan_event_id, plan_payload = plan
            actual_plan_binding = plan_payload.get("evidence_binding")
            plan_auth = plan_payload.get("authorization", {})
            if (payload["plan_event_id"] != plan_event_id
                    or payload["plan_evidence_binding"] != actual_plan_binding
                    or plan_payload.get("finding_version") != finding_version
                    or plan_auth.get("project_version") != project_version
                    or plan_auth.get("identity_provider_id") != approval.identity_provider_id
                    or plan_auth.get("identity_policy_version") != approval.identity_policy_version):
                db.rollback()
                raise ValueError("implementation does not bind the exact approved plan event and evidence")
            if sum(1 for eid, raw in plans if json.loads(raw).get("finding_version") == finding_version) != 1:
                db.rollback()
                raise ValueError("implementation requires exactly one approved plan")
            prior_events = db.execute(
                """SELECT event_type,payload_json FROM activity_events
                WHERE project_id=? AND subject_id=? AND event_type IN
                ('FINDING_RESEARCHED','FINDING_REPRODUCED','FINDING_PLANNED','FINDING_IMPLEMENTED')
                ORDER BY sequence""", (project_id, finding_id),
            ).fetchall()
            if any(kind == "FINDING_IMPLEMENTED" and json.loads(raw).get("finding_version") == finding_version
                   for kind, raw in prior_events):
                db.rollback()
                raise ValueError("implementation is already recorded for this finding version")
            if not any(kind == "FINDING_REPRODUCED" and json.loads(raw).get("finding_version") == finding_version
                       and json.loads(raw).get("outcome") == "REPRODUCED" for kind, raw in prior_events):
                db.rollback()
                raise ValueError("implementation requires a reproduced finding")
            prior_auth = []
            submitter = captured.get("submitter_identity")
            if submitter:
                prior_auth.append(submitter)
            for kind, raw in prior_events:
                event_payload = json.loads(raw)
                if event_payload.get("finding_version") == finding_version:
                    prior_auth.append(event_payload.get("authorization", {}))
            for prior in prior_auth:
                if (approval.subject_id == prior.get("subject_id")
                        or approval.identity_session_id == prior.get("identity_session_id")
                        or approval.identity_provider_id != prior.get("identity_provider_id")
                        or approval.identity_policy_version != prior.get("identity_policy_version")):
                    db.rollback()
                    raise ValueError("implementation requires an independent implementer in the same trusted identity domain")
            self._append_event_tx(db, event_id, "FINDING_IMPLEMENTED", normalised, project_id, finding_id)
            db.commit()
        return True

    def append_authenticated_finding_effectiveness_event(
        self, event_id: str, payload: dict[str, Any], *,
        project_id: str, project_version: str, request_id: str, approval: Any,
    ) -> bool:
        """Append an independent outcome assessment bound to the exact implementation."""
        from datetime import datetime, timezone
        from rhemascript.core.approvals import is_consumed_verified_approval

        if not is_consumed_verified_approval(approval):
            raise ValueError("effectiveness assessment requires a verifier-issued, consumed approval")
        if (approval.credential_schema != "RhemaScript.ApprovalCredential.v3"
                or approval.action != "FINDING_EFFECTIVENESS_ASSESS"
                or approval.project_id != project_id or approval.project_version != project_version
                or approval.request_id != request_id or approval.expires_at <= datetime.now(timezone.utc)):
            raise ValueError("effectiveness approval schema, action, scope or expiry is invalid")
        for name, value in (("event_id", event_id), ("project_id", project_id),
                            ("project_version", project_version), ("request_id", request_id)):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty trimmed text")
        if not isinstance(payload, dict) or "authorization" in payload:
            raise ValueError("effectiveness payload must be an object without caller authorization")
        required = {
            "schema", "finding_id", "finding_version", "implementation_event_id",
            "implementation_evidence_binding", "outcome", "criteria_results", "observed_outcomes",
            "residual_risks", "evidence_id", "evidence_version", "evidence_binding",
            "evidence_refs", "created_at_utc",
        }
        if set(payload) != required or payload.get("schema") != "raei-finding-effectiveness-v1":
            raise ValueError("effectiveness report has an invalid field set or schema")
        for field in ("finding_id", "finding_version", "implementation_event_id",
                      "evidence_id", "evidence_version", "created_at_utc"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise ValueError(f"{field} must be non-empty text")
        if payload.get("outcome") not in {"EFFECTIVE", "INEFFECTIVE", "INCONCLUSIVE"}:
            raise ValueError("effectiveness outcome is unsupported")
        for field in ("criteria_results", "observed_outcomes"):
            if (not isinstance(payload.get(field), list) or not payload[field]
                    or any(not isinstance(item, str) or not item.strip() for item in payload[field])):
                raise ValueError(f"{field} must be a non-empty list of non-empty strings")
        risks = payload.get("residual_risks")
        if not isinstance(risks, list) or any(not isinstance(item, str) or not item.strip() for item in risks):
            raise ValueError("residual_risks must be a list of non-empty strings")
        binding = payload.get("evidence_binding")
        implementation_binding = payload.get("implementation_evidence_binding")
        if (not isinstance(binding, dict) or set(binding) != {"evidence_id", "evidence_version", "sha256", "size_bytes"}
                or not isinstance(implementation_binding, dict)
                or set(implementation_binding) != {"evidence_id", "evidence_version", "sha256", "size_bytes"}):
            raise ValueError("effectiveness requires exact assessment and implementation evidence bindings")
        for item in (binding, implementation_binding):
            if (not isinstance(item.get("evidence_id"), str) or not item["evidence_id"].strip()
                    or not isinstance(item.get("evidence_version"), str) or not item["evidence_version"].strip()
                    or not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in item["sha256"])
                    or not isinstance(item.get("size_bytes"), int) or isinstance(item.get("size_bytes"), bool)
                    or item["size_bytes"] < 0):
                raise ValueError("effectiveness evidence binding is malformed")
        refs = payload.get("evidence_refs")
        if (payload.get("evidence_id") != binding["evidence_id"]
                or payload.get("evidence_version") != binding["evidence_version"]
                or not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict)
                or any(refs[0].get(k) != binding[v] for k, v in (
                    ("evidence_id", "evidence_id"), ("version", "evidence_version"),
                    ("sha256", "sha256"), ("size_bytes", "size_bytes")))
                or not isinstance(refs[0].get("relative_path"), str) or not refs[0]["relative_path"].strip()):
            raise ValueError("effectiveness evidence reference does not match its exact binding")
        if (approval.artifact_id != binding["evidence_id"]
                or approval.artifact_version != binding["evidence_version"]
                or approval.artifact_sha256 != binding["sha256"]
                or approval.artifact_size_bytes != binding["size_bytes"]
                or not all((approval.subject_id, approval.actor_id, approval.actor_role,
                            approval.authn_context, approval.identity_session_id,
                            approval.identity_policy_version, approval.identity_provider_id,
                            approval.authenticated_at))):
            raise ValueError("effectiveness approval is not bound to evidence or identity claims")
        finding_id, finding_version = payload["finding_id"], payload["finding_version"]
        if event_id != f"FINDING_EFFECTIVENESS_ASSESSED:{finding_id}@{finding_version}:{request_id}":
            raise ValueError("effectiveness event ID is invalid")
        enriched = dict(payload)
        enriched["authorization"] = {
            "issuer": approval.issuer, "approval_id": approval.approval_id,
            "actor_id": approval.actor_id, "subject_id": approval.subject_id,
            "actor_role": approval.actor_role, "action": approval.action,
            "identity_provider_id": approval.identity_provider_id,
            "identity_policy_version": approval.identity_policy_version,
            "identity_session_id": approval.identity_session_id,
            "authenticated_at_utc": approval.authenticated_at.isoformat(),
            "project_id": project_id, "project_version": project_version,
            "request_id": request_id, "artifact_sha256": binding["sha256"],
            "artifact_size_bytes": binding["size_bytes"],
            "signature_sha256": hashlib.sha256((approval.signature or "").encode("ascii")).hexdigest(),
        }
        normalised = self._normalise(enriched)
        encoded = self._canonical(normalised)
        if not self.verify():
            raise ValueError("cannot append to an invalid activity history")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT event_type,project_id,subject_id,payload_json FROM activity_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if existing:
                if existing != ("FINDING_EFFECTIVENESS_ASSESSED", project_id, finding_id, encoded):
                    db.rollback()
                    raise ReadinessReplayError("effectiveness event ID was replayed with different data")
                db.commit()
                return False
            rows = db.execute(
                """SELECT event_id,event_type,payload_json FROM activity_events
                WHERE project_id=? AND subject_id=? AND event_type IN
                ('FINDING_RESEARCHED','FINDING_REPRODUCED','FINDING_PLANNED','FINDING_IMPLEMENTED',
                 'FINDING_EFFECTIVENESS_ASSESSED') ORDER BY sequence""",
                (project_id, finding_id),
            ).fetchall()
            same_version = [(eid, kind, json.loads(raw)) for eid, kind, raw in rows
                            if json.loads(raw).get("finding_version") == finding_version]
            implementations = [(eid, item) for eid, kind, item in same_version if kind == "FINDING_IMPLEMENTED"]
            if len(implementations) != 1:
                db.rollback()
                raise ValueError("effectiveness requires exactly one prior implementation")
            impl_event_id, impl_payload = implementations[0]
            if (payload["implementation_event_id"] != impl_event_id
                    or payload["implementation_evidence_binding"] != impl_payload.get("evidence_binding")
                    or impl_payload.get("authorization", {}).get("project_version") != project_version):
                db.rollback()
                raise ValueError("effectiveness assessment does not bind the exact implementation event and evidence")
            if any(kind == "FINDING_EFFECTIVENESS_ASSESSED" for _, kind, _ in same_version):
                db.rollback()
                raise ValueError("effectiveness assessment is already recorded for this finding version")
            prior_auth = [item.get("authorization", {}) for _, kind, item in same_version
                          if kind in {"FINDING_RESEARCHED", "FINDING_REPRODUCED", "FINDING_PLANNED", "FINDING_IMPLEMENTED"}]
            captured_rows = db.execute(
                "SELECT payload_json FROM activity_events WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?",
                (project_id, finding_id),
            ).fetchall()
            captured = next((json.loads(raw) for (raw,) in captured_rows
                             if json.loads(raw).get("version") == finding_version), {})
            if captured.get("submitter_identity"):
                prior_auth.append(captured["submitter_identity"])
            for prior in prior_auth:
                if (approval.subject_id == prior.get("subject_id")
                        or approval.identity_session_id == prior.get("identity_session_id")
                        or approval.identity_provider_id != prior.get("identity_provider_id")
                        or approval.identity_policy_version != prior.get("identity_policy_version")):
                    db.rollback()
                    raise ValueError("effectiveness requires an independent assessor in the same trusted identity domain")
            self._append_event_tx(db, event_id, "FINDING_EFFECTIVENESS_ASSESSED", normalised, project_id, finding_id)
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
        from rhemascript.core.approvals import is_consumed_verified_approval

        if event_type not in {"FINDING_DISPOSITIONED", "FINDING_CLOSED", "FINDING_REOPENED", "KNOWLEDGE_REVIEWED"}:
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
            else ("FINDING_CLOSURE_REVIEW", "FINDING_CLOSURE_CONFIRM") if event_type == "FINDING_CLOSED"
            else ("FINDING_REOPEN_REVIEW", "FINDING_REOPEN_CONFIRM") if event_type == "FINDING_REOPENED"
            else ("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM")
        )
        if expected_actions != required_actions:
            raise ValueError("governed event approval actions do not match the event policy")
        if any(not is_consumed_verified_approval(item) for item in approvals):
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
        elif event_type == "FINDING_CLOSED":
            required = {"finding_id", "finding_version", "closure_decision", "rationale", "evidence_binding", "lifecycle_lineage"}
            decisions = {"CLOSED"}
            identity_field, version_field = "finding_id", "finding_version"
        elif event_type == "FINDING_REOPENED":
            required = {"finding_id", "finding_version", "new_finding_version", "reopen_decision", "rationale", "evidence_binding", "closure_event_id"}
            decisions = {"REOPENED"}
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
        decision_field = "disposition" if event_type == "FINDING_DISPOSITIONED" else "closure_decision" if event_type == "FINDING_CLOSED" else "reopen_decision" if event_type == "FINDING_REOPENED" else "decision"
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
        if event_type in {"FINDING_CLOSED", "FINDING_REOPENED"}:
            if event_type == "FINDING_CLOSED":
                lineage = payload.get("lifecycle_lineage")
                if (not isinstance(lineage, dict)
                        or set(lineage) != {"plan_event_id", "implementation_event_id", "effectiveness_event_id"}
                        or any(not isinstance(value, str) or not value.strip() for value in lineage.values())):
                    raise ValueError("closure requires exact plan, implementation and effectiveness event IDs")
            else:
                new_version = payload.get("new_finding_version")
                if not isinstance(new_version, str) or not new_version.strip() or new_version == version:
                    raise ValueError("reopening requires a distinct proposed new finding version")
            subjects = [item.subject_id for item in approvals]
            sessions = [item.identity_session_id for item in approvals]
            if (any(not value for value in subjects + sessions)
                    or len(set(subjects)) != 2 or len(set(sessions)) != 2
                    or any(item.artifact_id != binding["evidence_id"]
                           or item.artifact_version != binding["evidence_version"]
                           or item.artifact_sha256 != binding["sha256"]
                           or item.artifact_size_bytes != binding["size_bytes"] for item in approvals)
                    or len({item.identity_provider_id for item in approvals}) != 1
                    or len({item.identity_policy_version for item in approvals}) != 1
                    or any(item.credential_schema != "RhemaScript.ApprovalCredential.v3" for item in approvals)):
                raise ValueError("governed finding transition requires two distinct authenticated subjects and sessions in one trusted identity domain")
        enriched = dict(payload)
        enriched["authorization"] = {
            "issuer": approvals[0].issuer,
            "actor_ids": actors,
            "approval_ids": [item.approval_id for item in approvals],
            "actions": [item.action for item in approvals],
            "subject_ids": [item.subject_id for item in approvals],
            "identity_session_ids": [item.identity_session_id for item in approvals],
            "identity_provider_ids": [item.identity_provider_id for item in approvals],
            "identity_policy_versions": [item.identity_policy_version for item in approvals],
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
            if event_type == "FINDING_DISPOSITIONED":
                captured = db.execute(
                    """SELECT payload_json FROM activity_events
                    WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?
                    ORDER BY sequence DESC""",
                    (project_id, subject_id),
                ).fetchall()
                captured_payload = next(
                    (json.loads(row[0]) for row in captured
                     if json.loads(row[0]).get("version") == payload.get("finding_version")),
                    None,
                )
                if not captured_payload:
                    db.rollback()
                    raise ValueError("finding disposition requires the exact captured finding version")
                # A disposition may rely on original captured evidence or on a
                # previously authenticated research/reproduction report for this
                # exact finding version. Never accept an arbitrary later file.
                eligible_bindings = []
                for ref in captured_payload.get("evidence_refs", []):
                    if isinstance(ref, dict):
                        eligible_bindings.append({
                            "evidence_id": ref.get("evidence_id"),
                            "evidence_version": ref.get("version"),
                            "sha256": ref.get("sha256"),
                            "size_bytes": ref.get("size_bytes"),
                        })
                prior_evidence_rows = db.execute(
                    """SELECT event_type, payload_json FROM activity_events
                    WHERE event_type IN ('FINDING_RESEARCHED','FINDING_REPRODUCED')
                    AND project_id=? AND subject_id=?
                    ORDER BY sequence ASC""",
                    (project_id, subject_id),
                ).fetchall()
                for prior_type, prior_json in prior_evidence_rows:
                    prior_payload = json.loads(prior_json)
                    if prior_payload.get("finding_version") != payload.get("finding_version"):
                        continue
                    prior_binding = prior_payload.get("evidence_binding")
                    if isinstance(prior_binding, dict):
                        eligible_bindings.append({
                            "evidence_id": prior_binding.get("evidence_id"),
                            "evidence_version": prior_binding.get("evidence_version"),
                            "sha256": prior_binding.get("sha256"),
                            "size_bytes": prior_binding.get("size_bytes"),
                        })
                if not any(
                    item == {
                        "evidence_id": binding["evidence_id"],
                        "evidence_version": binding["evidence_version"],
                        "sha256": binding["sha256"],
                        "size_bytes": binding["size_bytes"],
                    }
                    for item in eligible_bindings
                ):
                    db.rollback()
                    raise ValueError(
                        "finding disposition evidence must be bound to the captured finding "
                        "or a prior authenticated research/reproduction report"
                    )
            elif event_type == "KNOWLEDGE_REVIEWED":
                run_id = f"KNOWLEDGE:{subject_id}:{payload.get('knowledge_version')}"
                stored = db.execute(
                    "SELECT payload_json FROM readiness_runs WHERE run_id=?",
                    (run_id,),
                ).fetchone()
                if not stored:
                    db.rollback()
                    raise ValueError("knowledge review requires an existing evidence-bound knowledge item")
                stored_payload = json.loads(stored[0])
                report = stored_payload.get("report", {})
                knowledge = report.get("knowledge_payload", {}) if isinstance(report, dict) else {}
                evidence_items = stored_payload.get("byte_verified_evidence", [])
                stored_binding = report.get("evidence_binding", {}) if isinstance(report, dict) else {}
                if (knowledge.get("status") != "PENDING_REVIEW"
                        or len(evidence_items) != 1
                        or not isinstance(evidence_items[0], dict)
                        or stored_binding.get("evidence_id") != binding["evidence_id"]
                        or stored_binding.get("evidence_version") != binding["evidence_version"]
                        or stored_binding.get("evidence_sha256") != binding["sha256"]
                        or evidence_items[0].get("size_bytes") != binding["size_bytes"]):
                    db.rollback()
                    raise ValueError("knowledge review evidence does not match the pending knowledge record")
            elif event_type in {"FINDING_CLOSED", "FINDING_REOPENED"}:
                captured_rows = db.execute(
                    "SELECT payload_json FROM activity_events WHERE event_type='FINDING_CAPTURED' AND project_id=? AND subject_id=?",
                    (project_id, subject_id),
                ).fetchall()
                captured = next((json.loads(raw) for (raw,) in captured_rows
                                 if json.loads(raw).get("version") == payload.get("finding_version")), None)
                if not captured:
                    db.rollback()
                    raise ValueError("governed finding transition requires the exact captured finding version")
                if event_type == "FINDING_REOPENED":
                    closure_rows = db.execute(
                        """SELECT event_id,payload_json FROM activity_events
                        WHERE event_type='FINDING_CLOSED' AND project_id=? AND subject_id=? ORDER BY sequence DESC""",
                        (project_id, subject_id),
                    ).fetchall()
                    closure = next(((eid, json.loads(raw)) for eid, raw in closure_rows
                                    if json.loads(raw).get("finding_version") == payload.get("finding_version")), None)
                    if (not closure or closure[0] != payload.get("closure_event_id")
                            or closure[1].get("closure_decision") != "CLOSED"
                            or binding != closure[1].get("evidence_binding")):
                        db.rollback()
                        raise ValueError("reopening must reference the exact closed finding event and its evidence")
                    prior_reviewers = closure[1].get("authorization", {})
                    if prior_reviewers.get("project_version") != project_version:
                        db.rollback()
                        raise ValueError("reopening project version must match the exact prior closure scope")
                    if any(
                        approval.subject_id == prior_subject
                        or approval.identity_session_id == prior_session
                        for approval in approvals
                        for prior_subject, prior_session in zip(
                            prior_reviewers.get("subject_ids", []),
                            prior_reviewers.get("identity_session_ids", []),
                        )
                    ) or any(
                        approval.identity_provider_id != prior_provider
                        or approval.identity_policy_version != prior_policy
                        for approval in approvals
                        for prior_provider, prior_policy in zip(
                            prior_reviewers.get("identity_provider_ids", []),
                            prior_reviewers.get("identity_policy_versions", []),
                        )
                    ):
                        db.rollback()
                        raise ValueError("reopening reviewers must be independent from closure reviewers in the same identity domain")
                    if any(
                        event_type == "FINDING_REOPENED"
                        and json.loads(raw).get("finding_version") == payload.get("finding_version")
                        for (raw,) in db.execute(
                            "SELECT payload_json FROM activity_events WHERE event_type='FINDING_REOPENED' AND project_id=? AND subject_id=?",
                            (project_id, subject_id),
                        ).fetchall()
                    ):
                        db.rollback()
                        raise ValueError("finding version has already been reopened")
                else:
                    lineage_rows = db.execute(
                        """SELECT event_id,event_type,payload_json FROM activity_events
                        WHERE project_id=? AND subject_id=? AND event_type IN
                        ('FINDING_RESEARCHED','FINDING_REPRODUCED','FINDING_PLANNED',
                         'FINDING_IMPLEMENTED','FINDING_EFFECTIVENESS_ASSESSED')
                        ORDER BY sequence""", (project_id, subject_id),
                    ).fetchall()
                    lineage = {kind: (eid, json.loads(raw)) for eid, kind, raw in lineage_rows
                               if json.loads(raw).get("finding_version") == payload.get("finding_version")}
                    required_lineage = (
                        "FINDING_RESEARCHED", "FINDING_REPRODUCED", "FINDING_PLANNED",
                        "FINDING_IMPLEMENTED", "FINDING_EFFECTIVENESS_ASSESSED",
                    )
                    if not all(kind in lineage for kind in required_lineage):
                        db.rollback()
                        raise ValueError("closure requires research, reproduction, plan, implementation and effectiveness evidence")
                    research_payload = lineage["FINDING_RESEARCHED"][1]
                    reproduction_payload = lineage["FINDING_REPRODUCED"][1]
                    plan_id, plan_payload = lineage["FINDING_PLANNED"]
                    implementation_id, implementation_payload = lineage["FINDING_IMPLEMENTED"]
                    effectiveness_id, effectiveness_payload = lineage["FINDING_EFFECTIVENESS_ASSESSED"]
                    expected_lineage = {
                        "plan_event_id": plan_id,
                        "implementation_event_id": implementation_id,
                        "effectiveness_event_id": effectiveness_id,
                    }
                    if payload.get("lifecycle_lineage") != expected_lineage:
                        db.rollback()
                        raise ValueError("closure does not bind the exact lifecycle event lineage")
                    if (effectiveness_payload.get("outcome") != "EFFECTIVE"
                            or binding != effectiveness_payload.get("evidence_binding")):
                        db.rollback()
                        raise ValueError("only an EFFECTIVE assessment and its exact evidence can be closed")
                    prior_identities = [
                        research_payload.get("authorization", {}),
                        reproduction_payload.get("authorization", {}),
                        plan_payload.get("authorization", {}),
                        implementation_payload.get("authorization", {}),
                        effectiveness_payload.get("authorization", {}),
                    ]
                    if captured.get("submitter_identity"):
                        prior_identities.append(captured["submitter_identity"])
                    if any(
                        approval.subject_id == prior.get("subject_id")
                        or approval.identity_session_id == prior.get("identity_session_id")
                        or approval.identity_provider_id != prior.get("identity_provider_id")
                        or approval.identity_policy_version != prior.get("identity_policy_version")
                        for approval in approvals for prior in prior_identities
                    ):
                        db.rollback()
                        raise ValueError("closure reviewers must be independent of lifecycle participants")
            prior_rows = db.execute(
                """SELECT payload_json FROM activity_events
                WHERE event_type=? AND project_id=? AND subject_id=?
                ORDER BY sequence DESC""",
                (event_type, project_id, subject_id),
            ).fetchall()
            version_field = "knowledge_version" if event_type == "KNOWLEDGE_REVIEWED" else "finding_version"
            same_version_prior = [
                json.loads(row[0]) for row in prior_rows
                if json.loads(row[0]).get(version_field) == payload.get(version_field)
            ]
            if event_type in {"KNOWLEDGE_REVIEWED", "FINDING_CLOSED", "FINDING_REOPENED"} and same_version_prior:
                db.rollback()
                raise ValueError("a knowledge/finding version may receive only one terminal review or reopen decision")
            if event_type == "FINDING_DISPOSITIONED" and same_version_prior:
                previous_payload = same_version_prior[0]
                previous_disposition = previous_payload.get("disposition")
                if previous_disposition in {"ACCEPTED", "REJECTED", "DUPLICATE", "WITHDRAWN"}:
                    db.rollback()
                    raise ValueError("a terminal finding disposition cannot be overwritten")
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
