import tempfile
import unittest
from pathlib import Path

from rhemascript.evidence.readiness_registry import ReadinessRunRegistry, ReadinessReplayError


class ReadinessRunRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "readiness.sqlite3"
        self.registry = ReadinessRunRegistry(self.path)
        self.report = {
            "run_id": "RUN-1",
            "overall_status": "ASSESSMENTS_READY_FOR_HUMAN_REVIEW",
            "capability_assessments": [{"capability_id": "CAP-01",
                                        "status": "ASSESSED_FOR_HUMAN_REVIEW",
                                        "assessment_is_approval": False}],
            "generation_preconditions_met": False,
        }
        self.evidence = ({"evidence_id": "ART-1", "version": "v1",
                          "sha256": "a" * 64, "size_bytes": 12},)

    def tearDown(self):
        self.tmp.cleanup()

    def test_persists_report_and_exact_evidence(self):
        self.assertTrue(self.registry.record("RUN-1", self.report, self.evidence))
        reopened = ReadinessRunRegistry(self.path)
        saved = reopened.get("RUN-1")
        self.assertEqual(saved["byte_verified_evidence"][0]["sha256"], "a" * 64)
        self.assertFalse(saved["assessment_is_approval"])
        self.assertFalse(saved["assessment_is_execution_authorisation"])
        self.assertTrue(reopened.verify())


    def test_single_record_read_rejects_tampered_registry_payload(self):
        self.registry.record("RUN-READ", self.report, self.evidence)
        with self.registry._connect() as db:
            db.execute(
                "UPDATE readiness_runs SET payload_json=? WHERE run_id=?",
                ('{"run_id":"RUN-READ","report":{"overall_status":"FORGED"}}', "RUN-READ"),
            )
        with self.assertRaisesRegex(ValueError, "integrity verification failed"):
            self.registry.get("RUN-READ")

    def test_persists_exact_local_source_receipt_and_catalog_identity(self):
        from rhemascript.evidence.local_source_resolver import LocalSourceReceipt
        receipt = LocalSourceReceipt(
            original_reference="local-source:source",
            source_id="ART-1",
            relative_path="source.txt",
            version="v3",
            sha256="c" * 64,
            size_bytes=19,
            media_type="text/plain",
            catalog_revision="catalog-v3",
            catalog_fingerprint="d" * 64,
            project_id="PROJECT-1",
            project_version="2.0",
            resolved_at_utc="2026-11-12T00:00:00+00:00",
        )
        self.registry.record("RUN-RECEIPT", self.report, self.evidence, (receipt,))
        saved = ReadinessRunRegistry(self.path).get("RUN-RECEIPT")
        retained = saved["source_resolution_receipts"][0]
        self.assertEqual(retained["source_id"], "ART-1")
        self.assertEqual(retained["version"], "v3")
        self.assertEqual(retained["sha256"], "c" * 64)
        self.assertEqual(retained["catalog_revision"], "catalog-v3")
        self.assertEqual(retained["catalog_fingerprint"], "d" * 64)
        self.assertEqual(retained["project_id"], "PROJECT-1")
        self.assertEqual(retained["project_version"], "2.0")
        self.assertEqual(retained["outcome"], "CONTENT_VERIFIED")

    def test_changed_receipt_on_same_run_is_rejected(self):
        from rhemascript.evidence.local_source_resolver import LocalSourceReceipt
        first = LocalSourceReceipt(
            "local-source:source", "ART-1", "source.txt", "v1", "a" * 64,
            10, "text/plain", "catalog-v1", "b" * 64, "PROJECT-1", "1.0",
            "2026-11-12T00:00:00+00:00",
        )
        changed = LocalSourceReceipt(
            "local-source:source", "ART-1", "source.txt", "v2", "c" * 64,
            10, "text/plain", "catalog-v2", "d" * 64, "PROJECT-1", "1.0",
            "2026-11-12T00:01:00+00:00",
        )
        self.registry.record("RUN-STALE", self.report, self.evidence, (first,))
        with self.assertRaises(ReadinessReplayError):
            self.registry.record("RUN-STALE", self.report, self.evidence, (changed,))

    def test_identical_run_replay_is_idempotent(self):
        self.assertTrue(self.registry.record("RUN-1", self.report, self.evidence))
        self.assertFalse(self.registry.record("RUN-1", self.report, self.evidence))

    def test_changed_evidence_on_replay_is_rejected(self):
        self.registry.record("RUN-1", self.report, self.evidence)
        changed = ({"evidence_id": "ART-1", "version": "v2",
                    "sha256": "b" * 64, "size_bytes": 12},)
        with self.assertRaises(ReadinessReplayError):
            self.registry.record("RUN-1", self.report, changed)

    def test_changed_assessment_on_replay_is_rejected(self):
        self.registry.record("RUN-1", self.report, self.evidence)
        changed = {**self.report, "overall_status": "EVIDENCE_OR_DEPENDENCY_GAPS"}
        with self.assertRaises(ReadinessReplayError):
            self.registry.record("RUN-1", changed, self.evidence)

    def test_external_checkpoint_detects_database_changes_and_wrong_key(self):
        key = b"independent-secret-key-material-32bytes!"
        self.registry.record("RUN-1", self.report, self.evidence)
        checkpoint = self.registry.checkpoint(key)
        self.assertTrue(self.registry.verify_checkpoint(checkpoint, key))
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, b"x" * 40))
        self.registry.record("RUN-2", {"overall_status": "NEW"}, ())
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, key))
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, b"short"))

    def test_list_all_returns_all_records_in_insertion_order(self):
        self.registry.record("RUN-1", self.report, self.evidence)
        self.registry.record("RUN-2", {"overall_status": "SECOND"}, ())
        records = self.registry.list_all()
        self.assertEqual([item["run_id"] for item in records], ["RUN-1", "RUN-2"])

    def test_rejects_non_finite_values_and_non_string_object_keys(self):
        with self.assertRaises(ValueError):
            self.registry.record("RUN-NAN", {"score": float("nan")}, ())
        with self.assertRaises(TypeError):
            self.registry.record("RUN-KEY", {1: "invalid"}, ())

    def test_checkpoint_rejects_short_key(self):
        with self.assertRaises(ValueError):
            self.registry.checkpoint(b"short")

    def test_readiness_record_also_appends_exact_evidence_event(self):
        evidence = ({
            "evidence_id": "ART-1", "relative_path": "proof.txt", "version": "v1",
            "sha256": "a" * 64, "size_bytes": 12,
        },)
        self.registry.record("RUN-1", self.report, evidence)
        events = self.registry.list_activity_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "READINESS_RUN_RECORDED")
        self.assertEqual(events[0]["payload"]["run_id"], "RUN-1")
        self.assertEqual(events[0]["payload"]["evidence_refs"][0]["evidence_id"], "ART-1")
        self.assertTrue(self.registry.verify())

    def test_activity_event_is_hash_chained_and_idempotent(self):
        payload = {"finding_id": "RS-FND-001", "status": "SUBMITTED"}
        self.assertTrue(self.registry.append_activity_event(
            "FINDING:RS-FND-001@1.0", "FINDING_CAPTURED", payload,
            project_id="RS-PROJECT-1", subject_id="RS-FND-001",
        ))
        self.assertFalse(self.registry.append_activity_event(
            "FINDING:RS-FND-001@1.0", "FINDING_CAPTURED", payload,
            project_id="RS-PROJECT-1", subject_id="RS-FND-001",
        ))
        events = self.registry.list_activity_events()
        self.assertEqual(events[0]["sequence"], 1)
        self.assertEqual(events[0]["previous_hash"], "GENESIS")
        self.assertEqual(events[0]["payload"], payload)
        self.assertTrue(self.registry.verify())

    def test_activity_event_replay_with_changed_payload_is_rejected(self):
        self.registry.append_activity_event(
            "FINDING:RS-FND-002@1.0", "FINDING_CAPTURED",
            {"finding_id": "RS-FND-002", "status": "SUBMITTED"},
        )
        with self.assertRaises(ReadinessReplayError):
            self.registry.append_activity_event(
                "FINDING:RS-FND-002@1.0", "FINDING_CAPTURED",
                {"finding_id": "RS-FND-002", "status": "APPROVED"},
            )

    def test_activity_event_tampering_breaks_hash_chain(self):
        self.registry.append_activity_event(
            "FINDING:RS-FND-003@1.0", "FINDING_CAPTURED",
            {"finding_id": "RS-FND-003", "status": "SUBMITTED"},
        )
        with self.registry._connect() as db:
            db.execute("DROP TRIGGER activity_events_no_update")
            db.execute(
                "UPDATE activity_events SET payload_json=? WHERE event_id=?",
                ('{"finding_id":"RS-FND-003","status":"ALTERED"}', "FINDING:RS-FND-003@1.0"),
            )
        self.assertFalse(self.registry.verify())

    def test_external_checkpoint_detects_activity_history_truncation(self):
        key = b"activity-checkpoint-key-material-32bytes"
        self.registry.append_activity_event(
            "FINDING:RS-FND-004@1.0", "FINDING_CAPTURED",
            {"finding_id": "RS-FND-004", "status": "SUBMITTED"},
        )
        checkpoint = self.registry.checkpoint(key)
        with self.registry._connect() as db:
            db.execute("DROP TRIGGER activity_events_no_delete")
            db.execute("DELETE FROM activity_events WHERE event_id=?",
                       ("FINDING:RS-FND-004@1.0",))
            db.execute("""CREATE TRIGGER activity_events_no_delete
                BEFORE DELETE ON activity_events
                BEGIN SELECT RAISE(ABORT, 'activity events are append-only'); END""")
        self.assertTrue(self.registry.verify())
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, key))

    def test_verify_uses_one_snapshot_when_readiness_and_event_commit_concurrently(self):
        import hashlib
        import json
        import sqlite3
        from unittest.mock import patch

        real_connect = self.registry._connect
        injected = {"done": False}

        def interleave():
            if injected["done"]:
                return
            injected["done"] = True
            payload = {
                "run_id": "RACE-RUN",
                "report": {},
                "byte_verified_evidence": [],
                "source_resolution_receipts": [],
                "assessment_is_approval": False,
                "assessment_is_execution_authorisation": False,
            }
            encoded = self.registry._canonical(payload)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            writer = sqlite3.connect(self.path, isolation_level=None)
            try:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute(
                    "INSERT INTO readiness_runs(run_id,payload_sha256,payload_json) VALUES(?,?,?)",
                    ("RACE-RUN", digest, encoded),
                )
                self.registry._append_event_tx(
                    writer, "READINESS:RACE-RUN", "READINESS_RUN_RECORDED",
                    {"run_id": "RACE-RUN", "payload_sha256": digest, "evidence_refs": []},
                    None, "RACE-RUN",
                )
                writer.execute("COMMIT")
            finally:
                writer.close()

        class InterleavingCursor:
            def __init__(self, cursor, trigger=False):
                self.cursor = cursor
                self.trigger = trigger

            def fetchall(self):
                rows = self.cursor.fetchall()
                if self.trigger:
                    interleave()
                return rows

            def __getattr__(self, name):
                return getattr(self.cursor, name)

        class InterleavingConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, sql, *args):
                cursor = self.connection.execute(sql, *args)
                trigger = (
                    "SELECT run_id,payload_sha256,payload_json FROM readiness_runs "
                    "ORDER BY created_at,rowid" in sql
                )
                return InterleavingCursor(cursor, trigger)

            def __enter__(self):
                self.connection.__enter__()
                return self

            def __exit__(self, *args):
                return self.connection.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.connection, name)

        with patch.object(
            self.registry, "_connect",
            side_effect=lambda: InterleavingConnection(real_connect()),
        ):
            self.assertTrue(self.registry.verify())
        self.assertTrue(injected["done"])
        self.assertTrue(self.registry.verify())

    def test_legacy_readiness_records_are_imported_into_event_chain(self):
        import hashlib
        import json
        import sqlite3
        legacy_path = Path(self.tmp.name) / "legacy.sqlite3"
        payload = {
            "run_id": "LEGACY-RUN",
            "report": {"overall_status": "LEGACY"},
            "byte_verified_evidence": [],
            "source_resolution_receipts": [],
            "assessment_is_approval": False,
            "assessment_is_execution_authorisation": False,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with sqlite3.connect(legacy_path) as db:
            db.execute("""CREATE TABLE readiness_runs (
                run_id TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")
            db.execute("INSERT INTO readiness_runs(run_id,payload_sha256,payload_json) VALUES(?,?,?)",
                       ("LEGACY-RUN", digest, encoded))
        # Legacy content is migratable only when its existing file permissions
        # already satisfy the registry's private-storage requirement.
        import os
        os.chmod(legacy_path, 0o600)
        migrated = ReadinessRunRegistry(legacy_path)
        events = migrated.list_activity_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "LEGACY_READINESS_RECORD_IMPORTED")
        self.assertEqual(events[0]["payload"]["run_id"], "LEGACY-RUN")
        self.assertTrue(migrated.verify())

    def test_backup_restores_and_matches_external_checkpoint(self):
        key = b"backup-checkpoint-secret-material-32bytes"
        self.registry.record("RUN-1", self.report, self.evidence)
        checkpoint = self.registry.checkpoint(key)
        backup_path = Path(self.tmp.name) / "backup.sqlite3"
        self.registry.backup_to(backup_path)
        restored = ReadinessRunRegistry(backup_path)
        self.assertEqual(restored.get("RUN-1")["run_id"], "RUN-1")
        self.assertTrue(restored.verify_checkpoint(checkpoint, key))

    def test_restored_backup_rejects_rewritten_history_against_external_checkpoint(self):
        import sqlite3
        key = b"independent-recovery-checkpoint-key-32bytes"
        self.registry.record("RUN-1", self.report, self.evidence)
        self.registry.append_activity_event(
            "FINDING:RECOVERY-1@1.0", "FINDING_CAPTURED",
            {"finding_id": "RECOVERY-1", "version": "1.0", "status": "SUBMITTED"},
            project_id="PROJECT-RECOVERY", subject_id="RECOVERY-1",
        )
        checkpoint = self.registry.checkpoint(key)
        backup_path = Path(self.tmp.name) / "recovery-backup.sqlite3"
        self.registry.backup_to(backup_path)
        restored = ReadinessRunRegistry(backup_path)
        self.assertTrue(restored.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(backup_path) as db:
            db.execute("DROP TRIGGER activity_events_no_update")
            db.execute(
                "UPDATE activity_events SET payload_json=? WHERE event_id=?",
                ('{"finding_id":"RECOVERY-1","status":"ALTERED","version":"1.0"}',
                 "FINDING:RECOVERY-1@1.0"),
            )
        self.assertFalse(restored.verify())
        self.assertFalse(restored.verify_checkpoint(checkpoint, key))

    def test_backup_refuses_existing_destination(self):
        destination = Path(self.tmp.name) / "existing.sqlite3"
        destination.write_text("do not overwrite", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.registry.backup_to(destination)
        self.assertEqual(destination.read_text(encoding="utf-8"), "do not overwrite")

    def test_direct_database_payload_tampering_invalidates_checkpoint(self):
        key = b"tamper-detection-key-material-32bytes!!"
        self.registry.record("RUN-1", self.report, self.evidence)
        checkpoint = self.registry.checkpoint(key)
        with self.registry._connect() as db:
            db.execute("UPDATE readiness_runs SET payload_json=? WHERE run_id=?",
                       ('{"run_id":"RUN-1","report":{"overall_status":"ALTERED"}}', "RUN-1"))
        self.assertFalse(self.registry.verify())
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, key))

    def test_backup_refuses_symlink_destination(self):
        destination = Path(self.tmp.name) / "destination-link.sqlite3"
        destination.symlink_to(self.path)
        with self.assertRaises(ValueError):
            self.registry.backup_to(destination)

    def test_backup_refuses_symlink_parent_directory(self):
        real_parent = Path(self.tmp.name) / "real-parent"
        real_parent.mkdir()
        alias_parent = Path(self.tmp.name) / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.registry.backup_to(alias_parent / "backup.sqlite3")

    def test_rejects_symlink_database(self):
        alias = Path(self.tmp.name) / "alias.sqlite3"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            ReadinessRunRegistry(alias)

    def test_database_is_owner_only(self):
        import os
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_rejects_group_or_world_readable_database(self):
        import os
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(ValueError, "permissions or file type are unsafe"):
            self.registry._connect()

    def test_rejects_public_database_parent(self):
        import os
        public_parent = Path(self.tmp.name) / "public-parent"
        public_parent.mkdir()
        os.chmod(public_parent, 0o755)
        with self.assertRaisesRegex(ValueError, "owner-owned and private"):
            ReadinessRunRegistry(public_parent / "readiness.sqlite3")

    def test_rejects_symlinked_database_ancestor(self):
        real_parent = Path(self.tmp.name) / "real-parent"
        real_parent.mkdir()
        alias_parent = Path(self.tmp.name) / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked directories"):
            ReadinessRunRegistry(alias_parent / "readiness.sqlite3")


if __name__ == "__main__":
    unittest.main()
