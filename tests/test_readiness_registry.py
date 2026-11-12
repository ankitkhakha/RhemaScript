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

    def test_backup_restores_and_matches_external_checkpoint(self):
        key = b"backup-checkpoint-secret-material-32bytes"
        self.registry.record("RUN-1", self.report, self.evidence)
        checkpoint = self.registry.checkpoint(key)
        backup_path = Path(self.tmp.name) / "backup.sqlite3"
        self.registry.backup_to(backup_path)
        restored = ReadinessRunRegistry(backup_path)
        self.assertEqual(restored.get("RUN-1")["run_id"], "RUN-1")
        self.assertTrue(restored.verify_checkpoint(checkpoint, key))

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


if __name__ == "__main__":
    unittest.main()
