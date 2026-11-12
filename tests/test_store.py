import tempfile
import threading
import unittest
from pathlib import Path

from raei.store import EvidenceStore, StoreError


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "evidence.sqlite3"
        self.store = EvidenceStore(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_malformed_create_inputs_raise_store_error_before_sql(self):
        cases = [
            ([], "Valid title", []),
            ("U1", [], []),
            ("U1", "Valid title", ["U2", []]),
            ("U1", "Valid title", ["U2", "U2"]),
        ]
        for unit_id, title, prerequisites in cases:
            with self.subTest(unit_id=unit_id, title=title, prerequisites=prerequisites):
                with self.assertRaises(StoreError):
                    self.store.create_unit(unit_id, title, prerequisites)
        self.assertEqual(self.store.event_count(), 0)

    def test_malformed_assessment_inputs_raise_store_error(self):
        self.store.create_unit("U1", "Foundations")
        invalid_calls = [
            ("U1", 3, "ref", [], 1),
            ("U1", True, "ref", "verified", 1),
            ("U1", 3, {}, "verified", 1),
            ("U1", 3, "ref", "verified", True),
            ("U1", 3, "ref", "verified", 0),
        ]
        for args in invalid_calls:
            with self.subTest(args=args), self.assertRaises(StoreError):
                self.store.assess(*args)

    def test_verified_evidence_requires_nonempty_string(self):
        self.store.create_unit("U1", "Foundations")
        for evidence_ref in (" ", [], {}, 42):
            with self.subTest(evidence_ref=evidence_ref), self.assertRaises(StoreError):
                self.store.assess("U1", 3, evidence_ref, "verified", 1)

    def test_nonverified_evidence_ref_must_be_string_or_null(self):
        self.store.create_unit("U1", "Foundations")
        with self.assertRaises(StoreError):
            self.store.assess("U1", 2, {"claim": "x"}, "reported_unverified", 1)

    def test_invalid_idempotency_key_is_rejected(self):
        with self.assertRaises(StoreError):
            self.store.create_unit("U1", "Foundations", idempotency_key=" ")
        self.assertEqual(self.store.event_count(), 0)

    def test_event_chain_returns_false_for_corrupt_payload_json(self):
        self.store.create_unit("U1", "Foundations")
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE events SET payload='not-json' WHERE sequence=1")
        self.assertFalse(self.store.verify_event_chain())

    def test_create_and_read_unit(self):
        result = self.store.create_unit("U1", "Foundations")
        self.assertEqual(result, {"unit_id": "U1", "status": "not_started", "version": 1})
        self.assertEqual(self.store.get_unit("U1")["title"], "Foundations")

    def test_verified_score_three_passes(self):
        self.store.create_unit("U1", "Foundations")
        result = self.store.assess("U1", 3, "tests/test_store.py", "verified", 1)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["version"], 2)

    def test_unverified_evidence_cannot_pass(self):
        self.store.create_unit("U1", "Foundations")
        result = self.store.assess("U1", 4, "claim-only", "reported_unverified", 1)
        self.assertEqual(result["status"], "needs_correction")

    def test_pending_prerequisite_can_be_registered_for_later_assessment(self):
        self.store.create_unit("U1", "Foundations")
        result = self.store.create_unit("U2", "Applied", ["U1"])
        self.assertEqual(result["status"], "not_started")
        self.assertEqual(self.store.get_unit("U2")["prerequisites"], ["U1"])

    def test_invalid_prerequisites_fail_with_store_error(self):
        for invalid in ("", {}, ["U1", 7], ["U1", "U1"]):
            with self.subTest(invalid=invalid), self.assertRaises(StoreError):
                self.store.create_unit("U2", "Applied", invalid)

    def test_child_assessment_requires_passed_prerequisite(self):
        self.store.create_unit("U1", "Foundations")
        self.store.create_unit("U2", "Applied", ["U1"])
        with self.assertRaises(StoreError):
            self.store.assess("U2", 4, "evidence", "verified", 1)

    def test_passed_parent_allows_child_creation_and_assessment(self):
        self.store.create_unit("U1", "Foundations")
        self.store.assess("U1", 3, "tests/test_store.py", "verified", 1)
        self.store.create_unit("U2", "Applied", ["U1"])
        result = self.store.assess("U2", 3, "tests/test_store.py", "verified", 1)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(self.store.get_unit("U2")["prerequisites"], ["U1"])

    def test_passed_unit_is_immutable(self):
        self.store.create_unit("U1", "Foundations")
        self.store.assess("U1", 3, "tests/test_store.py", "verified", 1)
        with self.assertRaises(StoreError):
            self.store.assess("U1", 4, "new-evidence", "verified", 2)

    def test_stale_version_is_rejected(self):
        self.store.create_unit("U1", "Foundations")
        self.store.assess("U1", 2, "attempt", "verified", 1)
        with self.assertRaisesRegex(StoreError, "stale version"):
            self.store.assess("U1", 4, "retry", "verified", 1)

    def test_idempotent_retry_does_not_duplicate_events(self):
        first = self.store.create_unit("U1", "Foundations", idempotency_key="create-u1")
        count = self.store.event_count()
        second = self.store.create_unit("U1", "Foundations", idempotency_key="create-u1")
        self.assertEqual(first, second)
        self.assertEqual(self.store.event_count(), count)

    def test_reusing_idempotency_key_for_different_request_fails(self):
        self.store.create_unit("U1", "Foundations", idempotency_key="same-key")
        with self.assertRaisesRegex(StoreError, "different request"):
            self.store.create_unit("U2", "Different", idempotency_key="same-key")

    def test_audit_hash_chain_verifies(self):
        self.store.create_unit("U1", "Foundations")
        self.store.assess("U1", 2, "attempt", "verified", 1)
        self.assertTrue(self.store.verify_event_chain())
        self.assertEqual(self.store.event_count(), 2)

    def test_backup_restore_preserves_state_and_audit_chain(self):
        self.store.create_unit("U1", "Foundations")
        self.store.assess("U1", 2, "attempt", "verified", 1)
        backup = Path(self.temp.name) / "backup.sqlite3"
        restored_path = Path(self.temp.name) / "restored.sqlite3"
        self.store.backup_to(backup)
        restored = EvidenceStore.restore_from(backup, restored_path)
        self.assertEqual(restored.get_unit("U1")["status"], "needs_correction")
        self.assertEqual(restored.event_count(), self.store.event_count())
        self.assertTrue(restored.verify_event_chain())

    def test_restore_refuses_to_overwrite_existing_destination(self):
        backup = Path(self.temp.name) / "backup.sqlite3"
        self.store.backup_to(backup)
        existing = Path(self.temp.name) / "existing.sqlite3"
        existing.write_text("do not overwrite")
        with self.assertRaisesRegex(StoreError, "refusing to overwrite"):
            EvidenceStore.restore_from(backup, existing)
        self.assertEqual(existing.read_text(), "do not overwrite")

    def test_restore_rejects_unrelated_sqlite_database_without_blessing_it(self):
        import sqlite3
        backup = Path(self.temp.name) / "unrelated.sqlite3"
        with sqlite3.connect(backup) as db:
            db.execute("CREATE TABLE unrelated (value TEXT)")
        destination = Path(self.temp.name) / "must-not-exist.sqlite3"
        with self.assertRaisesRegex(StoreError, "missing required"):
            EvidenceStore.restore_from(backup, destination)
        self.assertFalse(destination.exists())

    def test_restore_rejects_corrupt_event_chain_before_copy(self):
        import sqlite3
        backup = Path(self.temp.name) / "tampered.sqlite3"
        self.store.create_unit("U1", "Foundations")
        self.store.backup_to(backup)
        with sqlite3.connect(backup) as db:
            db.execute("UPDATE events SET payload='{}' WHERE sequence=1")
        destination = Path(self.temp.name) / "must-not-exist.sqlite3"
        with self.assertRaisesRegex(StoreError, "audit-chain"):
            EvidenceStore.restore_from(backup, destination)
        self.assertFalse(destination.exists())

    def test_restore_rejects_non_sqlite_file_with_controlled_error(self):
        backup = Path(self.temp.name) / "not-sqlite.sqlite3"
        backup.write_text("not a database")
        destination = Path(self.temp.name) / "must-not-exist.sqlite3"
        with self.assertRaises(StoreError):
            EvidenceStore.restore_from(backup, destination)
        self.assertFalse(destination.exists())

    def test_concurrent_competing_assessments_have_one_serial_winner(self):
        self.store.create_unit("U1", "Foundations")
        barrier = threading.Barrier(2)
        outcomes = []

        def worker(score):
            local = EvidenceStore(self.path)
            barrier.wait()
            try:
                outcomes.append(local.assess("U1", score, f"evidence-{score}", "verified", 1))
            except StoreError as exc:
                outcomes.append(str(exc))

        threads = [threading.Thread(target=worker, args=(score,)) for score in (2, 4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1)
        self.assertEqual(self.store.get_unit("U1")["version"], 2)
        self.assertTrue(self.store.verify_event_chain())


if __name__ == "__main__":
    unittest.main(verbosity=2)
