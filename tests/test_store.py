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

    def test_prerequisite_must_be_passed_before_child_creation(self):
        self.store.create_unit("U1", "Foundations")
        with self.assertRaises(StoreError):
            self.store.create_unit("U2", "Applied", ["U1"])

    def test_child_assessment_requires_passed_prerequisite(self):
        self.store.create_unit("U1", "Foundations")
        self.store.create_unit("U2", "Applied")
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
