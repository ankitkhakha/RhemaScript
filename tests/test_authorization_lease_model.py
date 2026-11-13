"""Synthetic contract tests for authorization lease fencing."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from rhemascript.core.authorization_lease_model import (
    LeaseStateError, SQLiteLeaseStateModel,
)


class SQLiteLeaseStateModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.model = SQLiteLeaseStateModel(str(Path(self.temp.name) / "leases.sqlite3"))
        self.expiry = datetime.now(timezone.utc) + timedelta(minutes=2)

    def tearDown(self):
        self.temp.cleanup()

    def acquire(self, *, nonce="dispatch-1", fingerprint="a" * 64):
        return self.model.acquire(
            resource_id="youtube:channel-1:publish",
            approval_ids=("approval-director", "approval-publisher"),
            dispatch_nonce=nonce, request_fingerprint=fingerprint,
            expires_at=self.expiry,
        )

    def test_lease_requires_exactly_two_distinct_approval_ids(self):
        with self.assertRaisesRegex(ValueError, "exactly two distinct"):
            self.model.acquire(
                resource_id="youtube:channel-1:publish",
                approval_ids=("one", "two", "three"),
                dispatch_nonce="dispatch-three-approvals",
                request_fingerprint="a" * 64, expires_at=self.expiry,
            )
        with self.assertRaisesRegex(ValueError, "exactly two distinct"):
            self.model.acquire(
                resource_id="youtube:channel-1:publish",
                approval_ids=("same", "same"),
                dispatch_nonce="dispatch-duplicate-approval",
                request_fingerprint="a" * 64, expires_at=self.expiry,
            )

    def test_request_fingerprint_must_be_lowercase_sha256(self):
        for invalid in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
                    self.acquire(nonce="dispatch-invalid-fingerprint", fingerprint=invalid)

    def test_accepts_exact_unexpired_single_use_lease(self):
        lease = self.acquire()
        self.assertTrue(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
        ))
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
        ))

    def test_revocation_after_lease_issue_invalidates_fence(self):
        lease = self.acquire()
        self.model.revoke("approval-publisher")
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
        ))

    def test_repeated_revocation_is_idempotent_and_does_not_advance_fence(self):
        lease = self.acquire(nonce="dispatch-revoke-idempotent")
        with sqlite3.connect(self.model.path) as db:
            before = db.execute(
                "SELECT generation FROM resource_fences WHERE resource_id=?",
                (lease.resource_id,),
            ).fetchone()[0]
        self.model.revoke("approval-publisher")
        with sqlite3.connect(self.model.path) as db:
            after_first = db.execute(
                "SELECT generation FROM resource_fences WHERE resource_id=?",
                (lease.resource_id,),
            ).fetchone()[0]
        self.model.revoke("approval-publisher")
        with sqlite3.connect(self.model.path) as db:
            after_second = db.execute(
                "SELECT generation FROM resource_fences WHERE resource_id=?",
                (lease.resource_id,),
            ).fetchone()[0]
        self.assertEqual(after_first, before + 1)
        self.assertEqual(after_second, after_first)
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
        ))

    def test_event_history_hash_chain_covers_lifecycle_and_detects_tampering(self):
        lease = self.acquire(nonce="dispatch-event-history")
        self.assertTrue(self.model.verify_event_history())
        self.assertEqual(
            [event["event_type"] for event in self.model.read_event_history()],
            ["LEASE_ISSUED"],
        )
        self.assertTrue(self.model.accept_dispatch(lease, request_fingerprint="a" * 64))
        self.model.revoke("approval-publisher")
        self.assertTrue(self.model.verify_event_history())
        events = self.model.read_event_history()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["LEASE_ISSUED", "DISPATCH_ACCEPTED", "APPROVAL_REVOKED"],
        )
        with sqlite3.connect(self.model.path) as db:
            db.execute(
                "UPDATE event_history SET payload_json=? WHERE sequence=2",
                ('{"dispatch_nonce":"forged"}',),
            )
        self.assertFalse(self.model.verify_event_history())

    def test_recovery_checkpoint_can_be_retrieved_after_lost_commit_response(self):
        lease = self.acquire(nonce="dispatch-checkpoint-response-lost")
        created = self.model.create_recovery_checkpoint()
        recovered = self.model.get_latest_recovery_checkpoint()
        self.assertEqual(recovered, created)
        self.assertTrue(self.model.verify_recovery_checkpoint(recovered))
        self.assertEqual(recovered["sha256"], created["sha256"])

    def test_recovery_checkpoint_detects_tampering_and_stale_sequence(self):
        first = self.acquire(nonce="dispatch-checkpoint-one")
        checkpoint_one = self.model.create_recovery_checkpoint()
        self.assertTrue(self.model.verify_recovery_checkpoint(checkpoint_one))
        second = self.model.acquire(
            resource_id="youtube:channel-1:publish",
            approval_ids=("approval-checkpoint-director", "approval-checkpoint-publisher"),
            dispatch_nonce="dispatch-checkpoint-two",
            request_fingerprint="b" * 64,
            expires_at=self.expiry,
        )
        checkpoint_two = self.model.create_recovery_checkpoint()
        self.assertGreater(checkpoint_two["sequence"], checkpoint_one["sequence"])
        self.assertGreater(checkpoint_two["generation_high_water"], checkpoint_one["generation_high_water"])
        self.assertFalse(self.model.verify_recovery_checkpoint(checkpoint_one))
        self.assertTrue(self.model.verify_recovery_checkpoint(checkpoint_two))
        tampered = dict(checkpoint_two)
        tampered["state"] = dict(checkpoint_two["state"])
        tampered["state"]["revoked_approvals"] = [["forged-approval", "forged-time"]]
        self.assertFalse(self.model.verify_recovery_checkpoint(tampered))

    def test_checkpoint_creation_rejects_generation_rollback_below_anchor(self):
        lease = self.acquire(nonce="dispatch-checkpoint-rollback")
        checkpoint = self.model.create_recovery_checkpoint()
        with sqlite3.connect(self.model.path) as db:
            db.execute(
                "UPDATE resource_fences SET generation=0 WHERE resource_id=?",
                (lease.resource_id,),
            )
            db.execute(
                "UPDATE leases SET generation=0 WHERE lease_id=?",
                (lease.lease_id,),
            )
        with self.assertRaisesRegex(LeaseStateError, "below trusted recovery anchor"):
            self.model.create_recovery_checkpoint()
        self.assertTrue(self.model.verify_recovery_checkpoint(checkpoint))

    def test_read_only_dispatch_state_lookup_supports_lost_response_recovery(self):
        lease = self.acquire(nonce="dispatch-state-inspection")
        self.assertIsNone(self.model.get_dispatch_state("unknown-nonce"))
        issued = self.model.get_dispatch_state(lease.dispatch_nonce)
        self.assertEqual(issued["lease_id"], lease.lease_id)
        self.assertEqual(issued["lease_state"], "ISSUED")
        self.assertIsNone(issued["outcome_state"])
        self.assertTrue(self.model.accept_dispatch(lease, request_fingerprint="a" * 64))
        self.assertTrue(self.model.mark_indeterminate(
            lease.lease_id, reason_code="RESPONSE_LOST_AFTER_SEND",
        ))
        indeterminate = self.model.get_dispatch_state(lease.dispatch_nonce)
        self.assertEqual(indeterminate["lease_state"], "INDETERMINATE")
        self.assertEqual(indeterminate["outcome_state"], "INDETERMINATE")
        self.assertEqual(indeterminate["reason_code"], "RESPONSE_LOST_AFTER_SEND")
        # Inspection is read-only and cannot make an ambiguous dispatch retryable.
        self.assertFalse(self.model.accept_dispatch(lease, request_fingerprint="a" * 64))

    def test_revoked_approval_cannot_acquire_future_lease(self):
        self.model.revoke("approval-director")
        with self.assertRaisesRegex(LeaseStateError, "revoked approval"):
            self.acquire()

    def test_newer_lease_supersedes_older_generation(self):
        old = self.acquire(nonce="dispatch-old")
        newer = self.model.acquire(
            resource_id="youtube:channel-1:publish",
            approval_ids=("approval-next-director", "approval-next-publisher"),
            dispatch_nonce="dispatch-new",
            request_fingerprint="b" * 64, expires_at=self.expiry,
        )
        self.assertGreater(newer.generation, old.generation)
        self.assertFalse(self.model.accept_dispatch(
            old, request_fingerprint="a" * 64,
        ))
        self.assertTrue(self.model.accept_dispatch(
            newer, request_fingerprint="b" * 64,
        ))

    def test_request_fingerprint_mismatch_is_rejected(self):
        lease = self.acquire()
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="b" * 64,
        ))

    def test_expired_lease_is_rejected_at_acceptance(self):
        lease = self.acquire()
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
            now=self.expiry + timedelta(seconds=1),
        ))

    def test_duplicate_dispatch_nonce_cannot_create_second_lease(self):
        self.acquire()
        with self.assertRaises(sqlite3.IntegrityError):
            self.acquire()

    def test_approval_credentials_cannot_be_reused_for_overlapping_leases(self):
        first = self.acquire(nonce="dispatch-overlap-1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.model.acquire(
                resource_id="youtube:channel-1:publish",
                approval_ids=("approval-publisher", "approval-second-director"),
                dispatch_nonce="dispatch-overlap-2",
                request_fingerprint="c" * 64, expires_at=self.expiry,
            )
        self.assertTrue(self.model.accept_dispatch(
            first, request_fingerprint="a" * 64,
        ))

    def test_approval_credentials_cannot_be_reused_on_another_resource(self):
        self.acquire(nonce="dispatch-resource-1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.model.acquire(
                resource_id="youtube:channel-2:publish",
                approval_ids=("approval-director", "approval-publisher"),
                dispatch_nonce="dispatch-resource-2",
                request_fingerprint="e" * 64, expires_at=self.expiry,
            )


    def test_expiry_is_rechecked_after_waiting_for_acquisition_lock(self):
        lock = sqlite3.connect(self.model.path, isolation_level=None)
        lock.execute("BEGIN IMMEDIATE")
        expiry = datetime.now(timezone.utc) + timedelta(seconds=0.25)
        outcome = []

        def acquire():
            try:
                outcome.append(self.model.acquire(
                    resource_id="youtube:channel-1:publish",
                    approval_ids=("approval-director", "approval-publisher"),
                    dispatch_nonce="dispatch-lock-expiry",
                    request_fingerprint="d" * 64,
                    expires_at=expiry,
                ))
            except Exception as exc:
                outcome.append(exc)

        worker = threading.Thread(target=acquire)
        worker.start()
        time.sleep(0.4)
        lock.execute("ROLLBACK")
        lock.close()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive(), "acquisition worker did not finish")
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], LeaseStateError)
        self.assertIn("expired while waiting", str(outcome[0]))

    def test_acceptance_rechecks_expiry_after_waiting_for_dispatch_lock(self):
        expiry = datetime.now(timezone.utc) + timedelta(seconds=0.25)
        lease = self.model.acquire(
            resource_id="youtube:channel-1:publish",
            approval_ids=("approval-dispatch-director", "approval-dispatch-publisher"),
            dispatch_nonce="dispatch-lock-expiry-accept",
            request_fingerprint="f" * 64,
            expires_at=expiry,
        )
        lock = sqlite3.connect(self.model.path, isolation_level=None)
        lock.execute("BEGIN IMMEDIATE")
        outcome = []

        def accept():
            outcome.append(self.model.accept_dispatch(
                lease, request_fingerprint="f" * 64,
            ))

        worker = threading.Thread(target=accept)
        worker.start()
        time.sleep(0.4)
        lock.execute("ROLLBACK")
        lock.close()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive(), "dispatch worker did not finish")
        self.assertEqual(outcome, [False])

    def test_unaccepted_lease_cannot_be_marked_indeterminate(self):
        lease = self.acquire(nonce="dispatch-not-accepted")
        self.assertFalse(self.model.mark_indeterminate(
            lease.lease_id, reason_code="RESPONSE_LOST_AFTER_SEND",
        ))
        self.assertFalse(self.model.reconcile_dispatch(
            lease.lease_id, provider_operation_id="provider-op-none", outcome="SUCCEEDED",
        ))

    def test_indeterminate_dispatch_requires_reconciliation_and_cannot_be_replayed(self):
        lease = self.acquire(nonce="dispatch-indeterminate")
        self.assertTrue(self.model.accept_dispatch(lease, request_fingerprint="a" * 64))
        self.assertTrue(self.model.mark_indeterminate(
            lease.lease_id, reason_code="RESPONSE_LOST_AFTER_SEND",
        ))
        self.assertFalse(self.model.accept_dispatch(lease, request_fingerprint="a" * 64))
        self.assertTrue(self.model.reconcile_dispatch(
            lease.lease_id, provider_operation_id="provider-op-123", outcome="SUCCEEDED",
        ))
        self.assertTrue(self.model.reconcile_dispatch(
            lease.lease_id, provider_operation_id="provider-op-123", outcome="SUCCEEDED",
        ))
        self.assertFalse(self.model.reconcile_dispatch(
            lease.lease_id, provider_operation_id="provider-op-456", outcome="SUCCEEDED",
        ))

    def test_provider_operation_id_cannot_be_reused_for_another_lease(self):
        first = self.acquire(nonce="dispatch-op-one")
        self.assertTrue(self.model.accept_dispatch(first, request_fingerprint="a" * 64))
        self.assertTrue(self.model.mark_indeterminate(
            first.lease_id, reason_code="LOST_RESPONSE",
        ))
        self.assertTrue(self.model.reconcile_dispatch(
            first.lease_id, provider_operation_id="provider-op-shared", outcome="SUCCEEDED",
        ))
        second = self.model.acquire(
            resource_id="youtube:channel-2:publish",
            approval_ids=("approval-other-director", "approval-other-publisher"),
            dispatch_nonce="dispatch-op-two", request_fingerprint="b" * 64,
            expires_at=self.expiry,
        )
        self.assertTrue(self.model.accept_dispatch(second, request_fingerprint="b" * 64))
        self.assertTrue(self.model.mark_indeterminate(
            second.lease_id, reason_code="LOST_RESPONSE",
        ))
        self.assertFalse(self.model.reconcile_dispatch(
            second.lease_id, provider_operation_id="provider-op-shared", outcome="SUCCEEDED",
        ))

    def test_concurrent_revocation_and_acceptance_have_one_serialized_order(self):
        lease = self.acquire(nonce="dispatch-revoke-race")
        barrier = threading.Barrier(2)

        def accept():
            barrier.wait()
            return self.model.accept_dispatch(
                lease, request_fingerprint="a" * 64,
            )

        def revoke():
            barrier.wait()
            self.model.revoke("approval-publisher")
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            accept_future = pool.submit(accept)
            revoke_future = pool.submit(revoke)
            accepted = accept_future.result(timeout=5)
            self.assertTrue(revoke_future.result(timeout=5))

        with sqlite3.connect(self.model.path) as db:
            accepted_row = db.execute(
                "SELECT COUNT(*) FROM accepted_dispatches WHERE dispatch_nonce=?",
                (lease.dispatch_nonce,),
            ).fetchone()[0]
            lease_state = db.execute(
                "SELECT state FROM leases WHERE lease_id=?", (lease.lease_id,),
            ).fetchone()[0]
            revoked = db.execute(
                "SELECT COUNT(*) FROM revoked_approvals WHERE approval_id=?",
                ("approval-publisher",),
            ).fetchone()[0]
        # If acceptance serialized first it is recorded once; if revocation
        # serialized first, acceptance rejects. Either way the final ledger
        # records revocation and the lease cannot be used again.
        self.assertEqual(accepted_row, 1 if accepted else 0)
        self.assertEqual(lease_state, "REVOKED")
        self.assertEqual(revoked, 1)
        self.assertFalse(self.model.accept_dispatch(
            lease, request_fingerprint="a" * 64,
        ))

    def test_concurrent_acceptance_has_at_most_one_winner(self):
        lease = self.acquire()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda _: self.model.accept_dispatch(
                    lease, request_fingerprint="a" * 64,
                ),
                range(8),
            ))
        self.assertEqual(sum(results), 1)


if __name__ == "__main__":
    unittest.main()
