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

    def test_revoked_approval_cannot_acquire_future_lease(self):
        self.model.revoke("approval-director")
        with self.assertRaisesRegex(LeaseStateError, "revoked approval"):
            self.acquire()

    def test_newer_lease_supersedes_older_generation(self):
        old = self.acquire(nonce="dispatch-old")
        newer = self.acquire(nonce="dispatch-new")
        self.assertGreater(newer.generation, old.generation)
        self.assertFalse(self.model.accept_dispatch(
            old, request_fingerprint="a" * 64,
        ))
        self.assertTrue(self.model.accept_dispatch(
            newer, request_fingerprint="a" * 64,
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

    def test_overlapping_approval_leases_are_serialized_and_old_fence_rejected(self):
        first = self.acquire(nonce="dispatch-overlap-1")
        second = self.model.acquire(
            resource_id="youtube:channel-1:publish",
            approval_ids=("approval-publisher", "approval-second-director"),
            dispatch_nonce="dispatch-overlap-2",
            request_fingerprint="c" * 64, expires_at=self.expiry,
        )
        self.assertFalse(self.model.accept_dispatch(
            first, request_fingerprint="a" * 64,
        ))
        self.assertTrue(self.model.accept_dispatch(
            second, request_fingerprint="c" * 64,
        ))


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
