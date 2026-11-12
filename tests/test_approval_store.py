import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rhemascript.core.approval_store import (
    ApprovalStoreError, SQLiteApprovalConsumptionStore,
)


class SQLiteApprovalConsumptionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "private"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "approvals.sqlite3"
        self.store = SQLiteApprovalConsumptionStore(self.path)
        self.future = datetime.now(timezone.utc) + timedelta(minutes=5)

    def tearDown(self):
        self.temp.cleanup()

    def test_database_is_owner_only(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_consumes_batch_atomically_and_persists_across_instances(self):
        entries = (
            ("approval-final-0001", "nonce-final-0001", self.future),
            ("approval-publish-0001", "nonce-publish-0001", self.future),
        )
        self.assertTrue(self.store.consume_many_once(entries))
        reopened = SQLiteApprovalConsumptionStore(self.path)
        self.assertTrue(reopened.is_consumed("approval-final-0001", "nonce-final-0001"))
        self.assertTrue(reopened.is_consumed("approval-publish-0001", "nonce-publish-0001"))
        self.assertFalse(reopened.consume_many_once(entries))

    def test_duplicate_existing_entry_rejects_entire_batch(self):
        first = ("approval-existing-0001", "nonce-existing-0001", self.future)
        self.assertTrue(self.store.consume_many_once((first,)))
        second = ("approval-new-0001", "nonce-new-0001", self.future)
        self.assertFalse(self.store.consume_many_once((second, first)))
        self.assertFalse(self.store.is_consumed("approval-new-0001", "nonce-new-0001"))

    def test_revoked_second_entry_prevents_consuming_first(self):
        self.store.revoke("approval-revoked-0001", "nonce-revoked-0001",
                          reason="operator requested revocation")
        first = ("approval-valid-0001", "nonce-valid-0001", self.future)
        second = ("approval-revoked-0001", "nonce-revoked-0001", self.future)
        self.assertFalse(self.store.consume_many_once((first, second)))
        self.assertFalse(self.store.is_consumed(*first[:2]))
        self.assertTrue(self.store.is_revoked(*second[:2]))

    def test_rejects_expired_batch_without_consuming_any_entry(self):
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        first = ("approval-valid-0002", "nonce-valid-0002", self.future)
        second = ("approval-expired-0002", "nonce-expired-0002", expired)
        self.assertFalse(self.store.consume_many_once((first, second)))
        self.assertFalse(self.store.is_consumed(*first[:2]))

    def test_rejects_duplicate_ids_or_nonces_in_batch(self):
        entry = ("approval-duplicate-0001", "nonce-duplicate-0001", self.future)
        self.assertFalse(self.store.consume_many_once((entry, entry)))
        self.assertFalse(self.store.is_consumed(*entry[:2]))

    def test_rejects_non_private_parent_directory(self):
        public = Path(self.temp.name) / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        with self.assertRaisesRegex(ApprovalStoreError, "owner-owned and private"):
            SQLiteApprovalConsumptionStore(public / "approvals.sqlite3")

    def test_rejects_symlink_database(self):
        target = self.directory / "target.sqlite3"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        link = self.directory / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(ApprovalStoreError, "private regular file"):
            SQLiteApprovalConsumptionStore(link)

    def test_rejects_group_or_world_readable_database(self):
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(ApprovalStoreError, "private regular file"):
            SQLiteApprovalConsumptionStore(self.path)


if __name__ == "__main__":
    unittest.main()
