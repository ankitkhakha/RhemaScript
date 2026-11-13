import os
import tempfile
import unittest
from pathlib import Path

from rhemascript.core.approval_store import ApprovalStoreError, SQLiteApprovalConsumptionStore
from rhemascript.core.approval_archive import (
    export_checkpoint_archive, verify_checkpoint_archive,
)


class ApprovalCheckpointArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_dir = root / "database"
        self.archive_dir = root / "independent-archive"
        self.db_dir.mkdir(mode=0o700)
        self.archive_dir.mkdir(mode=0o700)
        os.chmod(self.db_dir, 0o700)
        os.chmod(self.archive_dir, 0o700)
        self.store = SQLiteApprovalConsumptionStore(self.db_dir / "approvals.sqlite3")
        self.key = b"external-archive-authentication-key-32bytes"
        self.archive = self.archive_dir / "checkpoint-0001.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_export_is_private_and_verifies(self):
        path = export_checkpoint_archive(self.store, self.archive, key=self.key)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        result = verify_checkpoint_archive(path, key=self.key, current_store=self.store)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["consumed_count"], 0)
        self.assertTrue(result["matches_current_state"])

    def test_wrong_key_is_rejected(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        with self.assertRaisesRegex(ApprovalStoreError, "authentication failed"):
            verify_checkpoint_archive(
                self.archive, key=b"different-external-archive-key-32bytes!"
            )

    def test_tampered_archive_is_rejected(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        import json
        envelope = json.loads(self.archive.read_text(encoding="utf-8"))
        envelope["hmac_sha256"] = "0" * 64
        self.archive.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(ApprovalStoreError, "authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)

    def test_state_difference_is_reported_without_mutating_database(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        with self.store._connect() as db:
            db.execute(
                "INSERT INTO revoked_approvals VALUES (?, ?, ?, ?, ?)",
                ("revoked-1", "nonce-1", "2026-01-01T00:00:00+00:00", "test", "operator"),
            )
        result = verify_checkpoint_archive(
            self.archive, key=self.key, current_store=self.store
        )
        self.assertTrue(result["archive_valid"])
        self.assertFalse(result["matches_current_state"])
        self.assertTrue(self.store.is_revoked("revoked-1", "nonce-1"))

    def test_archive_must_be_outside_database_directory(self):
        with self.assertRaisesRegex(ApprovalStoreError, "outside the approval database directory"):
            export_checkpoint_archive(
                self.store, self.db_dir / "local-checkpoint.json", key=self.key
            )

    def test_destination_is_never_overwritten(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        with self.assertRaisesRegex(ApprovalStoreError, "already exists"):
            export_checkpoint_archive(self.store, self.archive, key=self.key)

    def test_archive_requires_external_key(self):
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            export_checkpoint_archive(self.store, self.archive, key=b"short")


if __name__ == "__main__":
    unittest.main()
