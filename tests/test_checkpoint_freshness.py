import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rhemascript.core.approval_archive import export_checkpoint_archive
from rhemascript.core.approval_store import SQLiteApprovalConsumptionStore
from rhemascript.core.checkpoint_freshness import (
    CheckpointAnchorRecord, advance_checkpoint_anchor,
    verify_checkpoint_against_anchor,
)


class FakeAnchor:
    def __init__(self):
        self.record = None
        self.now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)

    def read_latest(self):
        return self.record

    def compare_and_advance(self, *, expected_generation, new_generation, snapshot_sha256):
        actual = self.record.generation if self.record else 0
        if actual != expected_generation or new_generation != expected_generation + 1:
            return None
        self.record = CheckpointAnchorRecord(
            generation=new_generation, snapshot_sha256=snapshot_sha256,
            recorded_at=self.now, record_id=f"anchor-record-{new_generation:04d}",
        )
        return self.record


class CheckpointFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db_dir = root / "database"
        self.archive_dir = root / "archive"
        self.db_dir.mkdir(mode=0o700)
        self.archive_dir.mkdir(mode=0o700)
        os.chmod(self.db_dir, 0o700)
        os.chmod(self.archive_dir, 0o700)
        self.store = SQLiteApprovalConsumptionStore(self.db_dir / "approvals.sqlite3")
        self.key = b"independent-anchor-archive-key-32bytes"
        self.anchor = FakeAnchor()

    def make_archive(self, generation, name):
        return export_checkpoint_archive(
            self.store, self.archive_dir / name, key=self.key, generation=generation,
        )

    def test_advance_registers_exact_generation_and_digest_and_reads_back(self):
        archive = self.make_archive(1, "checkpoint-0001.json")
        record = advance_checkpoint_anchor(
            str(archive), key=self.key, anchor=self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        self.assertEqual(record.generation, 1)
        self.assertTrue(verify_checkpoint_against_anchor(
            str(archive), key=self.key, anchor=self.anchor,
        ) == record)

    def test_stale_archive_is_rejected_after_anchor_advances(self):
        old_archive = self.make_archive(1, "checkpoint-0001.json")
        advance_checkpoint_anchor(
            str(old_archive), key=self.key, anchor=self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        newer_archive = self.make_archive(2, "checkpoint-0002.json")
        advance_checkpoint_anchor(
            str(newer_archive), key=self.key, anchor=self.anchor, expected_generation=1,
            recorded_at=self.anchor.now,
        )
        with self.assertRaisesRegex(ValueError, "stale or differs"):
            verify_checkpoint_against_anchor(
                str(old_archive), key=self.key, anchor=self.anchor,
            )

    def test_generation_conflict_does_not_overwrite_latest_anchor(self):
        first_archive = self.make_archive(1, "checkpoint-0001.json")
        advance_checkpoint_anchor(
            str(first_archive), key=self.key, anchor=self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        replayed_archive = self.make_archive(1, "checkpoint-0001-replayed.json")
        with self.assertRaisesRegex(ValueError, "generation changed"):
            advance_checkpoint_anchor(
                str(replayed_archive), key=self.key, anchor=self.anchor,
                expected_generation=0, recorded_at=self.anchor.now,
            )
        self.assertEqual(self.anchor.record.generation, 1)

    def test_wrong_archive_key_cannot_advance_anchor(self):
        archive = self.make_archive(1, "checkpoint-0001.json")
        with self.assertRaisesRegex(ValueError, "cryptographic verification"):
            advance_checkpoint_anchor(
                str(archive), key=b"wrong-archive-key-32-bytes-long!!",
                anchor=self.anchor, expected_generation=0, recorded_at=self.anchor.now,
            )
        self.assertIsNone(self.anchor.record)

    def test_nonconsecutive_generation_is_rejected(self):
        archive = self.make_archive(3, "checkpoint-0003.json")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            advance_checkpoint_anchor(
                str(archive), key=self.key, anchor=self.anchor,
                expected_generation=0, recorded_at=self.anchor.now,
            )


if __name__ == "__main__":
    unittest.main()
