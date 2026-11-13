import tempfile
import unittest
from datetime import datetime, timedelta, timezone

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
        self.anchor = FakeAnchor()
        self.archive = {
            "archive_valid": True,
            "generation": 1,
            "snapshot_sha256": "a" * 64,
        }

    def test_advance_registers_exact_generation_and_digest_and_reads_back(self):
        record = advance_checkpoint_anchor(
            self.archive, self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        self.assertEqual(record.generation, 1)
        self.assertEqual(record.snapshot_sha256, "a" * 64)
        self.assertEqual(verify_checkpoint_against_anchor(self.archive, self.anchor), record)

    def test_stale_archive_is_rejected_after_anchor_advances(self):
        advance_checkpoint_anchor(
            self.archive, self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        newer = {**self.archive, "generation": 2, "snapshot_sha256": "b" * 64}
        advance_checkpoint_anchor(
            newer, self.anchor, expected_generation=1,
            recorded_at=self.anchor.now,
        )
        with self.assertRaisesRegex(ValueError, "stale or differs"):
            verify_checkpoint_against_anchor(self.archive, self.anchor)

    def test_generation_conflict_does_not_overwrite_latest_anchor(self):
        advance_checkpoint_anchor(
            self.archive, self.anchor, expected_generation=0,
            recorded_at=self.anchor.now,
        )
        with self.assertRaisesRegex(ValueError, "generation changed"):
            advance_checkpoint_anchor(
                {**self.archive, "generation": 2, "snapshot_sha256": "b" * 64},
                self.anchor, expected_generation=0, recorded_at=self.anchor.now,
            )
        self.assertEqual(self.anchor.record.generation, 1)
        self.assertEqual(self.anchor.record.snapshot_sha256, "a" * 64)

    def test_missing_or_invalid_archive_cannot_advance_anchor(self):
        with self.assertRaisesRegex(ValueError, "valid generation-bound"):
            advance_checkpoint_anchor(
                {"archive_valid": False, "generation": 1, "snapshot_sha256": "a" * 64},
                self.anchor, expected_generation=0, recorded_at=self.anchor.now,
            )
        self.assertIsNone(self.anchor.record)

    def test_nonconsecutive_generation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            advance_checkpoint_anchor(
                {**self.archive, "generation": 3}, self.anchor,
                expected_generation=0, recorded_at=self.anchor.now,
            )


if __name__ == "__main__":
    unittest.main()
