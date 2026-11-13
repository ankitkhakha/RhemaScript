import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rhemascript.core.approval_archive import export_checkpoint_archive
from rhemascript.core.approval_store import SQLiteApprovalConsumptionStore
from rhemascript.core.checkpoint_freshness import CheckpointAnchorRecord
from rhemascript.core.composite_checkpoint import (
    CompositeCheckpointError,
    advance_composite_checkpoint_anchor,
    export_composite_checkpoint_manifest,
    verify_composite_checkpoint_against_anchor,
    verify_composite_checkpoint_manifest,
)
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry


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
            generation=new_generation,
            snapshot_sha256=snapshot_sha256,
            recorded_at=self.now,
            resolved_at=self.now,
            record_id=f"composite-anchor-{new_generation:04d}",
        )
        return self.record


class CompositeCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.approval_dir = root / "approval-db"
        self.readiness_dir = root / "readiness-db"
        self.archive_dir = root / "approval-archives"
        self.manifest_dir = root / "composite-manifests"
        for directory in (self.approval_dir, self.readiness_dir,
                          self.archive_dir, self.manifest_dir):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        self.approval_store = SQLiteApprovalConsumptionStore(
            self.approval_dir / "approvals.sqlite3",
        )
        self.readiness_registry = ReadinessRunRegistry(
            self.readiness_dir / "readiness.sqlite3",
        )
        self.approval_key = b"approval-store-checkpoint-key-material-32"
        self.readiness_key = b"readiness-store-checkpoint-key-material-32"
        self.archive_key = b"approval-archive-authentication-key-32bytes"
        self.manifest_key = b"composite-manifest-authentication-key-32bytes"
        self.archive = export_checkpoint_archive(
            self.approval_store, self.archive_dir / "approval-generation-0001.json",
            key=self.archive_key, generation=1,
        )
        self.manifest = export_composite_checkpoint_manifest(
            self.approval_store, self.readiness_registry, self.archive,
            self.manifest_dir / "composite-generation-0001.json",
            approval_key=self.approval_key, readiness_key=self.readiness_key,
            archive_key=self.archive_key, manifest_key=self.manifest_key,
        )

    def verify(self):
        return verify_composite_checkpoint_manifest(
            self.manifest, self.archive, self.approval_store, self.readiness_registry,
            approval_key=self.approval_key, readiness_key=self.readiness_key,
            archive_key=self.archive_key, manifest_key=self.manifest_key,
        )

    def test_manifest_binds_both_live_stores_and_approval_archive(self):
        result = self.verify()
        self.assertTrue(result["manifest_valid"])
        self.assertTrue(result["matches_current_state"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["recovery_mode"],
                         "verified-composite-export-only; no automatic restore")

    def test_manifest_rejects_wrong_authentication_key(self):
        with self.assertRaisesRegex(CompositeCheckpointError, "authentication failed"):
            _ = __import__(
                "rhemascript.core.composite_checkpoint",
                fromlist=["_read_manifest"],
            )._read_manifest(self.manifest, b"wrong-composite-key-material-32bytes!!")

    def test_manifest_rejects_changed_approval_archive(self):
        original = self.archive.read_bytes()
        self.archive.write_bytes(original + b" ")
        with self.assertRaisesRegex(CompositeCheckpointError, "archive bytes differ"):
            self.verify()

    def test_manifest_rejects_changed_readiness_state(self):
        self.readiness_registry.append_activity_event(
            "FINDING:RS-FND-900@1.0", "FINDING_CAPTURED",
            {"finding_id": "RS-FND-900", "status": "SUBMITTED"},
        )
        with self.assertRaisesRegex(CompositeCheckpointError, "readiness checkpoint"):
            self.verify()

    def test_manifest_rejects_changed_approval_state(self):
        self.approval_store.revoke(
            "approval-000900", "nonce-000900", revoked_by="security-test",
            reason="synthetic test state change",
        )
        with self.assertRaisesRegex(CompositeCheckpointError, "approval archive"):
            self.verify()

    def test_manifest_is_create_once_and_private(self):
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(CompositeCheckpointError):
            export_composite_checkpoint_manifest(
                self.approval_store, self.readiness_registry, self.archive,
                self.manifest, approval_key=self.approval_key,
                readiness_key=self.readiness_key, archive_key=self.archive_key,
                manifest_key=self.manifest_key,
            )

    def test_independent_anchor_tracks_composite_manifest_digest(self):
        anchor = FakeAnchor()
        record = advance_composite_checkpoint_anchor(
            self.manifest, manifest_key=self.manifest_key, anchor=anchor,
            expected_generation=0, now=anchor.now,
        )
        self.assertEqual(record.generation, 1)
        self.assertEqual(
            verify_composite_checkpoint_against_anchor(
                self.manifest, manifest_key=self.manifest_key,
                anchor=anchor, now=anchor.now,
            ),
            record,
        )

    def test_anchor_rejects_modified_or_stale_manifest(self):
        anchor = FakeAnchor()
        advance_composite_checkpoint_anchor(
            self.manifest, manifest_key=self.manifest_key, anchor=anchor,
            expected_generation=0, now=anchor.now,
        )
        original = self.manifest.read_bytes()
        self.manifest.write_bytes(original + b" ")
        with self.assertRaises(CompositeCheckpointError):
            verify_composite_checkpoint_against_anchor(
                self.manifest, manifest_key=self.manifest_key,
                anchor=anchor, now=anchor.now,
            )


if __name__ == "__main__":
    unittest.main()
