import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path

from rhemascript.core.approvals import ApprovalVerifier, VerifiedApproval
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

    def record(self, approval_id, nonce, expires_at, *, action="PUBLISH", actor_id="director-0001"):
        return VerifiedApproval(
            approval_id=approval_id, issuer="trusted-approval-issuer",
            actor_id=actor_id, action=action, project_id="RS-PWW-001",
            project_version="3.2", request_id="publish-request-0001",
            issued_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            expires_at=expires_at, nonce=nonce, key_id="key-2026-01",
        )

    def test_public_consume_rejects_caller_constructed_verified_approval(self):
        forged = self.record("approval-forged-0001", "nonce-forged-0001", self.future)
        with self.assertRaisesRegex(ApprovalStoreError, "verifier-issued"):
            self.store.consume_many_once((forged,))
        self.assertFalse(self.store.is_consumed(forged.approval_id, forged.nonce))

    def test_public_consume_accepts_exact_verifier_object_but_rejects_copy(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v1",
            "approval_id": "approval-verified-0001",
            "issuer": "trusted-approval-issuer",
            "actor_id": "director-0001",
            "action": "PUBLISH",
            "project_id": "RS-PWW-001",
            "project_version": "3.2",
            "request_id": "publish-request-0001",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-verified-0001",
            "key_id": "key-2026-01",
        }
        payload["signature"] = private_key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()
        verifier = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=lambda entries: True,
        )
        verified = verifier.verify_and_consume(
            payload, action="PUBLISH", project_id="RS-PWW-001",
            project_version="3.2", request_id="publish-request-0001",
        )
        copied = replace(verified)
        with self.assertRaisesRegex(ApprovalStoreError, "verifier-issued"):
            self.store.consume_many_once((copied,))
        self.assertTrue(self.store.consume_many_once((verified,)))
        self.assertTrue(self.store.is_consumed(verified.approval_id, verified.nonce))

    def test_checkpoint_detects_rewritten_approval_state(self):
        entry = self.record("approval-checkpoint-0001", "nonce-checkpoint-0001", self.future)
        self.store._consume_many_once((entry,))
        key = b"approval-state-checkpoint-key-32-bytes!!"
        checkpoint = self.store.checkpoint(key)
        self.assertTrue(self.store.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE consumed_approvals SET actor_id='tampered-actor'")
        self.assertFalse(self.store.verify_checkpoint(checkpoint, key))

    def test_backup_is_owner_only_and_preserves_replay_state(self):
        entry = self.record("approval-backup-0001", "nonce-backup-0001", self.future)
        self.store._consume_many_once((entry,))
        backup = self.store.backup_to(self.directory / "backup.sqlite3")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        restored = SQLiteApprovalConsumptionStore(backup)
        self.assertTrue(restored.is_consumed(entry.approval_id, entry.nonce))

    def test_checkpoint_rejects_wrong_key_and_malformed_payload(self):
        checkpoint = self.store.checkpoint(b"approval-state-checkpoint-key-32-bytes!!")
        self.assertFalse(self.store.verify_checkpoint(checkpoint, b"wrong-key-which-is-at-least-32-bytes!"))
        self.assertFalse(self.store.verify_checkpoint({"schema": "wrong"}, b"approval-state-checkpoint-key-32-bytes!!"))

    def test_rejects_boolean_sqlite_timeout(self):
        with self.assertRaisesRegex(ValueError, "timeout_seconds"):
            SQLiteApprovalConsumptionStore(self.path, timeout_seconds=True)

    def test_rejects_symlinked_ancestor_directory(self):
        link = Path(self.temp.name) / "linked-private"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ApprovalStoreError, "symlinked directories"):
            SQLiteApprovalConsumptionStore(link / "approvals.sqlite3")

    def test_database_is_owner_only(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_consumes_batch_atomically_and_persists_across_instances(self):
        entries = (
            self.record("approval-final-0001", "nonce-final-0001", self.future,
                        action="FINAL_ACCEPTANCE"),
            self.record("approval-publish-0001", "nonce-publish-0001", self.future,
                        actor_id="publisher-0001"),
        )
        self.assertTrue(self.store._consume_many_once(entries))
        reopened = SQLiteApprovalConsumptionStore(self.path)
        self.assertTrue(reopened.is_consumed("approval-final-0001", "nonce-final-0001"))
        self.assertTrue(reopened.is_consumed("approval-publish-0001", "nonce-publish-0001"))
        self.assertFalse(reopened._consume_many_once(entries))
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                "SELECT actor_id, action, project_id, project_version, request_id "
                "FROM consumed_approvals ORDER BY action"
            ).fetchall()
        self.assertEqual(rows, [
            ("director-0001", "FINAL_ACCEPTANCE", "RS-PWW-001", "3.2", "publish-request-0001"),
            ("publisher-0001", "PUBLISH", "RS-PWW-001", "3.2", "publish-request-0001"),
        ])

    def test_duplicate_existing_entry_rejects_entire_batch(self):
        first = self.record("approval-existing-0001", "nonce-existing-0001", self.future)
        self.assertTrue(self.store._consume_many_once((first,)))
        second = self.record("approval-new-0001", "nonce-new-0001", self.future)
        self.assertFalse(self.store._consume_many_once((second, first)))
        self.assertFalse(self.store.is_consumed("approval-new-0001", "nonce-new-0001"))

    def test_revoked_second_entry_prevents_consuming_first(self):
        self.store.revoke("approval-revoked-0001", "nonce-revoked-0001",
                          revoked_by="operator-0001", reason="operator requested revocation")
        first = self.record("approval-valid-0001", "nonce-valid-0001", self.future)
        second = self.record("approval-revoked-0001", "nonce-revoked-0001", self.future)
        self.assertFalse(self.store._consume_many_once((first, second)))
        self.assertFalse(self.store.is_consumed(first.approval_id, first.nonce))
        self.assertTrue(self.store.is_revoked(second.approval_id, second.nonce))

    def test_rejects_expired_batch_without_consuming_any_entry(self):
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        first = self.record("approval-valid-0002", "nonce-valid-0002", self.future)
        second = self.record("approval-expired-0002", "nonce-expired-0002", expired)
        self.assertFalse(self.store._consume_many_once((first, second)))
        self.assertFalse(self.store.is_consumed(first.approval_id, first.nonce))

    def test_rejects_duplicate_ids_or_nonces_in_batch(self):
        entry = self.record("approval-duplicate-0001", "nonce-duplicate-0001", self.future)
        self.assertFalse(self.store._consume_many_once((entry, entry)))
        self.assertFalse(self.store.is_consumed(entry.approval_id, entry.nonce))

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



    def test_artifact_binding_is_persisted_and_covered_by_external_checkpoint(self):
        entry = replace(
            self.record("approval-artifact-0001", "nonce-artifact-0001", self.future),
            artifact_id="ART-FINAL-001",
            artifact_version="1",
            artifact_sha256="a" * 64,
            artifact_size_bytes=987654,
        )
        self.assertTrue(self.store._consume_many_once((entry,)))
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT artifact_id, artifact_version, artifact_sha256, artifact_size_bytes "
                "FROM consumed_approvals WHERE approval_id=?",
                (entry.approval_id,),
            ).fetchone()
        self.assertEqual(row, ("ART-FINAL-001", "1", "a" * 64, 987654))
        key = b"approval-state-checkpoint-key-32-bytes!!"
        checkpoint = self.store.checkpoint(key)
        self.assertTrue(self.store.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE consumed_approvals SET artifact_sha256=? WHERE approval_id=?",
                ("b" * 64, entry.approval_id),
            )
        self.assertFalse(self.store.verify_checkpoint(checkpoint, key))

if __name__ == "__main__":
    unittest.main()
