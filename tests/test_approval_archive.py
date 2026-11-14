import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from datetime import datetime, timezone

from rhemascript.core.approval_store import (
    ApprovalStoreError, SQLiteApprovalConsumptionStore, SQLitePublishSessionRegistry,
)
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
        self.store = SQLitePublishSessionRegistry(self.db_dir / "approvals.sqlite3")
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
        self.assertEqual(result["publish_session_count"], 0)
        self.assertEqual(result["snapshot_schema"], "RhemaScript.ApprovalStateCheckpoint.v5")
        self.assertTrue(result["matches_current_state"])

    def test_generation_bound_v2_archive_retains_generation_and_digest(self):
        path = export_checkpoint_archive(
            self.store, self.archive, key=self.key, generation=7,
        )
        result = verify_checkpoint_archive(path, key=self.key, current_store=self.store)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["generation"], 7)
        self.assertEqual(result["schema"], "RhemaScript.ApprovalCheckpointArchive.v2")
        self.assertTrue(result["matches_current_state"])

    def test_generation_must_be_positive_integer(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            export_checkpoint_archive(
                self.store, self.archive, key=self.key, generation=True,
            )

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

    def test_archive_must_not_be_nested_under_database_directory(self):
        nested_archive_dir = self.db_dir / "external-looking-subdirectory"
        nested_archive_dir.mkdir(mode=0o700)
        os.chmod(nested_archive_dir, 0o700)
        with self.assertRaisesRegex(
            ApprovalStoreError, "outside the approval database directory"
        ):
            export_checkpoint_archive(
                self.store, nested_archive_dir / "checkpoint.json", key=self.key
            )

    def test_destination_is_never_overwritten(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        with self.assertRaisesRegex(ApprovalStoreError, "already exists"):
            export_checkpoint_archive(self.store, self.archive, key=self.key)

    def test_archive_verification_rejects_symbolic_link(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        link = self.archive_dir / "checkpoint-link.json"
        link.symlink_to(self.archive)
        with self.assertRaisesRegex(ApprovalStoreError, "symbolic link"):
            verify_checkpoint_archive(link, key=self.key)

    def test_export_rejects_archive_larger_than_verification_limit(self):
        with patch("rhemascript.core.approval_archive.MAX_ARCHIVE_BYTES", 100):
            with self.assertRaisesRegex(ApprovalStoreError, "exceeds the permitted size"):
                export_checkpoint_archive(self.store, self.archive, key=self.key)
        self.assertFalse(self.archive.exists())

    def test_archive_verification_rejects_oversized_file(self):
        from rhemascript.core.approval_archive import MAX_ARCHIVE_BYTES
        oversized = self.archive_dir / "oversized.json"
        oversized.write_bytes(b"x" * (MAX_ARCHIVE_BYTES + 1))
        os.chmod(oversized, 0o600)
        with self.assertRaisesRegex(ApprovalStoreError, "bounded"):
            verify_checkpoint_archive(oversized, key=self.key)

    def test_archive_verification_rejects_malformed_timestamp(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        envelope = json.loads(self.archive.read_text(encoding="utf-8"))
        envelope["created_at"] = "not-a-timestamp"
        signed = {name: envelope[name] for name in (
            "schema", "created_at", "snapshot_sha256", "snapshot_b64"
        )}
        import hashlib, hmac
        import rhemascript.core.approval_archive as archive_module
        envelope["hmac_sha256"] = hmac.new(self.key, archive_module._canonical(signed), hashlib.sha256).hexdigest()
        self.archive.write_text(json.dumps(envelope), encoding="utf-8")
        os.chmod(self.archive, 0o600)
        with self.assertRaisesRegex(ApprovalStoreError, "malformed or authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)


    def _write_authenticated_payload(self, payload, *, canonical=True):
        import rhemascript.core.approval_archive as archive_module
        snapshot = (archive_module._canonical(payload) if canonical
                    else json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        signed = {
            "schema": "RhemaScript.ApprovalCheckpointArchive.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
            "snapshot_b64": base64.b64encode(snapshot).decode("ascii"),
        }
        envelope = dict(signed)
        envelope["hmac_sha256"] = hmac.new(
            self.key, archive_module._canonical(signed), hashlib.sha256
        ).hexdigest()
        self.archive.write_bytes(archive_module._canonical(envelope))
        os.chmod(self.archive, 0o600)

    def test_v5_archive_verifies_populated_publish_session_rows(self):
        fingerprint = "a" * 64
        artifact_digest = "b" * 64
        session_digest = "c" * 64
        self.assertTrue(self.store.reserve_publish_session(
            project_id="project-1", project_version="v1", request_id="request-1",
            approval_fingerprint=fingerprint, artifact_id="artifact-1",
            artifact_version="v1", artifact_sha256=artifact_digest,
            artifact_size_bytes=1024, owner_id="worker-1",
        ))
        self.assertTrue(self.store.bind_publish_session(
            project_id="project-1", project_version="v1", request_id="request-1",
            approval_fingerprint=fingerprint, artifact_id="artifact-1",
            artifact_version="v1", artifact_sha256=artifact_digest,
            artifact_size_bytes=1024, session_url_sha256=session_digest,
            owner_id="worker-1",
        ))
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        result = verify_checkpoint_archive(self.archive, key=self.key)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["publish_session_count"], 1)



    def test_v5_archive_verifies_completed_publish_session_metadata(self):
        fingerprint = "d" * 64
        artifact_digest = "e" * 64
        session_digest = "f" * 64
        identity = dict(
            project_id="project-complete", project_version="v2", request_id="request-complete",
            approval_fingerprint=fingerprint, artifact_id="artifact-complete",
            artifact_version="v2", artifact_sha256=artifact_digest,
            artifact_size_bytes=1024,
        )
        self.assertTrue(self.store.reserve_publish_session(
            **identity, owner_id="creator",
        ))
        self.assertTrue(self.store.bind_publish_session(
            **identity, session_url_sha256=session_digest, owner_id="creator",
        ))
        self.assertTrue(self.store.finalize_publish_session_operation(
            project_id=identity["project_id"], project_version=identity["project_version"],
            request_id=identity["request_id"], owner_id="creator",
        ))
        self.assertTrue(self.store.begin_publish_chunk(
            **identity, session_url_sha256=session_digest, owner_id="uploader",
            start=0, end=1023, total=1024, body_size=1024,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id=identity["project_id"], project_version=identity["project_version"],
            request_id=identity["request_id"], owner_id="uploader", status=201,
            provider_resource_id="provider_resource_123",
        ))
        session = self.store.get_publish_session(
            project_id=identity["project_id"], project_version=identity["project_version"],
            request_id=identity["request_id"],
        )
        self.assertTrue(self.store.finalize_publish_completion_audit(
            project_id=identity["project_id"], project_version=identity["project_version"],
            request_id=identity["request_id"], owner_id="uploader",
            completion_audit_id=session["completion_audit_id"],
        ))
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        result = verify_checkpoint_archive(self.archive, key=self.key)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["publish_session_count"], 1)

    def test_legacy_v3_archive_remains_verifiable(self):
        legacy_store = SQLiteApprovalConsumptionStore(self.db_dir / "legacy.sqlite3")
        legacy_archive = self.archive_dir / "legacy-v3.json"
        export_checkpoint_archive(legacy_store, legacy_archive, key=self.key)
        result = verify_checkpoint_archive(legacy_archive, key=self.key)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["snapshot_schema"], "RhemaScript.ApprovalStateCheckpoint.v3")
        self.assertEqual(result["publish_session_count"], 0)

    def test_v4_archive_with_empty_publish_sessions_remains_verifiable(self):
        self._write_authenticated_payload({
            "schema": "RhemaScript.ApprovalStateCheckpoint.v4",
            "consumed": [],
            "revoked": [],
            "publish_sessions": [],
        })
        result = verify_checkpoint_archive(self.archive, key=self.key)
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["snapshot_schema"], "RhemaScript.ApprovalStateCheckpoint.v4")


    def test_archive_rejects_authenticated_noncanonical_snapshot_json(self):
        self._write_authenticated_payload({
            "schema": "RhemaScript.ApprovalStateCheckpoint.v5",
            "consumed": [],
            "revoked": [],
            "publish_sessions": [],
        }, canonical=False)
        with self.assertRaisesRegex(ApprovalStoreError, "malformed or authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)


    def test_archive_rejects_noncanonical_nested_identity_claims(self):
        now = datetime.now(timezone.utc).isoformat()
        identity = {
            "subject_id": None, "actor_role": None, "authn_context": None,
            "authenticated_at": None, "identity_session_id": None,
            "identity_policy_version": None, "identity_provider_id": None,
        }
        noncanonical_identity = json.dumps(identity, ensure_ascii=False)
        row = [
            "approval-001", "nonce-001", "issuer-001", "actor-001", "PUBLISH",
            "project-001", "v1", "request-001", now, now, "key-001", now,
            None, None, None, None, None, None, noncanonical_identity,
        ]
        self._write_authenticated_payload({
            "schema": "RhemaScript.ApprovalStateCheckpoint.v5",
            "consumed": [row],
            "revoked": [],
            "publish_sessions": [],
        })
        with self.assertRaisesRegex(ApprovalStoreError, "malformed or authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)

    def test_archive_rejects_authenticated_consumed_row_with_wrong_width(self):
        self._write_authenticated_payload({
            "schema": "RhemaScript.ApprovalStateCheckpoint.v5",
            "consumed": [["approval-id"]],
            "revoked": [],
            "publish_sessions": [],
        })
        with self.assertRaisesRegex(ApprovalStoreError, "malformed or authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)

    def test_archive_rejects_authenticated_publish_session_with_wrong_width(self):
        self._write_authenticated_payload({
            "schema": "RhemaScript.ApprovalStateCheckpoint.v5",
            "consumed": [],
            "revoked": [],
            "publish_sessions": [["project-1", "v1", "request-1"]],
        })
        with self.assertRaisesRegex(ApprovalStoreError, "malformed or authentication failed"):
            verify_checkpoint_archive(self.archive, key=self.key)

    def test_archive_requires_external_key(self):
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            export_checkpoint_archive(self.store, self.archive, key=b"short")


    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative archive writes required")
    def test_export_rejects_replaced_destination_and_preserves_replacement(self):
        original_path = self.archive_dir / "original-opened-inode.json"
        replacement = b"replacement archive must be preserved"
        real_write = os.write
        replaced = False

        def replace_after_open(descriptor, data):
            nonlocal replaced
            if not replaced:
                self.archive.rename(original_path)
                replacement_fd = os.open(
                    self.archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                try:
                    real_write(replacement_fd, replacement)
                finally:
                    os.close(replacement_fd)
                replaced = True
            return real_write(descriptor, data)

        with patch(
            "rhemascript.core.approval_archive.os.write",
            side_effect=replace_after_open,
        ):
            with self.assertRaisesRegex(
                ApprovalStoreError, "destination changed during export"
            ):
                export_checkpoint_archive(self.store, self.archive, key=self.key)

        self.assertTrue(replaced)
        self.assertEqual(self.archive.read_bytes(), replacement)
        self.assertTrue(original_path.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-relative archive reads required")
    def test_verify_rejects_archive_replacement_during_read(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        original_path = self.archive_dir / "original-opened-inode.json"
        replacement = b"replacement archive must not be verified"
        real_read = os.read
        real_write = os.write
        replaced = False

        def replace_after_read(descriptor, size):
            nonlocal replaced
            chunk = real_read(descriptor, size)
            if chunk and not replaced:
                self.archive.rename(original_path)
                replacement_fd = os.open(
                    self.archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                try:
                    real_write(replacement_fd, replacement)
                finally:
                    os.close(replacement_fd)
                replaced = True
            return chunk

        with patch(
            "rhemascript.core.approval_archive.os.read",
            side_effect=replace_after_read,
        ):
            with self.assertRaisesRegex(
                ApprovalStoreError,
                "changed while being read|destination changed during verification",
            ):
                verify_checkpoint_archive(self.archive, key=self.key)

        self.assertTrue(replaced)
        self.assertEqual(self.archive.read_bytes(), replacement)
        self.assertTrue(original_path.exists())


    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptor semantics required")
    def test_export_rejects_parent_directory_replacement_and_preserves_new_entry(self):
        original_directory = self.archive_dir.with_name("independent-archive-original")
        replacement = b"replacement in new archive directory"
        real_write = os.write
        replaced = False

        def replace_parent_after_open(descriptor, data):
            nonlocal replaced
            if not replaced:
                self.archive_dir.rename(original_directory)
                self.archive_dir.mkdir(mode=0o700)
                os.chmod(self.archive_dir, 0o700)
                replacement_path = self.archive_dir / self.archive.name
                replacement_fd = os.open(
                    replacement_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                try:
                    real_write(replacement_fd, replacement)
                finally:
                    os.close(replacement_fd)
                replaced = True
            return real_write(descriptor, data)

        with patch(
            "rhemascript.core.approval_archive.os.write",
            side_effect=replace_parent_after_open,
        ):
            with self.assertRaisesRegex(
                ApprovalStoreError, "archive directory changed during operation"
            ):
                export_checkpoint_archive(self.store, self.archive, key=self.key)

        self.assertTrue(replaced)
        self.assertEqual((self.archive_dir / self.archive.name).read_bytes(), replacement)
        self.assertFalse((original_directory / self.archive.name).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptor semantics required")
    def test_verify_rejects_parent_directory_replacement_during_read(self):
        export_checkpoint_archive(self.store, self.archive, key=self.key)
        original_directory = self.archive_dir.with_name("independent-archive-original")
        replacement = b"replacement in new archive directory"
        real_read = os.read
        real_write = os.write
        replaced = False

        def replace_parent_after_read(descriptor, size):
            nonlocal replaced
            chunk = real_read(descriptor, size)
            if chunk and not replaced:
                self.archive_dir.rename(original_directory)
                self.archive_dir.mkdir(mode=0o700)
                os.chmod(self.archive_dir, 0o700)
                replacement_path = self.archive_dir / self.archive.name
                replacement_fd = os.open(
                    replacement_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                try:
                    real_write(replacement_fd, replacement)
                finally:
                    os.close(replacement_fd)
                replaced = True
            return chunk

        with patch(
            "rhemascript.core.approval_archive.os.read",
            side_effect=replace_parent_after_read,
        ):
            with self.assertRaisesRegex(
                ApprovalStoreError, "archive directory changed during operation"
            ):
                verify_checkpoint_archive(self.archive, key=self.key)

        self.assertTrue(replaced)
        self.assertEqual((self.archive_dir / self.archive.name).read_bytes(), replacement)
        self.assertTrue((original_directory / self.archive.name).exists())


if __name__ == "__main__":
    unittest.main()
