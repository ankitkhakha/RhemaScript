import os
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import json
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path

from rhemascript.core.approvals import ApprovalError, ApprovalVerifier, VerifiedApproval
from rhemascript.core.approval_store import (
    ApprovalStoreError, SQLiteApprovalConsumptionStore, SQLitePublishSessionRegistry,
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
            "action": "REVIEW",
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
            payload, action="REVIEW", project_id="RS-PWW-001",
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

    def test_checkpoint_snapshot_uses_one_snapshot_during_concurrent_revocation(self):
        from unittest.mock import patch

        # WAL allows a writer to commit while the checkpoint holds a read
        # transaction. The checkpoint must retain the pre-write view of both
        # tables instead of combining old consumed rows with new revocations.
        with self.store._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")

        real_connect = self.store._connect
        injected = {"done": False}

        def interleave():
            if injected["done"]:
                return
            injected["done"] = True
            writer = sqlite3.connect(self.path, isolation_level=None)
            try:
                writer.execute(
                    "INSERT INTO revoked_approvals VALUES (?, ?, ?, ?, ?)",
                    ("revoked-race", "nonce-race", "2026-11-13T00:00:00+00:00",
                     "concurrent checkpoint test", "test-actor"),
                )
            finally:
                writer.close()

        class InterleavingCursor:
            def __init__(self, cursor, trigger=False):
                self.cursor = cursor
                self.trigger = trigger

            def fetchall(self):
                rows = self.cursor.fetchall()
                if self.trigger:
                    interleave()
                return rows

            def __getattr__(self, name):
                return getattr(self.cursor, name)

        class InterleavingConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, sql, *args):
                cursor = self.connection.execute(sql, *args)
                return InterleavingCursor(
                    cursor, "FROM consumed_approvals ORDER BY approval_id" in sql
                )

            def __getattr__(self, name):
                return getattr(self.connection, name)

        with patch.object(
            self.store, "_connect",
            side_effect=lambda: InterleavingConnection(real_connect()),
        ):
            snapshot = json.loads(self.store._snapshot_bytes().decode("utf-8"))

        self.assertTrue(injected["done"])
        self.assertEqual(snapshot["revoked"], [])
        self.assertTrue(self.store.is_revoked("revoked-race", "nonce-race"))

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

    def test_expiry_is_rechecked_after_waiting_for_consumption_lock(self):
        # Hold SQLite's writer lock while a credential approaches expiry.
        # Consumption must use the time after BEGIN IMMEDIATE succeeds, not
        # the timestamp captured before waiting for the lock.
        lock = sqlite3.connect(self.path, isolation_level=None)
        lock.execute("BEGIN IMMEDIATE")
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=0.3)
        entry = self.record(
            "approval-lock-expiry-0001", "nonce-lock-expiry-0001", expires_at
        )
        started = threading.Event()
        outcome = []

        def consume():
            started.set()
            outcome.append(self.store._consume_many_once((entry,)))

        worker = threading.Thread(target=consume)
        worker.start()
        self.assertTrue(started.wait(timeout=2))
        time.sleep(0.45)
        lock.execute("ROLLBACK")
        lock.close()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive(), "consumption worker did not finish")
        self.assertEqual(outcome, [False])
        self.assertFalse(self.store.is_consumed(entry.approval_id, entry.nonce))

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


    def test_v3_identity_and_artifact_claims_are_persisted_and_reverified_after_restart(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": "approval-v2-artifact-0001",
            "issuer": "trusted-approval-issuer",
            "actor_id": "director-0001",
            "action": "PUBLISH",
            "project_id": "RS-PWW-001",
            "project_version": "3.2",
            "request_id": "publish-request-0001",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-v2-artifact-0001",
            "key_id": "key-2026-01",
            "artifact_id": "ART-FINAL-001",
            "artifact_version": "1",
            "artifact_sha256": "a" * 64,
            "artifact_size_bytes": 987654,
            "subject_id": "subject-director-0001",
            "actor_role": "publisher",
            "authn_context": "mfa",
            "authenticated_at": now.isoformat(),
            "identity_session_id": "session-director-0001",
            "identity_policy_version": "identity-policy-v1",
            "identity_provider_id": "test-idp",
        }
        payload["signature"] = private_key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()
        verifier = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=self.store.consume_many_once,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {"PUBLISH": ["publisher"]},
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        binding = {
            "artifact_id": "ART-FINAL-001",
            "artifact_version": "1",
            "sha256": "a" * 64,
            "size_bytes": 987654,
        }
        verified = verifier.verify_many_and_consume(
            (payload,),
            ({
                "action": "PUBLISH", "project_id": "RS-PWW-001",
                "project_version": "3.2", "request_id": "publish-request-0001",
                "artifact_binding": binding,
            },),
        )[0]
        self.assertTrue(self.store.is_consumed(verified.approval_id, verified.nonce))
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT artifact_id, artifact_version, artifact_sha256, artifact_size_bytes "
                "FROM consumed_approvals WHERE approval_id=?",
                (verified.approval_id,),
            ).fetchone()
        self.assertEqual(row, ("ART-FINAL-001", "1", "a" * 64, 987654))
        persisted = self.store.list_consumed_approval_records()[0]
        # A new verifier instance models a process restart: signature audit uses
        # the retained public key and persisted signed payload, not in-memory tokens.
        auditor = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=lambda entries: True,
        )
        audit = auditor.verify_persisted_record(persisted)
        self.assertTrue(audit["signature_valid"])

        # During key rotation, retain the old public key for historical audit.
        next_private_key = Ed25519PrivateKey.generate()
        next_public_key = next_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        rotation_auditor = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-01": public_key, "key-2026-02": next_public_key},
            consume_many_once=lambda entries: True,
        )
        self.assertTrue(rotation_auditor.verify_persisted_record(persisted)["signature_valid"])
        retired_key_auditor = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-02": next_public_key},
            consume_many_once=lambda entries: True,
        )
        with self.assertRaisesRegex(ApprovalError, "trusted issuer"):
            retired_key_auditor.verify_persisted_record(persisted)
        self.assertEqual(audit["credential_schema"], "RhemaScript.ApprovalCredential.v3")
        self.assertEqual(audit["artifact_sha256"], "a" * 64)
        self.assertEqual(audit["subject_id"], "subject-director-0001")
        self.assertEqual(audit["actor_role"], "publisher")
        self.assertEqual(audit["authn_context"], "mfa")
        self.assertEqual(audit["identity_session_id"], "session-director-0001")
        self.assertEqual(audit["identity_policy_version"], "identity-policy-v1")
        self.assertEqual(audit["identity_provider_id"], "test-idp")
        for field, value in (
            ("artifact_sha256", "b" * 64),
            ("subject_id", "subject-attacker-0001"),
            ("actor_role", "administrator"),
            ("authn_context", "password-only"),
            ("identity_session_id", "attacker-session-0001"),
            ("identity_policy_version", "identity-policy-v2"),
            ("identity_provider_id", "untrusted-idp"),
        ):
            tampered = dict(persisted)
            tampered[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ApprovalError, "persisted approval signature is invalid"):
                    auditor.verify_persisted_record(tampered)

        checkpoint_key = b"approval-state-checkpoint-key-32-bytes!!"
        checkpoint = self.store.checkpoint(checkpoint_key)
        self.assertTrue(self.store.verify_checkpoint(checkpoint, checkpoint_key))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE consumed_approvals SET identity_claims_json=? WHERE approval_id=?",
                ('{"subject_id":"tampered-subject"}', verified.approval_id),
            )
        self.assertFalse(self.store.verify_checkpoint(checkpoint, checkpoint_key))


class SQLitePublishSessionRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "private"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "publish.sqlite3"
        self.store = SQLitePublishSessionRegistry(self.path)
        self.session_url = "https://www.googleapis.com/upload/youtube/v3/videos/session?upload_id=secret-token"
        self.url_digest = hashlib.sha256(self.session_url.encode()).hexdigest()
        self.identity = {
            "project_id": "PROJECT-1",
            "project_version": "7",
            "request_id": "REQUEST-1",
            "approval_fingerprint": "a" * 64,
            "artifact_id": "FILM-1",
            "artifact_version": "4",
            "artifact_sha256": "b" * 64,
            "artifact_size_bytes": 10,
        }

    def tearDown(self):
        self.temp.cleanup()

    def reserve_and_bind(self, owner="gateway-A"):
        self.assertTrue(self.store.reserve_publish_session(
            **self.identity, owner_id=owner, lease_seconds=60,
        ))
        self.assertTrue(self.store.bind_publish_session(
            **self.identity, session_url_sha256=self.url_digest, owner_id=owner,
        ))
        self.assertTrue(self.store.finalize_publish_session_operation(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id=owner,
        ))

    def test_session_url_digest_only_and_duplicate_session_claim_rejected(self):
        self.reserve_and_bind()
        self.assertFalse(self.store.reserve_publish_session(
            **self.identity, owner_id="gateway-B",
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "ACTIVE")
        self.assertEqual(record["session_url_sha256"], self.url_digest)
        self.assertNotIn("session_url", record)
        self.assertNotIn(b"secret-token", self.path.read_bytes())

    def test_chunk_offsets_are_monotonic_and_completion_is_terminal(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertFalse(self.store.begin_publish_chunk(
            **args, owner_id="gateway-B", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", status=308, range_header="bytes=0-4",
        ))
        self.assertTrue(self.store.finalize_publish_session_operation(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A",
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["acknowledged_offset"], 5)
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=5, end=9, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", status=201, provider_resource_id="video-123",
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "COMPLETE")
        self.assertEqual(record["acknowledged_offset"], 10)
        self.assertEqual(record["provider_resource_id"], "video-123")
        self.assertEqual(record["provider_http_status"], 201)
        self.assertRegex(record["completion_audit_id"], r"^[0-9a-f]{64}$")
        self.assertTrue(self.store.finalize_publish_completion_audit(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", completion_audit_id=record["completion_audit_id"],
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["completion_audited"], 1)
        with self.assertRaisesRegex(ValueError, "chunk byte range is invalid"):
            self.store.begin_publish_chunk(
                **args, owner_id="gateway-A", start=10, end=10, total=10,
                body_size=1, lease_seconds=60,
            )

    def test_completed_response_requires_a_valid_provider_resource_id(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        with self.assertRaisesRegex(ValueError, "validated provider resource ID"):
            self.store.record_publish_response(
                project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
                owner_id="gateway-A", status=201,
            )
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "CHUNK_IN_FLIGHT")
        self.assertIsNone(record["provider_resource_id"])

    def test_wrong_session_url_and_out_of_order_ranges_are_rejected(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": "c" * 64}
        self.assertFalse(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        args["session_url_sha256"] = self.url_digest
        self.assertFalse(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=1, end=5, total=10,
            body_size=5, lease_seconds=60,
        ))

    def test_indeterminate_chunk_can_be_reconciled_but_not_replayed(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.mark_publish_session_indeterminate(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A",
        ))
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertTrue(restarted.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-B", status=308, range_header="bytes=0-2",
        ))
        self.assertTrue(self.store.finalize_publish_session_operation(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-B",
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "ACTIVE")
        self.assertEqual(record["acknowledged_offset"], 3)

    def test_stale_inflight_chunk_requires_lease_expiry_before_restart_reconciliation(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertFalse(self.store.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET lease_expires_at=? WHERE request_id=?",
                ("2000-01-01T00:00:00+00:00", "REQUEST-1"),
            )
        self.assertTrue(self.store.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))

    def test_reconciliation_rejects_acknowledgement_beyond_submitted_chunk(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.mark_publish_session_indeterminate(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A",
        ))
        self.assertTrue(self.store.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        self.assertFalse(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-B", status=308, range_header="bytes=0-9",
        ))
        record = self.store.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "INDETERMINATE")
        self.assertEqual(record["acknowledged_offset"], 0)
        self.assertEqual(record["inflight_end"], 4)

    def test_concurrent_chunk_claims_are_linearizable(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        barrier = threading.Barrier(3)
        outcomes = []
        def claim(owner):
            barrier.wait()
            outcomes.append(self.store.begin_publish_chunk(
                **args, owner_id=owner, start=0, end=4, total=10,
                body_size=5, lease_seconds=60,
            ))
        workers = [
            threading.Thread(target=claim, args=("gateway-A",)),
            threading.Thread(target=claim, args=("gateway-B",)),
        ]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=5)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(sorted(outcomes), [False, True])

    def test_approval_fingerprint_cannot_claim_a_second_request(self):
        self.reserve_and_bind()
        other = {**self.identity, "request_id": "REQUEST-2"}
        self.assertFalse(self.store.reserve_publish_session(**other, owner_id="gateway-B"))

    def test_checkpoint_covers_publish_sessions_and_detects_tampering(self):
        self.reserve_and_bind()
        key = b"publish-session-checkpoint-key-32-bytes!"
        checkpoint = self.store.checkpoint(key)
        self.assertEqual(checkpoint["schema"], "RhemaScript.ApprovalStateCheckpoint.v5")
        self.assertTrue(self.store.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET acknowledged_offset=1 WHERE request_id=?",
                ("REQUEST-1",),
            )
        self.assertFalse(self.store.verify_checkpoint(checkpoint, key))

    def test_v5_checkpoint_covers_completed_provider_result_and_audit_state(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=9, total=10,
            body_size=10, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", status=201, provider_resource_id="video-checkpoint-1",
        ))
        key = b"publish-session-checkpoint-key-32-bytes!"
        checkpoint = self.store.checkpoint(key)
        self.assertEqual(checkpoint["schema"], "RhemaScript.ApprovalStateCheckpoint.v5")
        self.assertTrue(self.store.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET provider_resource_id=? WHERE request_id=?",
                ("video-substituted", "REQUEST-1"),
            )
        self.assertFalse(self.store.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET provider_resource_id=?, completion_audited=1 WHERE request_id=?",
                ("video-checkpoint-1", "REQUEST-1"),
            )
        self.assertFalse(self.store.verify_checkpoint(checkpoint, key))

    def test_registry_rejects_approval_only_v3_checkpoint(self):
        base = SQLiteApprovalConsumptionStore(self.path)
        key = b"publish-session-checkpoint-key-32-bytes!"
        legacy = base.checkpoint(key)
        registry = SQLitePublishSessionRegistry(self.path)
        self.assertFalse(registry.verify_checkpoint(legacy, key))
        self.assertTrue(base.verify_checkpoint(legacy, key))

    def test_backup_restore_preserves_publish_session_and_v5_checkpoint(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", status=308, range_header="bytes=0-4",
        ))
        self.assertTrue(self.store.finalize_publish_session_operation(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A",
        ))
        key = b"publish-session-checkpoint-key-32-bytes!"
        checkpoint = self.store.checkpoint(key)
        backup = self.store.backup_to(self.directory / "publish-session-backup.sqlite3")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"secret-token", backup.read_bytes())
        restored = SQLitePublishSessionRegistry(backup)
        self.assertTrue(restored.verify_checkpoint(checkpoint, key))
        record = restored.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "ACTIVE")
        self.assertEqual(record["acknowledged_offset"], 5)
        self.assertEqual(record["session_url_sha256"], self.url_digest)
        with sqlite3.connect(backup) as db:
            db.execute(
                "UPDATE publish_sessions SET acknowledged_offset=6 WHERE request_id=?",
                ("REQUEST-1",),
            )
        self.assertFalse(restored.verify_checkpoint(checkpoint, key))

    def test_restart_does_not_reuse_unbound_session_creation_claim(self):
        self.assertTrue(self.store.reserve_publish_session(
            **self.identity, owner_id="gateway-A", lease_seconds=60,
        ))
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertFalse(restarted.reserve_publish_session(
            **self.identity, owner_id="gateway-B", lease_seconds=60,
        ))
        record = restarted.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "CREATING")
        self.assertIsNone(record["session_url_sha256"])

    def test_bound_active_session_with_expired_owner_lease_can_be_reclaimed(self):
        self.assertTrue(self.store.reserve_publish_session(
            **self.identity, owner_id="gateway-A", lease_seconds=60,
        ))
        self.assertTrue(self.store.bind_publish_session(
            **self.identity, session_url_sha256=self.url_digest, owner_id="gateway-A",
        ))
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT state, inflight_owner, lease_expires_at FROM publish_sessions WHERE request_id=?",
                ("REQUEST-1",),
            ).fetchone()
        self.assertEqual(row[0], "ACTIVE")
        self.assertEqual(row[1], "gateway-A")
        self.assertIsNotNone(row[2])
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertFalse(self.store.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET lease_expires_at=? WHERE request_id=?",
                ("2000-01-01T00:00:00+00:00", "REQUEST-1"),
            )
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertTrue(restarted.begin_publish_reconciliation(
            **{**self.identity, "session_url_sha256": self.url_digest},
            owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        record = restarted.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "RECONCILING")
        self.assertEqual(record["inflight_owner"], "gateway-B")

    def test_active_308_acknowledgement_with_expired_owner_lease_can_be_reclaimed(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        self.assertTrue(self.store.begin_publish_chunk(
            **args, owner_id="gateway-A", start=0, end=4, total=10,
            body_size=5, lease_seconds=60,
        ))
        self.assertTrue(self.store.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-A", status=308, range_header="bytes=0-4",
        ))
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT state, acknowledged_offset, inflight_owner, lease_expires_at FROM publish_sessions WHERE request_id=?",
                ("REQUEST-1",),
            ).fetchone()
        self.assertEqual(row[0], "ACTIVE")
        self.assertEqual(row[1], 5)
        self.assertEqual(row[2], "gateway-A")
        self.assertIsNotNone(row[3])
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE publish_sessions SET lease_expires_at=? WHERE request_id=?",
                ("2000-01-01T00:00:00+00:00", "REQUEST-1"),
            )
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertTrue(restarted.begin_publish_reconciliation(
            **args, owner_id="gateway-B", total=10, lease_seconds=60,
        ))
        record = restarted.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "RECONCILING")
        self.assertEqual(record["acknowledged_offset"], 5)
        self.assertEqual(record["inflight_owner"], "gateway-B")

    def test_idle_active_session_can_be_status_probed_after_process_restart(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertTrue(restarted.begin_publish_reconciliation(
            **args, owner_id="gateway-restarted", total=10, lease_seconds=60,
        ))
        self.assertTrue(restarted.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-restarted", status=308, range_header=None,
        ))
        self.assertTrue(restarted.finalize_publish_session_operation(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-restarted",
        ))
        record = restarted.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "ACTIVE")
        self.assertEqual(record["acknowledged_offset"], 0)

    def test_idle_active_status_probe_cannot_advance_acknowledged_offset(self):
        self.reserve_and_bind()
        args = {**self.identity, "session_url_sha256": self.url_digest}
        restarted = SQLitePublishSessionRegistry(self.path)
        self.assertTrue(restarted.begin_publish_reconciliation(
            **args, owner_id="gateway-restarted", total=10, lease_seconds=60,
        ))
        self.assertFalse(restarted.record_publish_response(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
            owner_id="gateway-restarted", status=308, range_header="bytes=0-4",
        ))
        record = restarted.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "INDETERMINATE")
        self.assertEqual(record["acknowledged_offset"], 0)

    def test_registry_state_survives_reopening_database(self):
        self.reserve_and_bind()
        reopened = SQLitePublishSessionRegistry(self.path)
        record = reopened.get_publish_session(
            project_id="PROJECT-1", project_version="7", request_id="REQUEST-1",
        )
        self.assertEqual(record["state"], "ACTIVE")
        self.assertEqual(record["session_url_sha256"], self.url_digest)



if __name__ == "__main__":
    unittest.main()
