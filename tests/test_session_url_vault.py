import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rhemascript.integrations.session_url_vault import (
    SessionUrlVaultError,
    SQLiteEncryptedSessionUrlVault,
    publish_session_vault_reference,
)


class SQLiteEncryptedSessionUrlVaultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / "session-urls.sqlite3"
        self.key = bytes(range(32))
        self.url = "https://www.googleapis.com/upload/youtube/v3/videos?upload_id=opaque-session-token"
        self.identity = {
            "project_id": "PROJECT-1",
            "project_version": "7",
            "request_id": "REQUEST-1",
            "approval_fingerprint": "a" * 64,
            "artifact_id": "FILM-1",
            "artifact_version": "3",
            "artifact_sha256": "b" * 64,
            "artifact_size_bytes": 10,
        }
        self.reference = publish_session_vault_reference(self.identity)
        self.vault = SQLiteEncryptedSessionUrlVault(self.path, self.key)

    def test_encrypted_url_survives_new_vault_instance_without_plaintext_on_disk(self):
        digest = self.vault.store(self.reference, self.url)
        self.assertEqual(len(digest), 64)
        raw = self.path.read_bytes()
        self.assertNotIn(self.url.encode(), raw)
        restarted = SQLiteEncryptedSessionUrlVault(self.path, self.key)
        self.assertEqual(restarted.retrieve(self.reference, expected_sha256=digest), self.url)
        self.assertEqual(restarted.verify_all(), 1)

    def test_wrong_key_and_ciphertext_tampering_fail_closed(self):
        digest = self.vault.store(self.reference, self.url)
        wrong_key = SQLiteEncryptedSessionUrlVault(self.path, b"x" * 32)
        with self.assertRaisesRegex(SessionUrlVaultError, "authentication failed"):
            wrong_key.retrieve(self.reference, expected_sha256=digest)
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT ciphertext FROM session_urls WHERE session_ref=?",
                (self.reference,),
            ).fetchone()
            changed = bytearray(row[0])
            changed[0] ^= 0x01
            db.execute(
                "UPDATE session_urls SET ciphertext=? WHERE session_ref=?",
                (bytes(changed), self.reference),
            )
        with self.assertRaises(SessionUrlVaultError):
            self.vault.retrieve(self.reference, expected_sha256=digest)

    def test_duplicate_reference_cannot_overwrite_existing_session_url(self):
        digest = self.vault.store(self.reference, self.url)
        with self.assertRaisesRegex(SessionUrlVaultError, "overwrite is forbidden"):
            self.vault.store(self.reference, self.url + "-changed")
        self.assertEqual(self.vault.retrieve(self.reference, expected_sha256=digest), self.url)

    def test_backup_restore_preserves_encrypted_url_and_permissions(self):
        digest = self.vault.store(self.reference, self.url)
        backup = self.vault.backup_to(self.root / "session-urls-backup.sqlite3")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.url.encode(), backup.read_bytes())
        restored = SQLiteEncryptedSessionUrlVault(backup, self.key)
        self.assertEqual(restored.retrieve(self.reference, expected_sha256=digest), self.url)

    def test_rejects_untrusted_url_and_invalid_key(self):
        with self.assertRaises(SessionUrlVaultError):
            SQLiteEncryptedSessionUrlVault(self.root / "bad.sqlite3", b"short")
        with self.assertRaises(SessionUrlVaultError):
            self.vault.store(self.reference, "http://www.googleapis.com/upload/youtube/v3/videos?upload_id=x")
        with self.assertRaises(SessionUrlVaultError):
            self.vault.store(self.reference, "https://evil.example/upload/youtube/v3/videos?upload_id=x")

    def test_environment_key_requires_exact_hex_and_is_not_persisted(self):
        with self.assertRaises(SessionUrlVaultError):
            SQLiteEncryptedSessionUrlVault.from_environment(
                self.root / "missing-key.sqlite3", environ={},
            )
        vault = SQLiteEncryptedSessionUrlVault.from_environment(
            self.root / "env-key.sqlite3",
            environ={"RHEMASCRIPT_SESSION_URL_VAULT_KEY": self.key.hex()},
        )
        digest = vault.store(self.reference, self.url)
        self.assertEqual(vault.retrieve(self.reference, expected_sha256=digest), self.url)


if __name__ == "__main__":
    unittest.main()
