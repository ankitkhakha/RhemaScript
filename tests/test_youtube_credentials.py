import os
import stat
import tempfile
import unittest
from pathlib import Path

from rhemascript.integrations.credentials import (
    PrivateCredentialError, load_private_credentials, write_private_credentials,
)
from rhemascript.integrations.youtube import YouTubeConfig, YouTubeIntegrationError


class YouTubeCredentialFileTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("private credential file permissions are POSIX-specific")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.path = self.directory / "youtube-oauth.json"

    def write(self):
        write_private_credentials(
            self.path, client_id="client-id",
            client_secret="client-secret", refresh_token="refresh-token",
        )

    def test_writes_owner_only_file_and_loads_values(self):
        self.write()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(load_private_credentials(self.path), {
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-token",
        })

    def test_config_can_load_private_file(self):
        self.write()
        config = YouTubeConfig.from_private_file(self.path)
        self.assertEqual(config.client_id, "client-id")
        self.assertEqual(config.client_secret, "client-secret")
        self.assertEqual(config.refresh_token, "refresh-token")

    def test_refuses_to_overwrite_existing_file(self):
        self.write()
        with self.assertRaisesRegex(PrivateCredentialError, "refusing to overwrite"):
            self.write()

    def test_rejects_broad_file_permissions(self):
        self.write()
        self.path.chmod(0o640)
        with self.assertRaisesRegex(PrivateCredentialError, "owner-only"):
            load_private_credentials(self.path)

    def test_rejects_broad_parent_permissions(self):
        self.directory.chmod(0o750)
        with self.assertRaisesRegex(PrivateCredentialError, "owner-only"):
            write_private_credentials(
                self.path, client_id="id", client_secret="secret",
                refresh_token="refresh",
            )

    def test_rejects_symlink_file(self):
        self.write()
        link = self.directory / "linked.json"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(PrivateCredentialError, "non-symlink"):
            load_private_credentials(link)

    def test_rejects_extra_fields_and_empty_values(self):
        self.path.write_text('{"client_id":"id","client_secret":"secret","refresh_token":"token","extra":"x"}')
        self.path.chmod(0o600)
        with self.assertRaisesRegex(PrivateCredentialError, "exactly"):
            load_private_credentials(self.path)
        self.path.write_text('{"client_id":"id","client_secret":"","refresh_token":"token"}')
        with self.assertRaisesRegex(PrivateCredentialError, "empty or invalid"):
            load_private_credentials(self.path)

    def test_config_wraps_storage_errors_without_secret_values(self):
        with self.assertRaises(YouTubeIntegrationError):
            YouTubeConfig.from_private_file(self.path)


if __name__ == "__main__":
    unittest.main()
