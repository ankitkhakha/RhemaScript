import os
import tempfile
import unittest
from pathlib import Path

from rhemascript.integrations.preflight import CREDENTIAL_ENV, inspect_local_preflight


class YouTubePreflightTests(unittest.TestCase):
    def private_directory(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name)
        if os.name == "posix":
            path.chmod(0o700)
        return path

    def test_preflight_passes_when_credentials_present_and_audit_path_is_safe(self):
        directory = self.private_directory()
        env = {name: "configured-secret-value" for name in CREDENTIAL_ENV}
        checks = inspect_local_preflight(directory / "youtube-audit.jsonl", env)
        self.assertTrue(all(passed for _, passed, _ in checks))
        self.assertFalse((directory / "youtube-audit.jsonl").exists())

    def test_preflight_reports_missing_credentials_without_echoing_values(self):
        directory = self.private_directory()
        env = {CREDENTIAL_ENV[0]: "client-id-secret"}
        checks = inspect_local_preflight(directory / "youtube-audit.jsonl", env)
        credential_check = next(item for item in checks if item[0] == "OAuth environment variables")
        self.assertFalse(credential_check[1])
        self.assertNotIn("client-id-secret", repr(checks))

    def test_preflight_rejects_missing_parent_without_creating_it(self):
        directory = self.private_directory()
        missing = directory / "missing" / "audit.jsonl"
        checks = inspect_local_preflight(missing, {})
        self.assertFalse(next(item[1] for item in checks if item[0] == "Local audit destination"))
        self.assertFalse(missing.parent.exists())

    def test_preflight_rejects_symlink_audit_destination(self):
        directory = self.private_directory()
        target = directory / "target.jsonl"
        target.write_text("")
        link = directory / "audit.jsonl"
        link.symlink_to(target)
        checks = inspect_local_preflight(link, {})
        self.assertFalse(next(item[1] for item in checks if item[0] == "Local audit destination"))

    def test_preflight_does_not_create_or_write_audit_file(self):
        directory = self.private_directory()
        audit_path = directory / "audit.jsonl"
        env = {name: "secret" for name in CREDENTIAL_ENV}
        inspect_local_preflight(audit_path, env)
        self.assertFalse(audit_path.exists())


if __name__ == "__main__":
    unittest.main()
