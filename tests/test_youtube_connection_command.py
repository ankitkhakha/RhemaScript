import json
import os
import tempfile
import unittest
from pathlib import Path

from rhemascript.integrations.connection import (
    read_only_youtube_binding,
    run_connection_check,
)
from rhemascript.integrations.credentials import write_private_credentials
from rhemascript.integrations.youtube import YouTubeIntegrationError


class ReadOnlyConnectionCommandTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("credential file permission tests require POSIX")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.credentials = self.root / "youtube-oauth.json"
        write_private_credentials(
            self.credentials,
            client_id="client-id",
            client_secret="client-secret-value",
            refresh_token="refresh-token-value",
        )
        self.audit = self.root / "audit.jsonl"

    class FakeTransport:
        def __init__(self, channel_id):
            self.channel_id = channel_id
            self.calls = []

        def send_request(self, url, method, headers, body, timeout):
            self.calls.append((url, method, dict(headers), body))
            if url == "https://oauth2.googleapis.com/token":
                return 200, b'{"access_token":"temporary-access-token"}', {}
            if url.startswith("https://www.googleapis.com/youtube/v3/channels?"):
                payload = {
                    "items": [{
                        "id": self.channel_id,
                        "snippet": {"title": "RhemaScript"},
                    }]
                }
                return 200, json.dumps(payload).encode(), {}
            raise AssertionError("unexpected operation reached transport")

    def test_command_verifies_identity_and_records_redacted_audit(self):
        transport = self.FakeTransport("UC_expected_channel")
        result = run_connection_check(
            self.credentials, "UC_expected_channel", self.audit, transport=transport
        )
        self.assertEqual(result["status"], "CONNECTED")
        self.assertEqual(result["identity"], "MATCH")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["publishing_enabled"])
        self.assertEqual([call[1] for call in transport.calls], ["POST", "GET"])
        audit_text = self.audit.read_text()
        self.assertIn("timestamp_utc", audit_text)
        self.assertNotIn("client-secret-value", audit_text)
        self.assertNotIn("refresh-token-value", audit_text)
        self.assertNotIn("temporary-access-token", audit_text)
        self.assertNotIn("UC_expected_channel", audit_text)
        self.assertNotIn("RhemaScript", audit_text)
        events = [json.loads(line) for line in audit_text.splitlines()]
        identity = [event for event in events if event["operation"] == "CHANNEL_IDENTITY_VERIFY"]
        self.assertEqual(identity[-1]["phase"], "COMPLETED")

    def test_mismatched_channel_fails_closed_and_audits_without_identity(self):
        transport = self.FakeTransport("UC_wrong_channel")
        with self.assertRaises(YouTubeIntegrationError):
            run_connection_check(
                self.credentials, "UC_expected_channel", self.audit, transport=transport
            )
        audit_text = self.audit.read_text()
        self.assertNotIn("UC_wrong_channel", audit_text)
        self.assertNotIn("UC_expected_channel", audit_text)
        events = [json.loads(line) for line in audit_text.splitlines()]
        identity = [event for event in events if event["operation"] == "CHANNEL_IDENTITY_VERIFY"]
        self.assertEqual(identity[-1]["phase"], "FAILED")

    def test_connection_binding_has_no_write_operations(self):
        binding = read_only_youtube_binding()
        self.assertEqual(binding.interface_id, "IF-18")
        self.assertEqual(set(binding.operations), {"OAUTH_TOKEN", "CHANNEL_READ"})

    def test_rejects_group_or_world_accessible_audit_directory_before_network(self):
        self.root.chmod(0o755)
        transport = self.FakeTransport("UC_expected_channel")
        with self.assertRaisesRegex(YouTubeIntegrationError, "owner-controlled"):
            run_connection_check(
                self.credentials, "UC_expected_channel", self.audit, transport=transport
            )
        self.assertEqual(transport.calls, [])
        self.assertFalse(self.audit.exists())

    def test_rejects_symlink_audit_directory(self):
        real_dir = self.root / "real-audit"
        real_dir.mkdir(mode=0o700)
        link = self.root / "audit-link"
        link.symlink_to(real_dir, target_is_directory=True)
        transport = self.FakeTransport("UC_expected_channel")
        with self.assertRaisesRegex(YouTubeIntegrationError, "owner-controlled"):
            run_connection_check(
                self.credentials, "UC_expected_channel",
                link / "audit.jsonl", transport=transport
            )
        self.assertEqual(transport.calls, [])

    def test_missing_credentials_still_produces_redacted_failure_audit(self):
        missing = self.root / "missing.json"
        with self.assertRaises(YouTubeIntegrationError):
            run_connection_check(missing, "UC_expected_channel", self.audit)
        audit_text = self.audit.read_text()
        self.assertIn("CHANNEL_IDENTITY_VERIFY", audit_text)
        self.assertIn('"phase":"FAILED"', audit_text)
        self.assertNotIn("UC_expected_channel", audit_text)


if __name__ == "__main__":
    unittest.main()
