import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from rhemascript.integrations.audit import AuditSinkError, JsonlAuditSink


class JsonlAuditSinkTests(unittest.TestCase):
    def event(self, **overrides):
        event = {
            "interface_id": "IF-18", "provider": "youtube",
            "request_id": "request-1", "project_id": "RS-TEST-1",
            "operation": "CHANNEL_READ", "method": "GET",
            "host": "www.googleapis.com", "request_fingerprint": "a" * 64,
            "request_bytes": 0, "phase": "REQUESTED",
        }
        event.update(overrides)
        return event

    def test_appends_jsonl_records_and_uses_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink(self.event())
            sink(self.event(phase="COMPLETED", http_status=200, response_bytes=17))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["phase"] for record in records],
                             ["REQUESTED", "COMPLETED"])
            self.assertTrue(all(record["timestamp_utc"] for record in records))
            self.assertEqual(records[1]["http_status"], 200)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rejects_payload_or_secret_bearing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            with self.assertRaisesRegex(AuditSinkError, "outside the safe schema"):
                sink(self.event(payload={"media": "private"}, authorization="Bearer secret"))
            self.assertFalse(path.exists())

    def test_rejects_invalid_event_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = JsonlAuditSink(Path(directory) / "audit.jsonl")
            with self.assertRaisesRegex(AuditSinkError, "phase is invalid"):
                sink(self.event(phase="UNKNOWN"))

    def test_requires_existing_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "audit.jsonl"
            with self.assertRaisesRegex(AuditSinkError, "parent directory"):
                JsonlAuditSink(missing)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_rejects_symlink_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.jsonl"
            target.write_text("")
            link = Path(directory) / "audit.jsonl"
            link.symlink_to(target)
            sink = JsonlAuditSink(link)
            with self.assertRaises(AuditSinkError):
                sink(self.event())
            self.assertEqual(target.read_text(), "")


if __name__ == "__main__":
    unittest.main()
