import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
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

    def test_completion_audit_event_is_idempotent_across_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="a" * 64,
            )
            sink(event)
            sink(event)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["completion_event_id"], "a" * 64)

    def test_completed_deduplication_retries_fsync_after_uncertain_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="e" * 64,
            )
            with patch("rhemascript.integrations.audit.os.fsync",
                       side_effect=[OSError("simulated fsync failure"), None]) as sync:
                with self.assertRaisesRegex(AuditSinkError, "durably persisted"):
                    sink(event)
                sink(event)
                self.assertEqual(sync.call_count, 2)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)

    def test_indeterminate_deduplication_retries_fsync_after_uncertain_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="INDETERMINATE", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="f" * 64,
            )
            with patch("rhemascript.integrations.audit.os.fsync",
                       side_effect=[OSError("simulated fsync failure"), None]) as sync:
                with self.assertRaisesRegex(AuditSinkError, "durably persisted"):
                    sink(event)
                sink(event)
                self.assertEqual(sync.call_count, 2)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)

    def test_indeterminate_completion_record_does_not_suppress_recovered_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            indeterminate = self.event(
                phase="INDETERMINATE", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="c" * 64,
                error_type="CompletionAuditFailure",
            )
            completed = dict(indeterminate, phase="COMPLETED")
            sink(indeterminate)
            sink(indeterminate)
            sink(completed)
            sink(completed)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["phase"] for record in records],
                             ["INDETERMINATE", "COMPLETED"])
            self.assertEqual(records[0]["completion_event_id"], records[1]["completion_event_id"])

    def test_existing_completion_suppresses_later_indeterminate_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            completed = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="d" * 64,
            )
            sink(completed)
            sink(dict(completed, phase="INDETERMINATE", error_type="LateFailure"))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["phase"] for record in records], ["COMPLETED"])

    def test_completion_event_id_collision_with_different_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="b" * 64,
            )
            sink(event)
            conflicting = dict(event)
            conflicting["provider_resource_id"] = "video-substituted"
            with self.assertRaisesRegex(AuditSinkError, "different provider result"):
                sink(conflicting)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["provider_resource_id"], "video-123")

    def test_deduplication_does_not_ignore_malformed_trailing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="g" * 64,
            )
            sink(event)
            with path.open("ab") as log:
                log.write(b'{"truncated":')
            with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                sink(event)

    def test_noncompletion_append_rejects_malformed_existing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            path.write_bytes(b'not-json\n')
            with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                sink(self.event(request_id="request-2"))

    def test_noncompletion_append_rejects_unterminated_existing_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink(self.event())
            with path.open("ab") as log:
                log.write(b'{"valid":"json-but-no-newline"}')
            with self.assertRaisesRegex(AuditSinkError, "append is unsafe"):
                sink(self.event(request_id="request-2"))

    def test_deduplication_rejects_valid_json_without_record_terminator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="i" * 64,
            )
            sink(event)
            with path.open("ab") as log:
                log.write(b'{"valid":"json-but-no-newline"}')
            with self.assertRaisesRegex(AuditSinkError, "unterminated records"):
                sink(event)

    def test_deduplication_rejects_non_object_json_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="h" * 64,
            )
            sink(event)
            with path.open("ab") as log:
                log.write(b'[]\n')
            with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                sink(event)

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

    def test_accepts_indeterminate_provider_write_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink(self.event(phase="INDETERMINATE", error_type="TimeoutError"))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["phase"], "INDETERMINATE")

    def test_bounds_and_validates_upload_session_audit_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = JsonlAuditSink(Path(directory) / "audit.jsonl")
            with self.assertRaisesRegex(AuditSinkError, "digest field"):
                sink(self.event(phase="COMPLETED", session_url_sha256="not-a-digest"))
            with self.assertRaisesRegex(AuditSinkError, "string field"):
                sink(self.event(phase="COMPLETED", artifact_id="x" * 129))
            with self.assertRaisesRegex(AuditSinkError, "publish-session state"):
                sink(self.event(phase="COMPLETED", publish_session_state="UNKNOWN"))
            with self.assertRaisesRegex(AuditSinkError, "numeric field"):
                sink(self.event(phase="COMPLETED", acknowledged_offset=2**63))

    def test_requires_existing_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "audit.jsonl"
            with self.assertRaisesRegex(AuditSinkError, "parent directory"):
                JsonlAuditSink(missing)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_rejects_group_or_world_accessible_audit_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o750)
            with self.assertRaisesRegex(AuditSinkError, "owner-controlled directory"):
                JsonlAuditSink(Path(directory) / "audit.jsonl")

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
