import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from rhemascript.integrations.audit import AuditSinkError, JsonlAuditSink



def _append_audit_events_from_process(path, worker_id, count, barrier, completion=False):
    sink = JsonlAuditSink(path)
    if completion:
        event = {
            "interface_id": "IF-18", "provider": "youtube",
            "request_id": "shared-completion", "project_id": "RS-TEST-1",
            "operation": "UPLOAD_CHUNK", "method": "PUT",
            "host": "www.googleapis.com", "request_fingerprint": "a" * 64,
            "request_bytes": 10, "response_bytes": 24, "http_status": 201,
            "provider_resource_id": "video-123", "completion_event_id": "c" * 64,
            "phase": "COMPLETED",
        }
        barrier.wait(timeout=10)
        for _ in range(count):
            sink(event)
        return
    barrier.wait(timeout=10)
    for index in range(count):
        sink({
            "interface_id": "IF-18", "provider": "youtube",
            "request_id": f"worker-{worker_id}-{index}", "project_id": "RS-TEST-1",
            "operation": "CHANNEL_READ", "method": "GET",
            "host": "www.googleapis.com", "request_fingerprint": "b" * 64,
            "request_bytes": 0, "phase": "REQUESTED",
        })

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

    def test_append_fsyncs_file_and_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            real_fsync = os.fsync
            synced_directory_flags = []

            def record_fsync(descriptor):
                synced_directory_flags.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
                return real_fsync(descriptor)

            with patch("rhemascript.integrations.audit.os.fsync", side_effect=record_fsync) as sync:
                sink(self.event())
            self.assertEqual(sync.call_count, 2)
            self.assertEqual(synced_directory_flags, [False, True])

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
                       side_effect=[OSError("simulated fsync failure"), None, None]) as sync:
                with self.assertRaisesRegex(AuditSinkError, "durably persisted"):
                    sink(event)
                sink(event)
                self.assertEqual(sync.call_count, 3)
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
                       side_effect=[OSError("simulated fsync failure"), None, None]) as sync:
                with self.assertRaisesRegex(AuditSinkError, "durably persisted"):
                    sink(event)
                sink(event)
                self.assertEqual(sync.call_count, 3)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)

    def test_duplicate_retries_parent_directory_fsync_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            event = self.event(
                phase="COMPLETED", http_status=201, response_bytes=24,
                provider_resource_id="video-123", completion_event_id="d" * 64,
            )
            with patch("rhemascript.integrations.audit.os.fsync",
                       side_effect=[None, OSError("simulated directory fsync failure"), None, None]) as sync:
                with self.assertRaisesRegex(AuditSinkError, "durably persisted"):
                    sink(event)
                sink(event)
                self.assertEqual(sync.call_count, 4)
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
                provider_resource_id="video-123", completion_event_id="7" * 64,
            )
            sink(event)
            with path.open("ab") as log:
                log.write(b'{"truncated":\n')
            with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                sink(event)

    def test_rejects_duplicate_json_members_in_historical_audit_rows(self):
        duplicate_rows = (
            b'{"interface_id":"IF-18","interface_id":"IF-99","provider":"youtube",'
            b'"request_id":"request-1","operation":"CHANNEL_READ","phase":"REQUESTED"}\n',
            b'{"interface_id":"IF-18","provider":"youtube","request_id":"request-1",'
            b'"operation":"CHANNEL_READ","phase":"REQUESTED","metadata":{"actor":"reader","actor":"admin"}}\n',
        )
        for index, row in enumerate(duplicate_rows):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "audit.jsonl"
                path.write_bytes(row)
                sink = JsonlAuditSink(path)
                with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                    sink(self.event(request_id=f"after-duplicate-{index}"))

    def test_rejects_nonstandard_numeric_constants_in_historical_audit_rows(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "audit.jsonl"
                row = (
                    b'{"interface_id":"IF-18","provider":"youtube","request_id":"request-1",'
                    b'"operation":"CHANNEL_READ","phase":"REQUESTED","request_bytes":'
                    + constant + b"}\\n"
                )
                path.write_bytes(row)
                sink = JsonlAuditSink(path)
                with self.assertRaisesRegex(AuditSinkError, "malformed records"):
                    sink(self.event(request_id="after-nonstandard-number"))

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
                provider_resource_id="video-123", completion_event_id="9" * 64,
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
                provider_resource_id="video-123", completion_event_id="8" * 64,
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

    def test_new_audit_records_carry_schema_version_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink(self.event())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["schema_version"], 1)

    def test_unversioned_legacy_audit_records_remain_append_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            legacy = self.event()
            legacy["timestamp_utc"] = "2026-11-14T09:00:00+00:00"
            path.write_text(json.dumps(legacy) + "\n")
            sink = JsonlAuditSink(path)
            sink(self.event(request_id="request-after-legacy"))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertNotIn("schema_version", records[0])
            self.assertEqual(records[1]["schema_version"], 1)

    def test_append_rejects_syntactically_valid_records_outside_supported_schema(self):
        invalid_records = [
            dict(self.event(), phase="UNKNOWN"),
            dict(self.event(), phase=[]),
            dict(self.event(), phase={}),
            dict(self.event(), unexpected_metadata="must-not-be-accepted"),
            dict(self.event(), request_bytes="0"),
            dict(self.event(), schema_version=999),
            dict(self.event(), schema_version=True),
        ]
        for index, invalid in enumerate(invalid_records):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "audit.jsonl"
                path.write_text(json.dumps(invalid) + "\n")
                sink = JsonlAuditSink(path)
                with self.assertRaisesRegex(AuditSinkError, "supported schema"):
                    sink(self.event(request_id=f"request-{index}"))

    def test_versioned_audit_records_enforce_metadata_grammar(self):
        invalid_events = [
            self.event(interface_id="IF-18\nforged"),
            self.event(provider="YouTube"),
            self.event(operation="upload_chunk"),
            self.event(method="TRACE"),
            self.event(host="https://www.googleapis.com"),
            self.event(timestamp_utc="not-a-timestamp"),
            self.event(request_id="request\nforged"),
        ]
        for index, event in enumerate(invalid_events):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                sink = JsonlAuditSink(Path(directory) / "audit.jsonl")
                with self.assertRaises(AuditSinkError):
                    sink(event)

    def test_rejects_empty_audit_destination(self):
        with self.assertRaisesRegex(AuditSinkError, "must name a file"):
            JsonlAuditSink("")

    def test_closed_audit_sink_rejects_future_appends(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = JsonlAuditSink(Path(directory) / "audit.jsonl")
            sink.close()
            sink.close()
            with self.assertRaisesRegex(AuditSinkError, "audit sink is closed"):
                sink(self.event())

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


    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors required")
    def test_relative_audit_path_is_pinned_to_initial_working_directory(self):
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            initial = Path(directory) / "initial"
            later = Path(directory) / "later"
            initial.mkdir(mode=0o700)
            later.mkdir(mode=0o700)
            try:
                os.chdir(initial)
                sink = JsonlAuditSink("audit.jsonl")
                os.chdir(later)
                sink(self.event())
                self.assertTrue((initial / "audit.jsonl").is_file())
                self.assertFalse((later / "audit.jsonl").exists())
                sink.close()
            finally:
                os.chdir(original_cwd)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow directory traversal required")
    def test_rejects_symlinked_ancestor_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(AuditSinkError, "contains a symlink"):
                JsonlAuditSink(alias / "audit.jsonl")

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors required")
    def test_directory_replacement_does_not_redirect_append_or_directory_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "private"
            moved = root / "pinned"
            parent.mkdir(mode=0o700)
            sink = JsonlAuditSink(parent / "audit.jsonl")
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            real_fsync = os.fsync
            synced_directories = []

            def record_fsync(descriptor):
                info = os.fstat(descriptor)
                if stat.S_ISDIR(info.st_mode):
                    synced_directories.append((info.st_dev, info.st_ino))
                return real_fsync(descriptor)

            with patch("rhemascript.integrations.audit.os.fsync", side_effect=record_fsync):
                sink(self.event())
            pinned_identity = (moved.stat().st_dev, moved.stat().st_ino)
            replacement_identity = (parent.stat().st_dev, parent.stat().st_ino)
            self.assertTrue((moved / "audit.jsonl").is_file())
            self.assertFalse((parent / "audit.jsonl").exists())
            self.assertIn(pinned_identity, synced_directories)
            self.assertNotIn(replacement_identity, synced_directories)
            sink.close()

    @unittest.skipUnless(os.name == "posix", "POSIX flock semantics required")
    def test_independent_processes_serialize_appends_to_one_audit_file(self):
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            workers, writes_per_worker = 4, 4
            barrier = context.Barrier(workers)
            processes = [
                context.Process(
                    target=_append_audit_events_from_process,
                    args=(str(path), worker_id, writes_per_worker, barrier, False),
                )
                for worker_id in range(workers)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            self.assertTrue(all(process.exitcode == 0 for process in processes))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            expected = workers * writes_per_worker
            self.assertEqual(len(records), expected)
            request_ids = [record["request_id"] for record in records]
            self.assertEqual(len(set(request_ids)), expected)

    @unittest.skipUnless(os.name == "posix", "POSIX flock semantics required")
    def test_independent_processes_deduplicate_same_completion_event(self):
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            workers, retries_per_worker = 4, 3
            barrier = context.Barrier(workers)
            processes = [
                context.Process(
                    target=_append_audit_events_from_process,
                    args=(str(path), worker_id, retries_per_worker, barrier, True),
                )
                for worker_id in range(workers)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            self.assertTrue(all(process.exitcode == 0 for process in processes))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["completion_event_id"], "c" * 64)


if __name__ == "__main__":
    unittest.main()
