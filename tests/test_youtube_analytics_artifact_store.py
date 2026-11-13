import json
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from rhemascript.integrations.youtube_analytics_evidence import build_analytics_evidence_snapshot
from rhemascript.integrations.youtube_analytics_insights import compare_analytics_periods
from rhemascript.integrations.youtube_analytics_artifact_store import (
    YouTubeAnalyticsArtifactStoreError,
    persist_analytics_evidence_artifact,
)
from rhemascript.evidence.artifact_verification import verify_artifact


def make_snapshot(start, end, views):
    params = {
        "ids": "channel==MINE",
        "startDate": start,
        "endDate": end,
        "metrics": "views,estimatedMinutesWatched",
        "dimensions": "day",
    }
    report = {
        "kind": "youtubeAnalytics#resultTable",
        "columnHeaders": [
            {"name": "day", "dataType": "STRING", "columnType": "DIMENSION"},
            {"name": "views", "dataType": "INTEGER", "columnType": "METRIC"},
            {"name": "estimatedMinutesWatched", "dataType": "FLOAT", "columnType": "METRIC"},
        ],
        "rows": [[start, views, float(views) / 2]],
    }
    return build_analytics_evidence_snapshot(
        params=params, report=report,
        retrieved_at=datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc),
    )


class YouTubeAnalyticsArtifactStoreTests(unittest.TestCase):
    def test_persists_snapshot_as_draft_with_separate_file_and_payload_digests(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "youtube").mkdir()
            record = persist_analytics_evidence_artifact(
                snapshot, evidence_root=directory, relative_path="youtube/analytics.json",
                artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                project_version="3",
            )
            self.assertEqual(record["artifact_type"], "YOUTUBE_ANALYTICS_SNAPSHOT")
            self.assertEqual(record["status"], "DRAFT")
            self.assertEqual(record["snapshot_sha256"], snapshot["snapshot_sha256"])
            self.assertNotEqual(record["sha256"], record["snapshot_sha256"])
            verified = verify_artifact(
                directory, record["local_path"], evidence_id=record["artifact_id"],
                version=record["version"],
            )
            self.assertEqual(verified.sha256, record["sha256"])
            envelope = json.loads((Path(directory) / record["local_path"]).read_text(encoding="utf-8"))
            self.assertEqual(envelope["payload"], snapshot)
            self.assertEqual(os.stat(Path(directory) / record["local_path"]).st_mode & 0o777, 0o600)

    def test_refuses_to_overwrite_existing_evidence(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        with tempfile.TemporaryDirectory() as directory:
            first = persist_analytics_evidence_artifact(
                snapshot, evidence_root=directory, relative_path="analytics.json",
                artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                project_version="3",
            )
            original = (Path(directory) / first["local_path"]).read_bytes()
            with self.assertRaisesRegex(YouTubeAnalyticsArtifactStoreError, "overwrite"):
                persist_analytics_evidence_artifact(
                    snapshot, evidence_root=directory, relative_path="analytics.json",
                    artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                    project_version="3",
                )
            self.assertEqual((Path(directory) / first["local_path"]).read_bytes(), original)

    def test_rejects_tampered_snapshot_before_creating_file(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        snapshot["response"]["rows"][0][1] = 999
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(YouTubeAnalyticsArtifactStoreError, "payload verification"):
                persist_analytics_evidence_artifact(
                    snapshot, evidence_root=directory, relative_path="analytics.json",
                    artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                    project_version="3",
                )
            self.assertFalse((Path(directory) / "analytics.json").exists())

    def test_rejects_symlink_parent_and_noncanonical_paths(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            link = Path(directory) / "linked"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(YouTubeAnalyticsArtifactStoreError):
                persist_analytics_evidence_artifact(
                    snapshot, evidence_root=directory, relative_path="linked/analytics.json",
                    artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                    project_version="3",
                )
            with self.assertRaisesRegex(YouTubeAnalyticsArtifactStoreError, "canonical relative"):
                persist_analytics_evidence_artifact(
                    snapshot, evidence_root=directory, relative_path="folder//analytics.json",
                    artifact_id="YT-ANALYTICS-002", project_id="PROJECT-1",
                    project_version="3",
                )
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_persists_comparison_with_two_exact_snapshot_artifact_references(self):
        previous = make_snapshot("2026-10-01", "2026-10-01", 10)
        current = make_snapshot("2026-10-02", "2026-10-02", 15)
        comparison = compare_analytics_periods(current, previous)
        with tempfile.TemporaryDirectory() as directory:
            record = persist_analytics_evidence_artifact(
                comparison, evidence_root=directory, relative_path="comparison.json",
                artifact_id="YT-COMP-001", project_id="PROJECT-1",
                project_version="3", current_snapshot_artifact_id="YT-CURRENT",
                previous_snapshot_artifact_id="YT-PREVIOUS",
            )
            self.assertEqual(record["artifact_type"], "YOUTUBE_ANALYTICS_COMPARISON")
            self.assertEqual(record["comparison_sha256"], comparison["comparison_sha256"])
            self.assertEqual(record["current_snapshot_artifact_id"], "YT-CURRENT")
            self.assertEqual(record["previous_snapshot_artifact_id"], "YT-PREVIOUS")


if __name__ == "__main__":
    unittest.main()
