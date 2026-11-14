import json
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from rhemascript.integrations.youtube_analytics_evidence import build_analytics_evidence_snapshot
from rhemascript.integrations.youtube_analytics_insights import (
    compare_analytics_periods,
    _canonical_digest,
)
from rhemascript.integrations.youtube_analytics_artifact_store import (
    YouTubeAnalyticsArtifactStoreError,
    persist_analytics_evidence_artifact,
)
from rhemascript.evidence.artifact_verification import verify_artifact
from rhemascript.evidence import validate_evidence_pack
from rhemascript.evidence.evidence_pack_integrity import (
    EvidencePackIntegrityError,
    verify_pack_artifacts,
)


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

    def test_persisted_draft_is_byte_verified_when_referenced_by_project_evidence_pack(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        with tempfile.TemporaryDirectory() as directory:
            record = persist_analytics_evidence_artifact(
                snapshot, evidence_root=directory, relative_path="analytics.json",
                artifact_id="YT-ANALYTICS-001", project_id="PROJECT-1",
                project_version="3",
            )
            manifest = {
                "manifest_id": "MANIFEST-1",
                "schema_version": "1.0",
                "project_record": {
                    "record_id": "PROJECT-RECORD-1",
                    "record_type": "RHEMASCRIPT_PROJECT",
                    "schema_version": "1.0",
                    "project_id": "PROJECT-1",
                    "status": "DRAFT",
                    "classification": "OPERATIONAL",
                    "version": "3",
                },
                "artifacts": [record],
                "evidence_records": [{
                    "evidence_id": "EVIDENCE-1",
                    "capability_id": "CAP-01",
                    "payload": {},
                    "evidence_refs": [],
                    "artifact_refs": ["YT-ANALYTICS-001"],
                }],
                "source_to_final_links": [],
            }
            validated = validate_evidence_pack(manifest)
            versions = verify_pack_artifacts(validated, directory)
            self.assertEqual(len(versions), 1)
            self.assertEqual(versions[0].evidence_id, "YT-ANALYTICS-001")
            self.assertEqual(versions[0].sha256, record["sha256"])


    def test_pack_integrity_revalidates_detached_validated_pack(self):
        snapshot = make_snapshot("2026-10-01", "2026-10-01", 10)
        with tempfile.TemporaryDirectory() as directory:
            record = persist_analytics_evidence_artifact(
                snapshot, evidence_root=directory, relative_path="analytics.json",
                artifact_id="YT-ANALYTICS-DETACHED", project_id="PROJECT-1",
                project_version="3",
            )
            manifest = {
                "manifest_id": "MANIFEST-DETACHED",
                "schema_version": "1.0",
                "project_record": {
                    "record_id": "PROJECT-RECORD-DETACHED",
                    "record_type": "RHEMASCRIPT_PROJECT",
                    "schema_version": "1.0",
                    "project_id": "PROJECT-1",
                    "status": "DRAFT",
                    "classification": "OPERATIONAL",
                    "version": "3",
                },
                "artifacts": [record],
                "evidence_records": [{
                    "evidence_id": "EVIDENCE-DETACHED",
                    "capability_id": "CAP-01",
                    "payload": {},
                    "evidence_refs": [],
                    "artifact_refs": ["YT-ANALYTICS-DETACHED"],
                }],
                "source_to_final_links": [],
            }
            validated = validate_evidence_pack(manifest)
            manifest["artifacts"][0]["status"] = "FORGED_AFTER_VALIDATION"
            self.assertEqual(validated.artifacts[0]["status"], "DRAFT")
            validated.artifacts[0]["project_id"] = "OTHER-PROJECT"
            with self.assertRaisesRegex(
                EvidencePackIntegrityError, "failed structural revalidation"
            ):
                verify_pack_artifacts(validated, directory)

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
                current_snapshot=current, previous_snapshot=previous,
            )
            self.assertEqual(record["artifact_type"], "YOUTUBE_ANALYTICS_COMPARISON")
            self.assertEqual(record["comparison_sha256"], comparison["comparison_sha256"])
            self.assertEqual(record["current_snapshot_artifact_id"], "YT-CURRENT")
            self.assertEqual(record["previous_snapshot_artifact_id"], "YT-PREVIOUS")
            self.assertEqual(record["current_snapshot_sha256"], comparison["current_snapshot_sha256"])
            self.assertEqual(record["previous_snapshot_sha256"], comparison["previous_snapshot_sha256"])

    def test_pack_integrity_accepts_comparison_derived_from_exact_source_snapshots(self):
        previous = make_snapshot("2026-10-01", "2026-10-01", 10)
        current = make_snapshot("2026-10-02", "2026-10-02", 15)
        with tempfile.TemporaryDirectory() as directory:
            previous_record = persist_analytics_evidence_artifact(
                previous, evidence_root=directory, relative_path="previous-valid.json",
                artifact_id="YT-PREV-VALID", project_id="PROJECT-1", project_version="3",
            )
            current_record = persist_analytics_evidence_artifact(
                current, evidence_root=directory, relative_path="current-valid.json",
                artifact_id="YT-CURRENT-VALID", project_id="PROJECT-1", project_version="3",
            )
            comparison = compare_analytics_periods(current, previous)
            comparison_record = persist_analytics_evidence_artifact(
                comparison, evidence_root=directory, relative_path="comparison-valid.json",
                artifact_id="YT-COMP-VALID", project_id="PROJECT-1", project_version="3",
                current_snapshot_artifact_id="YT-CURRENT-VALID",
                previous_snapshot_artifact_id="YT-PREV-VALID",
                current_snapshot=current, previous_snapshot=previous,
            )
            manifest = {
                "manifest_id": "MANIFEST-VALID",
                "schema_version": "1.0",
                "project_record": {
                    "record_id": "PROJECT-RECORD-1",
                    "record_type": "RHEMASCRIPT_PROJECT",
                    "schema_version": "1.0",
                    "project_id": "PROJECT-1",
                    "status": "DRAFT",
                    "classification": "OPERATIONAL",
                    "version": "3",
                },
                "artifacts": [previous_record, current_record, comparison_record],
                "evidence_records": [{
                    "evidence_id": "EVIDENCE-VALID",
                    "capability_id": "CAP-01",
                    "payload": {},
                    "evidence_refs": [],
                    "artifact_refs": ["YT-COMP-VALID"],
                }],
                "source_to_final_links": [
                    {"from_artifact_id": "YT-PREV-VALID", "to_artifact_id": "YT-COMP-VALID",
                     "relationship": "DERIVED_FROM"},
                    {"from_artifact_id": "YT-CURRENT-VALID", "to_artifact_id": "YT-COMP-VALID",
                     "relationship": "DERIVED_FROM"},
                ],
            }
            validated = validate_evidence_pack(manifest)
            verified = verify_pack_artifacts(validated, directory)
            self.assertEqual(
                {item.evidence_id for item in verified},
                {"YT-PREV-VALID", "YT-CURRENT-VALID", "YT-COMP-VALID"},
            )


    def test_pack_integrity_rejects_forged_comparison_even_when_file_hashes_match(self):
        previous = make_snapshot("2026-10-01", "2026-10-01", 10)
        current = make_snapshot("2026-10-02", "2026-10-02", 15)
        with tempfile.TemporaryDirectory() as directory:
            previous_record = persist_analytics_evidence_artifact(
                previous, evidence_root=directory, relative_path="previous.json",
                artifact_id="YT-PREV", project_id="PROJECT-1", project_version="3",
            )
            current_record = persist_analytics_evidence_artifact(
                current, evidence_root=directory, relative_path="current.json",
                artifact_id="YT-CURRENT", project_id="PROJECT-1", project_version="3",
            )
            forged = compare_analytics_periods(current, previous)
            forged["metrics"]["views"]["current_value"] = "99"
            forged["metrics"]["views"]["absolute_change"] = "89"
            forged["metrics"]["views"]["percentage_change"] = "890"
            forged["comparison_sha256"] = _canonical_digest({
                key: value for key, value in forged.items() if key != "comparison_sha256"
            })

            envelope = {
                "evidence_id": "YT-COMP-FORGED",
                "evidence_version": "1",
                "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
                "project_id": "PROJECT-1",
                "project_version": "3",
                "payload": forged,
            }
            raw = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            (Path(directory) / "forged.json").write_bytes(raw)
            forged_record = {
                "artifact_id": "YT-COMP-FORGED",
                "project_id": "PROJECT-1",
                "project_version": "3",
                "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
                "version": "1",
                "status": "DRAFT",
                "local_path": "forged.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "comparison_sha256": forged["comparison_sha256"],
                "current_snapshot_artifact_id": "YT-CURRENT",
                "previous_snapshot_artifact_id": "YT-PREV",
                "current_snapshot_sha256": current["snapshot_sha256"],
                "previous_snapshot_sha256": previous["snapshot_sha256"],
            }
            manifest = {
                "manifest_id": "MANIFEST-FORGED",
                "schema_version": "1.0",
                "project_record": {
                    "record_id": "PROJECT-RECORD-1",
                    "record_type": "RHEMASCRIPT_PROJECT",
                    "schema_version": "1.0",
                    "project_id": "PROJECT-1",
                    "status": "DRAFT",
                    "classification": "OPERATIONAL",
                    "version": "3",
                },
                "artifacts": [previous_record, current_record, forged_record],
                "evidence_records": [{
                    "evidence_id": "EVIDENCE-FORGED",
                    "capability_id": "CAP-01",
                    "payload": {},
                    "evidence_refs": [],
                    "artifact_refs": ["YT-COMP-FORGED"],
                }],
                "source_to_final_links": [
                    {"from_artifact_id": "YT-PREV", "to_artifact_id": "YT-COMP-FORGED",
                     "relationship": "DERIVED_FROM"},
                    {"from_artifact_id": "YT-CURRENT", "to_artifact_id": "YT-COMP-FORGED",
                     "relationship": "DERIVED_FROM"},
                ],
            }
            validated = validate_evidence_pack(manifest)
            with self.assertRaisesRegex(
                EvidencePackIntegrityError, "does not derive from its exact source snapshots"
            ):
                verify_pack_artifacts(validated, directory)


    def test_comparison_persistence_requires_both_exact_source_snapshots(self):
        previous = make_snapshot("2026-10-01", "2026-10-01", 10)
        current = make_snapshot("2026-10-02", "2026-10-02", 15)
        comparison = compare_analytics_periods(current, previous)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                YouTubeAnalyticsArtifactStoreError, "requires both exact source snapshots"
            ):
                persist_analytics_evidence_artifact(
                    comparison, evidence_root=directory, relative_path="comparison.json",
                    artifact_id="YT-COMP-002", project_id="PROJECT-1",
                    project_version="3", current_snapshot_artifact_id="YT-CURRENT",
                    previous_snapshot_artifact_id="YT-PREVIOUS",
                )
            self.assertFalse((Path(directory) / "comparison.json").exists())

    def test_comparison_persistence_rejects_rehashed_but_wrong_source_derivation(self):
        previous = make_snapshot("2026-10-01", "2026-10-01", 10)
        current = make_snapshot("2026-10-02", "2026-10-02", 15)
        forged = compare_analytics_periods(current, previous)
        forged["metrics"]["views"]["current_value"] = "99"
        forged["metrics"]["views"]["absolute_change"] = "89"
        forged["metrics"]["views"]["percentage_change"] = "890"
        forged["comparison_sha256"] = _canonical_digest({
            key: value for key, value in forged.items() if key != "comparison_sha256"
        })
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                YouTubeAnalyticsArtifactStoreError, "exact source snapshots"
            ):
                persist_analytics_evidence_artifact(
                    forged, evidence_root=directory, relative_path="forged-comparison.json",
                    artifact_id="YT-COMP-FORGED", project_id="PROJECT-1",
                    project_version="3", current_snapshot_artifact_id="YT-CURRENT",
                    previous_snapshot_artifact_id="YT-PREVIOUS",
                    current_snapshot=current, previous_snapshot=previous,
                )
            self.assertFalse((Path(directory) / "forged-comparison.json").exists())


if __name__ == "__main__":
    unittest.main()
