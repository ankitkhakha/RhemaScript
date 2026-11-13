import json
import os
import tempfile
import unittest
from pathlib import Path

from raei.findings import (
    FINDING_SCHEMA if False else RAEIFindingError,
)
from raei.findings import capture_finding, list_findings, SCHEMA
from rhemascript.evidence.artifact_verification import verify_artifact
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry, ReadinessReplayError


class RAEIFindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        os.chmod(self.private, 0o700)
        self.evidence_root = self.private / "evidence"
        self.evidence_root.mkdir(mode=0o700)
        os.chmod(self.evidence_root, 0o700)
        self.registry = ReadinessRunRegistry(self.private / "learning.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def payload(self, finding_id="RS-FND-001", *, reproduction_steps=None, supporting=True):
        support = []
        if supporting:
            support = [{
                "evidence_id": "EV-FND-SUPPORT-001",
                "version": "1.0",
                "relative_path": "screenshot.txt",
                "description": "Screenshot evidence supplied with the observation",
            }]
            (self.evidence_root / "screenshot.txt").write_text(
                "synthetic supporting evidence fixture", encoding="utf-8"
            )
        return {
            "schema": SCHEMA,
            "finding_id": finding_id,
            "version": "1.0",
            "project_id": "RS-PWW-001",
            "title": "Video output ignored the portrait aspect ratio",
            "raw_observation": "The next clip unexpectedly rendered in landscape.",
            "affected_workflow": "video_generation",
            "expected_behavior": "The clip should be portrait 9:16.",
            "observed_behavior": "The returned clip was landscape 16:9.",
            "impact": "The generation attempt and its limited credits were wasted.",
            "reproduction_steps": reproduction_steps or ["Select portrait 9:16 before each clip request."],
            "supporting_evidence": support,
            "evidence_id": f"EV-FND-OBS-{finding_id}",
            "evidence_version": "1.0",
            "created_at_utc": "2026-11-13T01:00:00+00:00",
            "tags": ["aspect-ratio", "provider-workflow"],
            "related_work_ids": ["RS-PWW-001"],
            "supersedes": [],
        }

    def write_artifact(self, payload):
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        path = self.evidence_root / "finding.json"
        path.write_bytes(encoded)
        evidence = verify_artifact(
            self.evidence_root, "finding.json",
            evidence_id=payload["evidence_id"], version=payload["evidence_version"],
        )
        return encoded, evidence

    def test_capture_preserves_exact_evidence_and_starts_unapproved(self):
        payload = self.payload()
        encoded, evidence = self.write_artifact(payload)
        result = capture_finding(self.registry, self.evidence_root, encoded, evidence)
        self.assertTrue(result["recorded"])
        self.assertEqual(result["status"], "SUBMITTED")
        self.assertEqual(result["suggested_evidence_level"], "E2")
        self.assertEqual(result["identity_authentication_status"], "UNVERIFIED")
        findings = list_findings(self.registry, project_id="RS-PWW-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["observation_evidence"]["sha256"], evidence.sha256)
        self.assertEqual(len(findings[0]["supporting_evidence"]), 1)
        self.assertNotIn("approval", findings[0])
        self.assertTrue(self.registry.verify_artifacts(self.evidence_root))

    def test_evidence_suggestion_distinguishes_reported_steps_from_no_steps(self):
        detailed = self.payload("RS-FND-002", reproduction_steps=["Open the project.", "Request the next clip."], supporting=False)
        encoded, evidence = self.write_artifact(detailed)
        result = capture_finding(self.registry, self.evidence_root, encoded, evidence)
        self.assertEqual(result["suggested_evidence_level"], "E1")

        minimal = self.payload("RS-FND-003", reproduction_steps=[], supporting=False)
        encoded, evidence = self.write_artifact(minimal)
        result = capture_finding(self.registry, self.evidence_root, encoded, evidence)
        self.assertEqual(result["suggested_evidence_level"], "E0")

    def test_same_finding_version_cannot_be_replayed_with_changed_content(self):
        first = self.payload("RS-FND-004")
        encoded, evidence = self.write_artifact(first)
        capture_finding(self.registry, self.evidence_root, encoded, evidence)
        changed = dict(first)
        changed["raw_observation"] = "A different observation was supplied."
        encoded, evidence = self.write_artifact(changed)
        with self.assertRaises(ReadinessReplayError):
            capture_finding(self.registry, self.evidence_root, encoded, evidence)

    def test_caller_cannot_supply_approval_or_evidence_grade(self):
        payload = self.payload("RS-FND-005")
        payload["status"] = "APPROVED"
        encoded, evidence = self.write_artifact(payload)
        with self.assertRaises(RAEIFindingError):
            capture_finding(self.registry, self.evidence_root, encoded, evidence)

    def test_primary_artifact_bytes_must_match_verified_version(self):
        payload = self.payload("RS-FND-006")
        encoded, evidence = self.write_artifact(payload)
        with self.assertRaises(RAEIFindingError):
            capture_finding(self.registry, self.evidence_root, encoded + b" ", evidence)

    def test_changed_supporting_artifact_blocks_registry_verification(self):
        payload = self.payload("RS-FND-007")
        encoded, evidence = self.write_artifact(payload)
        capture_finding(self.registry, self.evidence_root, encoded, evidence)
        (self.evidence_root / "screenshot.txt").write_text("altered", encoding="utf-8")
        self.assertFalse(self.registry.verify_artifacts(self.evidence_root))


if __name__ == "__main__":
    unittest.main()
