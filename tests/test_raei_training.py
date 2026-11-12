import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rhemascript.evidence.artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact
from rhemascript.evidence.readiness_registry import ReadinessReplayError, ReadinessRunRegistry
from raei.curriculum import CURRICULUM_VERSION, BIBLE_BOOKS, build_registry, registry_summary
from raei.training import (
    RAEITrainingError,
    SCHEMA,
    _prerequisites_met,
    build_training_brief,
    canonical_assessment_bytes,
    get_progress,
    next_unit,
    record_attempt,
)


class RAEITrainingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "evidence"
        self.root.mkdir()
        self.registry = ReadinessRunRegistry(Path(self.tmp.name) / "learning.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def make_artifact(self, unit_id="CS-FOUND", *, attempt_id="ATT-1", score=4,
                      critical_failures=None, assessor_role="RAEI_SELF"):
        unit = next(item for item in build_registry() if item["id"] == unit_id)
        evidence_id = f"EV-{attempt_id}"
        payload = {
            "schema": SCHEMA,
            "curriculum_version": CURRICULUM_VERSION,
            "attempt_id": attempt_id,
            "unit_id": unit_id,
            "learner_id": "RAEI",
            "assessor_id": "RAEI" if assessor_role == "RAEI_SELF" else "HUMAN-1",
            "assessor_role": assessor_role,
            "evidence_id": evidence_id,
            "evidence_version": "v1",
            "criterion_scores": {criterion: score for criterion in unit["rubric"]},
            "critical_failures": list(critical_failures or []),
            "assessor_note": "Assessment generated from retained task evidence.",
            "created_at_utc": "2026-11-12T12:00:00+00:00",
        }
        relative = f"{attempt_id}.json"
        (self.root / relative).write_bytes(canonical_assessment_bytes(payload))
        evidence = verify_artifact(
            self.root, relative, evidence_id=evidence_id, version="v1"
        )
        return payload, evidence

    def test_curriculum_contains_full_scope_and_is_not_mastery(self):
        summary = registry_summary()
        self.assertEqual(summary["curriculum_version"], CURRICULUM_VERSION)
        self.assertEqual(summary["bible_book_count"], 66)
        self.assertEqual(len(BIBLE_BOOKS), 66)
        self.assertEqual(summary["ethics_case_count"], 10)
        self.assertEqual(summary["capability_count"], 15)
        self.assertEqual(summary["interface_count"], 18)
        self.assertEqual(summary["specialist_count"], 13)
        self.assertEqual(summary["total_units"], 146)
        self.assertEqual(summary["status"], "CURRICULUM_DEFINED_NOT_ASSESSED")

    def test_curriculum_enforces_cross_domain_prerequisites(self):
        units = {unit["id"]: unit for unit in build_registry()}
        self.assertEqual(units["PROG-CORE"]["prerequisites"], ["CS-FOUND"])
        self.assertEqual(units["BIBLE-01"]["prerequisites"], ["CAPSTONE-REPRODUCIBLE"])
        self.assertEqual(units["ETH-TRUTH"]["prerequisites"], ["BIBLE-66"])
        self.assertEqual(units["CAP-01"]["prerequisites"], ["ETH-TECH"])
        self.assertEqual(
            set(units["INTEGRATED-CAPSTONE"]["prerequisites"]),
            {"CAPSTONE-REPRODUCIBLE", "BIBLE-66", "ETH-TECH", "QC-COMPLIANCE"},
        )

    def test_next_unit_starts_with_first_engineering_unit(self):
        self.assertEqual(next_unit(self.registry)["id"], "CS-FOUND")

    def test_brief_cannot_bypass_cross_domain_prerequisites(self):
        with self.assertRaisesRegex(RAEITrainingError, "prerequisites"):
            build_training_brief("BIBLE-01", self.registry)

    def test_verified_canonical_attempt_is_recorded_as_provisional(self):
        payload, evidence = self.make_artifact()
        report = record_attempt(self.registry, payload, evidence)
        self.assertEqual(report["status"], "PROVISIONAL_PASS")
        self.assertEqual(report["overall_score"], 4)
        self.assertTrue(report["assessment_binding"].evidence_sha256 == evidence.sha256)
        progress = get_progress(self.registry)
        self.assertEqual(progress["CS-FOUND"]["status"], "PROVISIONAL_PASS")
        self.assertEqual(next_unit(self.registry)["id"], "PROG-CORE")
        self.assertTrue(self.registry.verify())

    def test_low_score_requires_remediation(self):
        payload, evidence = self.make_artifact(score=2)
        report = record_attempt(self.registry, payload, evidence)
        self.assertEqual(report["status"], "NEEDS_REMEDIATION")
        self.assertEqual(next_unit(self.registry)["id"], "CS-FOUND")

    def test_critical_failure_overrides_high_score(self):
        payload, evidence = self.make_artifact(critical_failures=["SECURITY_TEST_FAILED"])
        report = record_attempt(self.registry, payload, evidence)
        self.assertEqual(report["status"], "NEEDS_REMEDIATION")

    def test_forged_evidence_dataclass_is_rejected(self):
        payload, evidence = self.make_artifact()
        forged = EvidenceVersion(
            evidence.evidence_id, evidence.relative_path, evidence.version,
            evidence.sha256, evidence.size_bytes,
        )
        with self.assertRaisesRegex(RAEITrainingError, "exact EvidenceVersion"):
            record_attempt(self.registry, payload, forged)

    def test_dataclass_copy_of_verified_evidence_is_rejected(self):
        payload, evidence = self.make_artifact()
        copied = replace(evidence, sha256="a" * 64)
        with self.assertRaisesRegex(RAEITrainingError, "exact EvidenceVersion"):
            record_attempt(self.registry, payload, copied)

    def test_assessment_payload_must_match_exact_artifact_digest(self):
        payload, evidence = self.make_artifact()
        changed = {**payload, "assessor_note": "tampered"}
        with self.assertRaisesRegex(RAEITrainingError, "does not match"):
            record_attempt(self.registry, changed, evidence)

    def test_evidence_identity_and_version_must_match_artifact(self):
        payload, evidence = self.make_artifact()
        changed = {**payload, "evidence_version": "v2"}
        (self.root / evidence.relative_path).write_bytes(canonical_assessment_bytes(changed))
        changed_evidence = verify_artifact(
            self.root, evidence.relative_path, evidence_id=evidence.evidence_id, version="v2"
        )
        with self.assertRaisesRegex(RAEITrainingError, "does not identify"):
            record_attempt(self.registry, changed, changed_evidence)

    def test_human_review_cannot_be_self_asserted(self):
        payload, evidence = self.make_artifact(assessor_role="HUMAN_INDEPENDENT")
        with self.assertRaisesRegex(RAEITrainingError, "authenticated approval"):
            record_attempt(self.registry, payload, evidence)

    def test_status_only_or_non_json_assessment_is_rejected(self):
        payload, evidence = self.make_artifact()
        with self.assertRaises(RAEITrainingError):
            record_attempt(self.registry, {"status": "PROVISIONAL_PASS"}, evidence)
        with self.assertRaises(RAEITrainingError):
            canonical_assessment_bytes({"score": float("nan")})

    def test_prerequisite_gate_requires_independent_review_for_capstone(self):
        capstone = next(unit for unit in build_registry() if unit["id"] == "INTEGRATED-CAPSTONE")
        provisional = {item: {"status": "PROVISIONAL_PASS"} for item in capstone["prerequisites"]}
        self.assertFalse(_prerequisites_met(capstone, provisional))
        reviewed = {item: {"status": "INDEPENDENTLY_REVIEWED"} for item in capstone["prerequisites"]}
        self.assertTrue(_prerequisites_met(capstone, reviewed))

    def test_replay_with_changed_assessment_is_rejected(self):
        first, evidence1 = self.make_artifact(attempt_id="ATT-REPLAY", score=4)
        record_attempt(self.registry, first, evidence1)
        changed, evidence2 = self.make_artifact(attempt_id="ATT-REPLAY", score=3)
        with self.assertRaises(ReadinessReplayError):
            record_attempt(self.registry, changed, evidence2)

    def test_external_checkpoint_protects_learning_history(self):
        payload, evidence = self.make_artifact()
        record_attempt(self.registry, payload, evidence)
        key = b"raei-learning-checkpoint-secret-32bytes!"
        checkpoint = self.registry.checkpoint(key)
        self.assertTrue(self.registry.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.registry.database) as db:
            db.execute("UPDATE readiness_runs SET payload_json='{}' WHERE run_id='ATT-1'")
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, key))


if __name__ == "__main__":
    unittest.main()
