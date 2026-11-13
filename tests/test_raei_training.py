import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rhemascript.evidence.artifact_verification import EvidenceIntegrityError, EvidenceVersion, verify_artifact
from rhemascript.evidence.readiness_registry import ReadinessReplayError, ReadinessRunRegistry
from raei.curriculum import CURRICULUM_VERSION, SUPPORTED_CURRICULUM_VERSIONS, BIBLE_BOOKS, build_registry, registry_summary
from raei.training import (
    RAEITrainingError,
    SCHEMA,
    _prerequisites_met,
    build_self_assessment_payload,
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
        self.assertEqual(summary["total_units"], 154)
        self.assertEqual(summary["biblical_wisdom_count"], 8)
        self.assertIn("RAEI-CURRICULUM-1.0", SUPPORTED_CURRICULUM_VERSIONS)
        self.assertEqual(summary["status"], "CURRICULUM_DEFINED_NOT_ASSESSED")

    def test_curriculum_enforces_cross_domain_prerequisites(self):
        units = {unit["id"]: unit for unit in build_registry()}
        self.assertEqual(units["PROG-CORE"]["prerequisites"], ["CS-FOUND"])
        self.assertEqual(units["BIBLE-01"]["prerequisites"], ["CAPSTONE-REPRODUCIBLE"])
        self.assertEqual(units["ETH-TRUTH"]["prerequisites"], ["BIBLE-66"])
        self.assertEqual(units["BWSF-01"]["prerequisites"], ["ETH-TECH"])
        self.assertEqual(units["BWSF-08"]["prerequisites"], ["BWSF-07"])
        self.assertEqual(units["CAP-01"]["prerequisites"], ["BWSF-08"])
        self.assertEqual(
            set(units["INTEGRATED-CAPSTONE"]["prerequisites"]),
            {"CAPSTONE-REPRODUCIBLE", "BIBLE-66", "ETH-TECH", "BWSF-08", "QC-COMPLIANCE"},
        )

    def test_bwsf_units_are_evidence_required_and_contextual(self):
        units = {item["id"]: item for item in build_registry()}
        expected = {f"BWSF-{index:02d}" for index in range(1, 9)}
        self.assertTrue(expected.issubset(units))
        for unit_id in expected:
            self.assertEqual(units[unit_id]["domain"], "biblical_wisdom")
            self.assertTrue(units[unit_id]["source_refs"])
            self.assertTrue(units[unit_id]["objectives"])
            self.assertTrue(units[unit_id]["practice_prompt"])
            self.assertTrue(units[unit_id]["evidence_required"])

    def test_self_assessment_payload_builder_uses_versioned_schema(self):
        payload = build_self_assessment_payload(
            "CS-FOUND", "ATT-BUILDER", "EV-BUILDER", "v1",
            {"accuracy": 4, "reasoning": 4, "execution": 4, "evidence": 4},
            created_at_utc="2026-11-12T12:00:00+00:00",
        )
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["curriculum_version"], CURRICULUM_VERSION)
        self.assertEqual(payload["assessor_role"], "RAEI_SELF")

    def test_next_unit_starts_with_first_engineering_unit(self):
        self.assertEqual(next_unit(self.registry, evidence_root=self.root)["id"], "CS-FOUND")

    def test_brief_cannot_bypass_cross_domain_prerequisites(self):
        with self.assertRaisesRegex(RAEITrainingError, "prerequisites"):
            build_training_brief("BIBLE-01", self.registry, evidence_root=self.root)

    def test_verified_canonical_attempt_is_recorded_as_provisional(self):
        payload, evidence = self.make_artifact()
        report = record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        self.assertEqual(report["status"], "PROVISIONAL_PASS")
        self.assertEqual(report["overall_score"], 4)
        self.assertTrue(report["assessment_binding"].evidence_sha256 == evidence.sha256)
        progress = get_progress(self.registry, evidence_root=self.root)
        self.assertEqual(progress["CS-FOUND"]["status"], "PROVISIONAL_PASS")
        self.assertEqual(next_unit(self.registry, evidence_root=self.root)["id"], "PROG-CORE")
        self.assertTrue(self.registry.verify())

    def test_low_score_requires_remediation(self):
        payload, evidence = self.make_artifact(score=2)
        report = record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        self.assertEqual(report["status"], "NEEDS_REMEDIATION")
        self.assertEqual(next_unit(self.registry, evidence_root=self.root)["id"], "CS-FOUND")

    def test_critical_failure_overrides_high_score(self):
        payload, evidence = self.make_artifact(critical_failures=["SECURITY_TEST_FAILED"])
        report = record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        self.assertEqual(report["status"], "NEEDS_REMEDIATION")

    def test_forged_evidence_dataclass_is_rejected(self):
        payload, evidence = self.make_artifact()
        forged = EvidenceVersion(
            evidence.evidence_id, evidence.relative_path, evidence.version,
            evidence.sha256, evidence.size_bytes,
        )
        with self.assertRaisesRegex(RAEITrainingError, "exact EvidenceVersion"):
            record_attempt(self.registry, payload, forged, evidence_root=self.root)

    def test_dataclass_copy_of_verified_evidence_is_rejected(self):
        payload, evidence = self.make_artifact()
        copied = replace(evidence, sha256="a" * 64)
        with self.assertRaisesRegex(RAEITrainingError, "exact EvidenceVersion"):
            record_attempt(self.registry, payload, copied, evidence_root=self.root)

    def test_assessment_payload_must_match_exact_artifact_digest(self):
        payload, evidence = self.make_artifact()
        changed = {**payload, "assessor_note": "tampered"}
        with self.assertRaisesRegex(RAEITrainingError, "does not match"):
            record_attempt(self.registry, changed, evidence, evidence_root=self.root)

    def test_evidence_identity_and_version_must_match_artifact(self):
        payload, evidence = self.make_artifact()
        changed_evidence = verify_artifact(
            self.root, evidence.relative_path, evidence_id="EV-OTHER", version="v2"
        )
        with self.assertRaisesRegex(RAEITrainingError, "does not identify"):
            record_attempt(self.registry, payload, changed_evidence, evidence_root=self.root)

    def test_human_review_cannot_be_self_asserted(self):
        payload, evidence = self.make_artifact(assessor_role="HUMAN_INDEPENDENT")
        with self.assertRaisesRegex(RAEITrainingError, "authenticated approval"):
            record_attempt(self.registry, payload, evidence, evidence_root=self.root)

    def test_status_only_or_non_json_assessment_is_rejected(self):
        payload, evidence = self.make_artifact()
        with self.assertRaises(RAEITrainingError):
            record_attempt(self.registry, {"status": "PROVISIONAL_PASS"}, evidence, evidence_root=self.root)
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
        record_attempt(self.registry, first, evidence1, evidence_root=self.root)
        changed, evidence2 = self.make_artifact(attempt_id="ATT-REPLAY", score=3)
        with self.assertRaises(ReadinessReplayError):
            record_attempt(self.registry, changed, evidence2, evidence_root=self.root)

    def test_rewritten_status_cannot_self_grant_independent_review(self):
        payload, evidence = self.make_artifact()
        record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        stored = self.registry.get("ATT-1")
        stored["report"]["status"] = "INDEPENDENTLY_REVIEWED"
        encoded = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.registry.database) as db:
            db.execute(
                "UPDATE readiness_runs SET payload_sha256=?, payload_json=? WHERE run_id=?",
                (digest, encoded, "ATT-1"),
            )
        self.assertFalse(self.registry.verify())
        with self.assertRaisesRegex(ValueError, "integrity verification failed"):
            get_progress(self.registry, evidence_root=self.root)

    def test_external_checkpoint_protects_learning_history(self):
        payload, evidence = self.make_artifact()
        record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        key = b"raei-learning-checkpoint-secret-32bytes!"
        checkpoint = self.registry.checkpoint(key)
        self.assertTrue(self.registry.verify_checkpoint(checkpoint, key))
        with sqlite3.connect(self.registry.database) as db:
            db.execute("UPDATE readiness_runs SET payload_json='{}' WHERE run_id='ATT-1'")
        self.assertFalse(self.registry.verify_checkpoint(checkpoint, key))


    def test_direct_training_reads_reverify_retained_evidence_bytes(self):
        payload, evidence = self.make_artifact()
        record_attempt(self.registry, payload, evidence, evidence_root=self.root)
        (self.root / evidence.relative_path).write_bytes(b"tampered after intake")
        with self.assertRaisesRegex(RAEITrainingError, "integrity verification failed"):
            get_progress(self.registry, evidence_root=self.root)

    def test_record_attempt_rechecks_bytes_after_initial_verification(self):
        payload, evidence = self.make_artifact()
        (self.root / evidence.relative_path).write_bytes(b"tampered after verification")
        with self.assertRaisesRegex(RAEITrainingError, "bytes changed after verification"):
            record_attempt(self.registry, payload, evidence, evidence_root=self.root)


if __name__ == "__main__":
    unittest.main()
