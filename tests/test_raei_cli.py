import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from raei.curriculum import build_registry
from raei.knowledge import SCHEMA as KNOWLEDGE_SCHEMA, canonical_knowledge_bytes
from raei.training import build_self_assessment_payload, canonical_assessment_bytes


class RAEICLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        os.chmod(self.private, 0o700)
        self.database = self.private / "learning.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        # Each command runs in a distinct interpreter process. This exercises
        # durable state recovery rather than relying on process-local objects.
        completed = subprocess.run(
            [sys.executable, "-m", "raei", *args],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr

    def test_init_creates_private_registry(self):
        code, output, errors = self.run_cli("init", "--database", str(self.database))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["status"], "INITIALIZED")
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)

    def test_init_refuses_existing_database(self):
        self.run_cli("init", "--database", str(self.database))
        code, _, errors = self.run_cli("init", "--database", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("already exists", errors)

    def test_status_requires_existing_database(self):
        code, _, errors = self.run_cli("status", "--database", str(self.database), "--evidence-root", str(self.private))
        self.assertEqual(code, 2)
        self.assertIn("does not exist", errors)

    def test_status_and_next_after_initialization(self):
        self.run_cli("init", "--database", str(self.database))
        code, output, errors = self.run_cli("status", "--database", str(self.database), "--evidence-root", str(self.private))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["recorded_units"], 0)
        code, output, errors = self.run_cli("next", "--database", str(self.database), "--evidence-root", str(self.private))
        self.assertEqual(code, 0, errors)
        self.assertIsNotNone(json.loads(output))

    def test_registry_path_symlink_is_rejected(self):
        self.run_cli("init", "--database", str(self.database))
        link = self.private / "link.sqlite3"
        link.symlink_to(self.database)
        code, _, errors = self.run_cli("status", "--database", str(link), "--evidence-root", str(self.private))
        self.assertEqual(code, 2)
        self.assertIn("symlink", errors)

    def test_verify_detects_missing_artifact_root(self):
        self.run_cli("init", "--database", str(self.database))
        code, _, errors = self.run_cli("verify", "--database", str(self.database), "--evidence-root", str(self.private / "missing"))
        self.assertEqual(code, 2)
        self.assertIn("evidence artefact integrity", errors)

    def test_modified_recorded_evidence_blocks_read_operations(self):
        from rhemascript.evidence.artifact_verification import verify_artifact
        from rhemascript.evidence.readiness_registry import ReadinessRunRegistry

        self.run_cli("init", "--database", str(self.database))
        evidence_root = self.private / "evidence"
        evidence_root.mkdir(mode=0o700)
        os.chmod(evidence_root, 0o700)
        artifact = evidence_root / "proof.json"
        artifact.write_text('{"proof":"original"}', encoding="utf-8")
        verified = verify_artifact(
            evidence_root, "proof.json", evidence_id="EV-CLI-001", version="1.0"
        )
        registry = ReadinessRunRegistry(self.database)
        registry.record(
            "RUN-CLI-001",
            {"assessment_is_approval": False, "assessment_is_execution_authorisation": False},
            (verified,), (),
        )
        artifact.write_text('{"proof":"modified"}', encoding="utf-8")
        code, _, errors = self.run_cli(
            "status", "--database", str(self.database), "--evidence-root", str(evidence_root)
        )
        self.assertEqual(code, 2)
        self.assertIn("integrity verification failed", errors)

    def test_record_knowledge_cli_keeps_item_pending_and_searchable_only_on_request(self):
        self.run_cli("init", "--database", str(self.database))
        evidence_root = self.private / "evidence"
        evidence_root.mkdir(mode=0o700)
        os.chmod(evidence_root, 0o700)
        payload = {
            "schema": KNOWLEDGE_SCHEMA,
            "knowledge_id": "RS-CLI-KNOW-001",
            "version": "1.0",
            "title": "Python packaging guidance",
            "domain": "engineering",
            "source_type": "OFFICIAL_DOC",
            "authority_level": "OFFICIAL_PRIMARY",
            "source_name": "Python Packaging User Guide",
            "source_version": "2026-11",
            "source_reference": "local://python-packaging",
            "summary": "Python packaging and build reliability.",
            "claims": ["Build artifacts should be reproducible."],
            "limitations": ["Applies to the recorded documentation version."],
            "tags": ["python", "packaging"],
            "evidence_id": "EV-CLI-KNOW-001",
            "evidence_version": "1.0",
            "status": "PENDING_REVIEW",
            "source_authentication_status": "NOT_CHECKED",
            "claim_relevance_status": "NOT_ASSESSED",
            "created_at_utc": "2026-11-12T12:00:00+00:00",
            "supersedes": [],
        }
        (evidence_root / "knowledge.json").write_bytes(canonical_knowledge_bytes(payload))
        code, output, errors = self.run_cli(
            "record-knowledge", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--artifact-path", "knowledge.json",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["knowledge_payload"]["status"], "PENDING_REVIEW")
        code, output, errors = self.run_cli(
            "knowledge-search", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--query", "python packaging",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output), [])
        code, output, errors = self.run_cli(
            "knowledge-search", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--query", "python packaging",
            "--include-pending",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(len(json.loads(output)), 1)

    def test_record_attempt_cli_binds_assessment_to_verified_artifact(self):
        self.run_cli("init", "--database", str(self.database))
        evidence_root = self.private / "evidence"
        evidence_root.mkdir(mode=0o700)
        os.chmod(evidence_root, 0o700)
        unit = next(item for item in build_registry() if item["id"] == "CS-FOUND")
        scores = {criterion: 3 for criterion in unit["rubric"]}
        payload = build_self_assessment_payload(
            "CS-FOUND", "ATT-CLI-001", "EV-CLI-ATT-001", "1.0", scores,
            created_at_utc="2026-11-12T12:00:00+00:00",
        )
        (evidence_root / "assessment.json").write_bytes(canonical_assessment_bytes(payload))
        code, output, errors = self.run_cli(
            "record-attempt", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--artifact-path", "assessment.json",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["status"], "PROVISIONAL_PASS")
        code, output, errors = self.run_cli(
            "status", "--database", str(self.database), "--evidence-root", str(evidence_root),
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["recorded_units"], 1)

    def test_capture_finding_cli_records_and_lists_pending_observation(self):
        self.run_cli("init", "--database", str(self.database))
        evidence_root = self.private / "evidence"
        evidence_root.mkdir(mode=0o700)
        os.chmod(evidence_root, 0o700)
        (evidence_root / "screenshot.txt").write_text("synthetic screenshot fixture", encoding="utf-8")
        payload = {
            "schema": "raei-field-finding-v1",
            "finding_id": "RS-FND-CLI-001",
            "version": "1.0",
            "project_id": "RS-PWW-001",
            "title": "Portrait aspect ratio was not retained",
            "raw_observation": "The next clip unexpectedly rendered in landscape.",
            "affected_workflow": "video_generation",
            "expected_behavior": "The clip should be portrait 9:16.",
            "observed_behavior": "The returned clip was landscape 16:9.",
            "impact": "The generation attempt and credits were wasted.",
            "reproduction_steps": ["Select portrait 9:16 before each clip request."],
            "supporting_evidence": [{
                "evidence_id": "EV-CLI-FIND-SUPPORT",
                "version": "1.0",
                "relative_path": "screenshot.txt",
                "description": "Supporting screenshot fixture",
            }],
            "evidence_id": "EV-CLI-FIND-OBS",
            "evidence_version": "1.0",
            "created_at_utc": "2026-11-13T01:00:00+00:00",
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        (evidence_root / "finding.json").write_bytes(encoded)
        code, output, errors = self.run_cli(
            "capture-finding", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--artifact-path", "finding.json",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["status"], "SUBMITTED")
        code, output, errors = self.run_cli(
            "finding-list", "--database", str(self.database),
            "--evidence-root", str(evidence_root), "--project-id", "RS-PWW-001",
        )
        self.assertEqual(code, 0, errors)
        findings = json.loads(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "RS-FND-CLI-001")
        self.assertEqual(findings[0]["identity_authentication_status"], "UNVERIFIED")

    def test_private_parent_is_required(self):
        public = self.root / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        code, _, errors = self.run_cli("init", "--database", str(public / "learning.sqlite3"))
        self.assertEqual(code, 2)
        self.assertIn("private", errors)


if __name__ == "__main__":
    unittest.main()
