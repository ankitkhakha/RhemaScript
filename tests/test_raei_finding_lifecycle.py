import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from raei.findings import capture_finding, list_findings, SCHEMA as FINDING_SCHEMA
from raei.governance import record_finding_disposition
from raei.finding_lifecycle import (
    RAEIFindingLifecycleError, record_finding_research, record_finding_reproduction, record_finding_plan,
)
from rhemascript.core.approvals import ApprovalVerifier
from rhemascript.evidence.artifact_verification import verify_artifact
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry


class RAEIFindingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence_root = self.root / "evidence"
        self.evidence_root.mkdir()
        self.registry = ReadinessRunRegistry(self.root / "readiness.sqlite")
        self.now = datetime.now(timezone.utc)
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.used = set()

        def consume_once(entries):
            ids = [(item.approval_id, item.nonce) for item in entries]
            if len(set(ids)) != len(ids) or any(item in self.used for item in ids):
                return False
            self.used.update(ids)
            return True

        self.verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=consume_once,
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    "FINDING_RESEARCH": ["researcher"],
                    "FINDING_REPRODUCE": ["reproducer"],
                    "FINDING_PLAN": ["planner"],
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        self.finding_id = "RS-FND-LIFECYCLE-001"
        self.finding_version = "1.0"
        self.project_id = "RS-PWW-001"
        self.project_version = "3.2"
        self.finding_evidence = self._capture_finding()

    def _capture_finding(self):
        payload = {
            "schema": FINDING_SCHEMA,
            "finding_id": self.finding_id,
            "version": self.finding_version,
            "project_id": self.project_id,
            "title": "Portrait clip rendered in landscape",
            "raw_observation": "The output ignored the requested portrait ratio.",
            "affected_workflow": "video_generation",
            "expected_behavior": "Output should be 9:16 portrait.",
            "observed_behavior": "Output was 16:9 landscape.",
            "impact": "A generation attempt was wasted.",
            "reproduction_steps": ["Select portrait 9:16 and request a clip."],
            "supporting_evidence": [],
            "evidence_id": "EV-FND-OBS-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
            "tags": ["aspect-ratio"],
            "related_work_ids": ["RS-PWW-001"],
            "supersedes": [],
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        path = self.evidence_root / "observation.json"
        path.write_bytes(raw)
        evidence = verify_artifact(self.evidence_root, path.name, evidence_id=payload["evidence_id"], version="1.0")
        capture_finding(self.registry, self.evidence_root, raw, evidence)
        return evidence

    def _write_report(self, filename, payload, evidence_id):
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        path = self.evidence_root / filename
        path.write_bytes(raw)
        evidence = verify_artifact(self.evidence_root, filename, evidence_id=evidence_id, version="1.0")
        return raw, evidence

    def _credential(self, action, evidence, *, subject_id, actor_id, session_id):
        token = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": f"approval-{action.lower()}-{subject_id}",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": actor_id,
            "action": action,
            "project_id": self.project_id,
            "project_version": self.project_version,
            "request_id": f"request-{action}-{self.finding_id}",
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat(),
            "nonce": f"nonce-{action.lower()}-{subject_id}",
            "key_id": "key-2026-01",
            "artifact_id": evidence.evidence_id,
            "artifact_version": evidence.version,
            "artifact_sha256": evidence.sha256,
            "artifact_size_bytes": evidence.size_bytes,
            "subject_id": subject_id,
            "actor_role": {"FINDING_RESEARCH": "researcher", "FINDING_REPRODUCE": "reproducer", "FINDING_PLAN": "planner"}[action],
            "authn_context": "mfa",
            "authenticated_at": self.now.isoformat(),
            "identity_session_id": session_id,
            "identity_policy_version": "identity-policy-v1",
            "identity_provider_id": "test-idp",
        }
        token["signature"] = self.private_key.sign(
            json.dumps(token, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hex()
        return token

    def _research_report(self):
        return {
            "schema": "raei-finding-research-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "research_question": "Which stage discarded the portrait aspect-ratio constraint?",
            "methodology": "Trace prompt configuration and inspect returned clip metadata.",
            "findings": ["The requested ratio was not preserved in the generation request."],
            "knowledge_gaps": ["Provider-side default precedence remains to be independently verified."],
            "limitations": ["Synthetic investigation fixture; no live provider call."],
            "evidence_id": "EV-FND-RESEARCH-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
        }

    def _reproduction_report(self, outcome="REPRODUCED"):
        return {
            "schema": "raei-finding-reproduction-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "outcome": outcome,
            "environment": "Synthetic local fixture; no external provider call.",
            "steps": ["Set portrait 9:16.", "Submit generation request.", "Inspect returned aspect ratio."],
            "expected_behavior": "9:16 portrait output.",
            "observed_behavior": "16:9 landscape output.",
            "evidence_id": "EV-FND-REPRODUCTION-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
        }

    def _record_research(self):
        report = self._research_report()
        raw, evidence = self._write_report("research.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_RESEARCH", evidence, subject_id="subject-researcher-001",
            actor_id="actor-researcher-001", session_id="session-researcher-001",
        )
        result = record_finding_research(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_RESEARCH-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )
        return result


    def _v1_disposition_credential(self, action, actor, suffix):
        token = {
            "schema": "RhemaScript.ApprovalCredential.v1",
            "approval_id": f"approval-{suffix}",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": actor,
            "action": action,
            "project_id": self.project_id,
            "project_version": self.project_version,
            "request_id": f"request-FINDING-DISPOSITION-{self.finding_id}",
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat(),
            "nonce": f"nonce-{suffix}",
            "key_id": "key-2026-01",
        }
        token["signature"] = self.private_key.sign(
            json.dumps(token, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hex()
        return token

    def _record_reproduction(self, *, subject_id="subject-reproducer-001", session_id="session-reproducer-001"):
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id=subject_id,
            actor_id="actor-reproducer-001", session_id=session_id,
        )
        return record_finding_reproduction(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )

    def _record_accepted_disposition(self):
        research_evidence = verify_artifact(
            self.evidence_root, "research.json",
            evidence_id="EV-FND-RESEARCH-001", version="1.0",
        )
        credentials = (
            self._v1_disposition_credential("FINDING_DISPOSITION_REVIEW", "reviewer-001", "review-001"),
            self._v1_disposition_credential("FINDING_DISPOSITION_CONFIRM", "approver-001", "confirm-001"),
        )
        return record_finding_disposition(
            self.registry, self.verifier, credentials,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING-DISPOSITION-{self.finding_id}",
            disposition="ACCEPTED", rationale="Research and reproduction evidence independently reviewed.",
            evidence_root=str(self.evidence_root), evidence=research_evidence,
        )

    def _plan_report(self):
        return {
            "schema": "raei-finding-plan-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "plan_objective": "Correct the portrait aspect-ratio propagation and prove it remains stable.",
            "scope": "Update the prompt-to-generation aspect-ratio contract and its tests.",
            "tasks": ["Trace ratio field propagation.", "Implement validated mapping.", "Add regression tests."],
            "milestones": ["Contract fixed.", "Regression suite passes."],
            "acceptance_criteria": ["9:16 remains 9:16 through generation request construction."],
            "dependencies": ["Approved implementation scope."],
            "risks": ["Potential regressions in landscape workflows."],
            "rollback_plan": "Revert the scoped commit and restore the prior validated mapping.",
            "evidence_id": "EV-FND-PLAN-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
        }

    def _record_plan(self, *, subject_id="subject-planner-001", session_id="session-planner-001"):
        report = self._plan_report()
        raw, evidence = self._write_report("plan.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_PLAN", evidence, subject_id=subject_id,
            actor_id="actor-planner-001", session_id=session_id,
        )
        return record_finding_plan(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_PLAN-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )

    def test_research_then_independent_reproduction_projects_status(self):
        research = self._record_research()
        self.assertEqual(research["status"], "RESEARCHED")
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id="subject-reproducer-001",
            actor_id="actor-reproducer-001", session_id="session-reproducer-001",
        )
        result = record_finding_reproduction(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )
        self.assertEqual(result["status"], "REPRODUCED")
        finding = list_findings(self.registry)[0]
        self.assertEqual(finding["status"], "REPRODUCED")
        self.assertEqual(finding["reproduction_outcome"], "REPRODUCED")
        self.assertTrue(self.registry.verify_artifacts(self.evidence_root))

    def test_reproduction_before_research_is_rejected(self):
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction-first.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id="subject-reproducer-002",
            actor_id="actor-reproducer-002", session_id="session-reproducer-002",
        )
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "requires prior research"):
            record_finding_reproduction(
                self.registry, self.verifier, credential,
                finding_id=self.finding_id, finding_version=self.finding_version,
                project_id=self.project_id, project_version=self.project_version,
                request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
                evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
            )
        self.assertEqual(list_findings(self.registry)[0]["status"], "SUBMITTED")

    def test_reproduction_requires_different_human_from_researcher(self):
        self._record_research()
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction-same-person.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id="subject-researcher-001",
            actor_id="actor-researcher-001", session_id="session-researcher-002",
        )
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "independent human subject"):
            record_finding_reproduction(
                self.registry, self.verifier, credential,
                finding_id=self.finding_id, finding_version=self.finding_version,
                project_id=self.project_id, project_version=self.project_version,
                request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
                evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
            )
        self.assertEqual(list_findings(self.registry)[0]["status"], "RESEARCHED")

    def test_reproduction_requires_distinct_session_even_for_different_subject(self):
        self._record_research()
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction-shared-session.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id="subject-reproducer-004",
            actor_id="actor-reproducer-004", session_id="session-researcher-001",
        )
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "independent human subject and session"):
            record_finding_reproduction(
                self.registry, self.verifier, credential,
                finding_id=self.finding_id, finding_version=self.finding_version,
                project_id=self.project_id, project_version=self.project_version,
                request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
                evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
            )
        self.assertEqual(list_findings(self.registry)[0]["status"], "RESEARCHED")


    def test_plan_requires_research_reproduction_and_accepted_disposition(self):
        self._record_research()
        self._record_reproduction()
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "accepted governed disposition"):
            self._record_plan()
        self._record_accepted_disposition()
        result = self._record_plan(subject_id="subject-planner-retry-001", session_id="session-planner-retry-001")
        self.assertEqual(result["status"], "PLANNED")
        self.assertEqual(list_findings(self.registry)[0]["status"], "PLANNED")

    def test_plan_rejects_same_human_as_reproducer(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "independent planner"):
            self._record_plan(subject_id="subject-reproducer-001", session_id="session-planner-other")
        self.assertEqual(list_findings(self.registry)[0]["status"], "ACCEPTED")

    def test_generic_append_cannot_forge_research_or_reproduction(self):
        with self.assertRaisesRegex(ValueError, "authenticated finding lifecycle"):
            self.registry.append_activity_event(
                "FINDING_RESEARCHED:RS-FND-LIFECYCLE-001@1.0:request",
                "FINDING_RESEARCHED", {"finding_id": self.finding_id},
                project_id=self.project_id, subject_id=self.finding_id,
            )

    def test_report_bytes_must_match_verified_evidence(self):
        self._record_research()
        report = self._reproduction_report()
        raw, evidence = self._write_report("reproduction-tamper.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_REPRODUCE", evidence, subject_id="subject-reproducer-003",
            actor_id="actor-reproducer-003", session_id="session-reproducer-003",
        )
        with self.assertRaises(RAEIFindingLifecycleError):
            record_finding_reproduction(
                self.registry, self.verifier, credential,
                finding_id=self.finding_id, finding_version=self.finding_version,
                project_id=self.project_id, project_version=self.project_version,
                request_id=f"request-FINDING_REPRODUCE-{self.finding_id}",
                evidence_root=str(self.evidence_root), artifact_bytes=raw + b" ",
                evidence=evidence,
            )
        self.assertEqual(list_findings(self.registry)[0]["status"], "RESEARCHED")


if __name__ == "__main__":
    unittest.main()
