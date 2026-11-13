import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from raei.findings import RAEIFindingError, capture_finding, list_findings, SCHEMA as FINDING_SCHEMA
from raei.governance import RAEIGovernanceError, record_finding_disposition, record_finding_closure, record_finding_reopening
from raei.knowledge import inherit_closed_finding_as_knowledge, list_knowledge
from raei.finding_lifecycle import (
    RAEIFindingLifecycleError, record_finding_research, record_finding_reproduction, record_finding_plan, record_finding_implementation, record_finding_effectiveness,
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
                    "FINDING_IMPLEMENT": ["implementer"],
                    "FINDING_EFFECTIVENESS_ASSESS": ["assessor"],
                    "FINDING_CLOSURE_REVIEW": ["closure-reviewer"],
                    "FINDING_CLOSURE_CONFIRM": ["closure-approver"],
                    "FINDING_REOPEN_REVIEW": ["reopen-reviewer"],
                    "FINDING_REOPEN_CONFIRM": ["reopen-approver"],
                    "FINDING_SUBMIT": ["submitter"],
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

    def _credential(self, action, evidence, *, subject_id, actor_id, session_id, request_id=None):
        token = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": f"approval-{action.lower()}-{subject_id}",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": actor_id,
            "action": action,
            "project_id": self.project_id,
            "project_version": self.project_version,
            "request_id": request_id or f"request-{action}-{self.finding_id}",
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat(),
            "nonce": f"nonce-{action.lower()}-{subject_id}",
            "key_id": "key-2026-01",
            "artifact_id": evidence.evidence_id,
            "artifact_version": evidence.version,
            "artifact_sha256": evidence.sha256,
            "artifact_size_bytes": evidence.size_bytes,
            "subject_id": subject_id,
            "actor_role": {"FINDING_RESEARCH": "researcher", "FINDING_REPRODUCE": "reproducer", "FINDING_PLAN": "planner", "FINDING_IMPLEMENT": "implementer", "FINDING_EFFECTIVENESS_ASSESS": "assessor", "FINDING_CLOSURE_REVIEW": "closure-reviewer", "FINDING_CLOSURE_CONFIRM": "closure-approver", "FINDING_REOPEN_REVIEW": "reopen-reviewer", "FINDING_REOPEN_CONFIRM": "reopen-approver", "FINDING_SUBMIT": "submitter"}[action],
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

    def _implementation_report(self):
        plan_event = next(
            event for event in self.registry.list_activity_events()
            if event["event_type"] == "FINDING_PLANNED"
            and event["payload"].get("finding_version") == self.finding_version
        )
        return {
            "schema": "raei-finding-implementation-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "plan_event_id": plan_event["event_id"],
            "plan_evidence_binding": plan_event["payload"]["evidence_binding"],
            "implementation_summary": "Applied the approved bounded aspect-ratio correction in the isolated candidate.",
            "changes": ["Changed the ratio mapping and added a focused regression assertion."],
            "test_results": ["Synthetic regression test passed in the isolated test environment."],
            "deviations": [],
            "rollback_reference": "Revert the isolated candidate commit containing the scoped mapping change.",
            "evidence_id": "EV-FND-IMPLEMENTATION-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
        }

    def _record_implementation(self, *, subject_id="subject-implementer-001", session_id="session-implementer-001"):
        report = self._implementation_report()
        raw, evidence = self._write_report("implementation.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_IMPLEMENT", evidence, subject_id=subject_id,
            actor_id="actor-implementer-001", session_id=session_id,
        )
        return record_finding_implementation(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_IMPLEMENT-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )

    def _effectiveness_report(self, outcome="EFFECTIVE"):
        implementation_event = next(
            event for event in self.registry.list_activity_events()
            if event["event_type"] == "FINDING_IMPLEMENTED"
            and event["payload"].get("finding_version") == self.finding_version
        )
        return {
            "schema": "raei-finding-effectiveness-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "implementation_event_id": implementation_event["event_id"],
            "implementation_evidence_binding": implementation_event["payload"]["evidence_binding"],
            "outcome": outcome,
            "criteria_results": ["The requested portrait ratio is preserved in the candidate generation request."],
            "observed_outcomes": ["Synthetic regression test confirms the request remains 9:16."],
            "residual_risks": ["Live provider behavior has not been tested."],
            "evidence_id": "EV-FND-EFFECTIVENESS-001",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
        }

    def _record_effectiveness(self, *, outcome="EFFECTIVE", subject_id="subject-assessor-001", session_id="session-assessor-001"):
        report = self._effectiveness_report(outcome)
        raw, evidence = self._write_report("effectiveness.json", report, report["evidence_id"])
        credential = self._credential(
            "FINDING_EFFECTIVENESS_ASSESS", evidence, subject_id=subject_id,
            actor_id="actor-assessor-001", session_id=session_id,
        )
        return record_finding_effectiveness(
            self.registry, self.verifier, credential,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=f"request-FINDING_EFFECTIVENESS_ASSESS-{self.finding_id}",
            evidence_root=str(self.evidence_root), artifact_bytes=raw, evidence=evidence,
        )

    def _record_closure(self, *, outcome="EFFECTIVE"):
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-CLOSURE-{self.finding_id}"
        credentials = (
            self._credential(
                "FINDING_CLOSURE_REVIEW", evidence,
                subject_id="subject-closure-reviewer-001", actor_id="actor-closure-reviewer-001",
                session_id="session-closure-reviewer-001", request_id=request_id,
            ),
            self._credential(
                "FINDING_CLOSURE_CONFIRM", evidence,
                subject_id="subject-closure-approver-001", actor_id="actor-closure-approver-001",
                session_id="session-closure-approver-001", request_id=request_id,
            ),
        )
        return record_finding_closure(
            self.registry, self.verifier, credentials,
            finding_id=self.finding_id, finding_version=self.finding_version,
            project_id=self.project_id, project_version=self.project_version,
            request_id=request_id, rationale="Independent effectiveness evidence meets all approved acceptance criteria.",
            evidence_root=str(self.evidence_root), evidence=evidence,
        )

    def _record_reopening(self):
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-REOPEN-{self.finding_id}"
        credentials = (
            self._credential(
                "FINDING_REOPEN_REVIEW", evidence,
                subject_id="subject-reopen-reviewer-001", actor_id="actor-reopen-reviewer-001",
                session_id="session-reopen-reviewer-001", request_id=request_id,
            ),
            self._credential(
                "FINDING_REOPEN_CONFIRM", evidence,
                subject_id="subject-reopen-approver-001", actor_id="actor-reopen-approver-001",
                session_id="session-reopen-approver-001", request_id=request_id,
            ),
        )
        return record_finding_reopening(
            self.registry, self.verifier, credentials,
            finding_id=self.finding_id, finding_version=self.finding_version,
            new_finding_version="1.1", project_id=self.project_id,
            project_version=self.project_version, request_id=request_id,
            rationale="New counterexample evidence requires a controlled follow-up version.",
            evidence_root=str(self.evidence_root), evidence=evidence,
        )

    def _capture_resumed_finding(self, *, subject_id="subject-new-submitter-001", session_id="session-new-submitter-001"):
        payload = {
            "schema": FINDING_SCHEMA,
            "finding_id": self.finding_id,
            "version": "1.1",
            "project_id": self.project_id,
            "title": "Portrait clip rendered in landscape — follow-up",
            "raw_observation": "A newly observed counterexample requires renewed research.",
            "affected_workflow": "video_generation",
            "expected_behavior": "Output should remain 9:16 portrait.",
            "observed_behavior": "A new candidate path still emitted landscape output.",
            "impact": "The correction needs a bounded follow-up investigation.",
            "reproduction_steps": ["Repeat the controlled generation request on the revised path."],
            "supporting_evidence": [],
            "evidence_id": "EV-FND-OBS-002",
            "evidence_version": "1.0",
            "created_at_utc": self.now.isoformat(),
            "tags": ["aspect-ratio", "follow-up"],
            "related_work_ids": ["RS-PWW-001"],
            "supersedes": [f"{self.finding_id}@{self.finding_version}"],
        }
        raw, evidence = self._write_report("observation-v1.1.json", payload, payload["evidence_id"])
        request_id = f"request-FINDING-SUBMIT-{self.finding_id}-1.1"
        credential = self._credential(
            "FINDING_SUBMIT", evidence, subject_id=subject_id,
            actor_id=f"actor-{subject_id}", session_id=session_id,
            request_id=request_id,
        )
        return capture_finding(
            self.registry, self.evidence_root, raw, evidence,
            verifier=self.verifier, submitter_credential=credential,
            project_version=self.project_version, request_id=request_id,
        )

    def test_reopening_requires_two_reviewers_and_new_authenticated_version(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        reopened = self._record_reopening()
        self.assertEqual(reopened["decision"], "REOPENED")
        old_finding = next(item for item in list_findings(self.registry) if item["version"] == "1.0")
        self.assertEqual(old_finding["status"], "REOPENED")
        self.assertEqual(old_finding["reopened_as_version"], "1.1")
        resumed = self._capture_resumed_finding()
        self.assertEqual(resumed["version"], "1.1")
        findings = list_findings(self.registry)
        new_finding = next(item for item in findings if item["version"] == "1.1")
        self.assertEqual(new_finding["status"], "SUBMITTED")
        self.assertEqual(new_finding["supersedes"], [f"{self.finding_id}@1.0"])

    def test_reopening_rejects_non_increasing_version_before_consuming_approvals(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-REOPEN-LOW-{self.finding_id}"
        credentials = (
            self._credential("FINDING_REOPEN_REVIEW", evidence, subject_id="subject-reopen-reviewer-low",
                             actor_id="actor-reopen-reviewer-low", session_id="session-reopen-reviewer-low", request_id=request_id),
            self._credential("FINDING_REOPEN_CONFIRM", evidence, subject_id="subject-reopen-approver-low",
                             actor_id="actor-reopen-approver-low", session_id="session-reopen-approver-low", request_id=request_id),
        )
        with self.assertRaisesRegex(RAEIGovernanceError, "numerically greater"):
            record_finding_reopening(
                self.registry, self.verifier, credentials,
                finding_id=self.finding_id, finding_version="1.0", new_finding_version="0.9",
                project_id=self.project_id, project_version=self.project_version,
                request_id=request_id, rationale="Test invalid version progression.",
                evidence_root=str(self.evidence_root), evidence=evidence,
            )
        self.assertFalse(any(event["event_type"] == "FINDING_REOPENED" for event in self.registry.list_activity_events()))

    def test_reopened_version_submitter_cannot_reuse_reopening_reviewer(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        self._record_reopening()
        with self.assertRaisesRegex(RAEIFindingError, "independent from reopening reviewers"):
            self._capture_resumed_finding(
                subject_id="subject-reopen-reviewer-001",
                session_id="session-new-submitter-unique",
            )
        self.assertFalse(any(
            event["event_type"] == "FINDING_CAPTURED"
            and event["payload"].get("version") == "1.1"
            for event in self.registry.list_activity_events()
        ))

    def test_reopening_rejects_same_closure_reviewer(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-REOPEN-{self.finding_id}"
        credentials = (
            self._credential("FINDING_REOPEN_REVIEW", evidence, subject_id="subject-closure-reviewer-001",
                             actor_id="actor-reopen-reviewer-001", session_id="session-new-review-001", request_id=request_id),
            self._credential("FINDING_REOPEN_CONFIRM", evidence, subject_id="subject-reopen-approver-002",
                             actor_id="actor-reopen-approver-002", session_id="session-reopen-approver-002", request_id=request_id),
        )
        with self.assertRaisesRegex(RAEIGovernanceError, "independent from closure reviewers"):
            record_finding_reopening(
                self.registry, self.verifier, credentials,
                finding_id=self.finding_id, finding_version=self.finding_version,
                new_finding_version="1.1", project_id=self.project_id,
                project_version=self.project_version, request_id=request_id,
                rationale="Counterexample requires a new investigation.",
                evidence_root=str(self.evidence_root), evidence=evidence,
            )
        self.assertFalse(any(event["event_type"] == "FINDING_REOPENED" for event in self.registry.list_activity_events()))

    def test_reopening_rejects_two_reviewers_sharing_one_identity_session(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-REOPEN-SHARED-SESSION-{self.finding_id}"
        credentials = (
            self._credential(
                "FINDING_REOPEN_REVIEW", evidence,
                subject_id="subject-reopen-reviewer-shared-001",
                actor_id="actor-reopen-reviewer-shared-001",
                session_id="session-reopen-shared",
                request_id=request_id,
            ),
            self._credential(
                "FINDING_REOPEN_CONFIRM", evidence,
                subject_id="subject-reopen-approver-shared-002",
                actor_id="actor-reopen-approver-shared-002",
                session_id="session-reopen-shared",
                request_id=request_id,
            ),
        )
        with self.assertRaisesRegex(Exception, "distinct authenticated subjects and sessions"):
            record_finding_reopening(
                self.registry, self.verifier, credentials,
                finding_id=self.finding_id, finding_version=self.finding_version,
                new_finding_version="1.1", project_id=self.project_id,
                project_version=self.project_version, request_id=request_id,
                rationale="Reject two reviewers authenticated in one shared session.",
                evidence_root=str(self.evidence_root), evidence=evidence,
            )
        self.assertFalse(any(
            event["event_type"] == "FINDING_REOPENED"
            for event in self.registry.list_activity_events()
        ))

    def test_reopening_approval_replay_does_not_append_a_second_event(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        first = self._record_reopening()
        before = [
            event for event in self.registry.list_activity_events()
            if event["event_type"] == "FINDING_REOPENED"
        ]
        self.assertEqual(len(before), 1)
        with self.assertRaises(Exception):
            self._record_reopening()
        after = [
            event for event in self.registry.list_activity_events()
            if event["event_type"] == "FINDING_REOPENED"
        ]
        self.assertEqual(len(after), 1)
        self.assertEqual(after[0]["event_id"], first["event_id"])
        self.assertTrue(self.registry.verify())

    def test_reopening_rejects_project_version_different_from_prior_closure(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        evidence = verify_artifact(
            self.evidence_root, "effectiveness.json",
            evidence_id="EV-FND-EFFECTIVENESS-001", version="1.0",
        )
        request_id = f"request-FINDING-REOPEN-CROSS-PROJECT-VERSION-{self.finding_id}"
        credentials = []
        for action, subject, actor, session in (
            ("FINDING_REOPEN_REVIEW", "subject-reopen-version-reviewer", "actor-reopen-version-reviewer", "session-reopen-version-reviewer"),
            ("FINDING_REOPEN_CONFIRM", "subject-reopen-version-approver", "actor-reopen-version-approver", "session-reopen-version-approver"),
        ):
            token = self._credential(
                action, evidence, subject_id=subject, actor_id=actor,
                session_id=session, request_id=request_id,
            )
            token["project_version"] = "3.3"
            token.pop("signature")
            token["signature"] = self.private_key.sign(
                json.dumps(token, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hex()
            credentials.append(token)
        with self.assertRaisesRegex(RAEIGovernanceError, "match the exact prior closure scope"):
            record_finding_reopening(
                self.registry, self.verifier, tuple(credentials),
                finding_id=self.finding_id, finding_version=self.finding_version,
                new_finding_version="1.1", project_id=self.project_id,
                project_version="3.3", request_id=request_id,
                rationale="Attempt to reopen a finding under a different project version.",
                evidence_root=str(self.evidence_root), evidence=evidence,
            )
        self.assertFalse(any(
            event["event_type"] == "FINDING_REOPENED"
            for event in self.registry.list_activity_events()
        ))
        self.assertTrue(self.registry.verify())

    def test_registry_rejects_forked_resumed_version_even_with_fresh_v3_approval(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        self._record_reopening()
        self._capture_resumed_finding()
        prior_event = next(
            event for event in self.registry.list_activity_events()
            if event["event_type"] == "FINDING_CAPTURED"
            and event["payload"].get("version") == "1.1"
        )
        second_payload = dict(prior_event["payload"])
        second_payload["version"] = "1.2"
        second_payload["supersedes"] = [f"{self.finding_id}@1.0"]
        raw, evidence = self._write_report(
            "observation-v1.2.json",
            {
                "schema": FINDING_SCHEMA,
                "finding_id": self.finding_id,
                "version": "1.2",
                "project_id": self.project_id,
                "title": "Portrait clip rendered in landscape — fork attempt",
                "raw_observation": "A second branch attempts to supersede the same closed version.",
                "affected_workflow": "video_generation",
                "expected_behavior": "Output should remain 9:16 portrait.",
                "observed_behavior": "A second candidate path still emitted landscape output.",
                "impact": "A competing version branch must be rejected.",
                "reproduction_steps": ["Repeat the controlled generation request."],
                "supporting_evidence": [],
                "evidence_id": "EV-FND-OBS-003",
                "evidence_version": "1.0",
                "created_at_utc": self.now.isoformat(),
                "supersedes": [f"{self.finding_id}@1.0"],
            },
            "EV-FND-OBS-003",
        )
        second_payload["observation_evidence"] = {
            "evidence_id": evidence.evidence_id,
            "relative_path": evidence.relative_path,
            "version": evidence.version,
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
            "description": "Competing resumed finding submission",
        }
        second_payload["evidence_refs"] = [second_payload["observation_evidence"]]
        second_payload["observation_sha256"] = evidence.sha256
        second_payload["identity_authentication_status"] = "UNVERIFIED"
        second_payload.pop("submitter_identity", None)
        second_payload.pop("submitter_authorization", None)
        request_id = f"request-FINDING-SUBMIT-FORK-{self.finding_id}-1.2"
        token = self._credential(
            "FINDING_SUBMIT", evidence, subject_id="subject-fork-submitter",
            actor_id="actor-fork-submitter", session_id="session-fork-submitter",
            request_id=request_id,
        )
        verified = self.verifier.verify_many_and_consume(
            (token,),
            ({
                "action": "FINDING_SUBMIT",
                "project_id": self.project_id,
                "project_version": self.project_version,
                "request_id": request_id,
                "artifact_binding": {
                    "artifact_id": evidence.evidence_id,
                    "artifact_version": evidence.version,
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                },
            },),
        )[0]
        before = len(self.registry.list_activity_events())
        with self.assertRaisesRegex(ValueError, "does not match the exact prior closure and reopening project scope"):
            self.registry.append_authenticated_finding_capture_event(
                f"FINDING:{self.finding_id}@1.2", second_payload,
                project_id=self.project_id, project_version=self.project_version,
                request_id=request_id, approval=verified,
            )
        self.assertEqual(len(self.registry.list_activity_events()), before)
        self.assertTrue(self.registry.verify())

    def test_registry_rejects_resumed_capture_in_another_project(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        self._record_reopening()
        self._capture_resumed_finding()
        raw, evidence = self._write_report(
            "observation-cross-project.json",
            {
                "schema": FINDING_SCHEMA,
                "finding_id": self.finding_id,
                "version": "1.1",
                "project_id": "RS-PWW-OTHER",
                "title": "Cross-project resumed finding attempt",
                "raw_observation": "A finding attempts to cross project boundaries.",
                "affected_workflow": "video_generation",
                "expected_behavior": "Finding remains bound to its source project.",
                "observed_behavior": "Payload attempts to use another project ID.",
                "impact": "Cross-project lineage substitution must be rejected.",
                "reproduction_steps": ["Attempt to reuse the closed finding ID in another project."],
                "supporting_evidence": [],
                "evidence_id": "EV-FND-CROSS-PROJECT",
                "evidence_version": "1.0",
                "created_at_utc": self.now.isoformat(),
                "supersedes": [f"{self.finding_id}@1.0"],
            },
            "EV-FND-CROSS-PROJECT",
        )
        request_id = f"request-FINDING-SUBMIT-CROSS-PROJECT-{self.finding_id}"
        token = self._credential(
            "FINDING_SUBMIT", evidence, subject_id="subject-cross-project-submitter",
            actor_id="actor-cross-project-submitter", session_id="session-cross-project-submitter",
            request_id=request_id,
        )
        token["project_id"] = "RS-PWW-OTHER"
        token.pop("signature")
        token["signature"] = self.private_key.sign(
            json.dumps(token, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hex()
        verified = self.verifier.verify_many_and_consume(
            (token,),
            ({
                "action": "FINDING_SUBMIT",
                "project_id": "RS-PWW-OTHER",
                "project_version": self.project_version,
                "request_id": request_id,
                "artifact_binding": {
                    "artifact_id": evidence.evidence_id,
                    "artifact_version": evidence.version,
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                },
            },),
        )[0]
        payload = {
            "finding_id": self.finding_id,
            "version": "1.1",
            "project_id": "RS-PWW-OTHER",
            "identity_authentication_status": "UNVERIFIED",
            "observation_evidence": {
                "evidence_id": evidence.evidence_id,
                "version": evidence.version,
                "sha256": evidence.sha256,
                "size_bytes": evidence.size_bytes,
            },
            "supersedes": [f"{self.finding_id}@1.0"],
        }
        before = len(self.registry.list_activity_events())
        with self.assertRaisesRegex(ValueError, "exactly one prior closure and reopening in this project"):
            self.registry.append_authenticated_finding_capture_event(
                f"FINDING:{self.finding_id}@1.1", payload,
                project_id="RS-PWW-OTHER", project_version=self.project_version,
                request_id=request_id, approval=verified,
            )
        self.assertEqual(len(self.registry.list_activity_events()), before)
        self.assertTrue(self.registry.verify())

    def _inherit_closed_knowledge(self):
        events = {
            event["event_type"]: event
            for event in self.registry.list_activity_events()
            if event.get("subject_id") == self.finding_id
            and event.get("payload", {}).get("finding_version") == self.finding_version
        }
        plan = events["FINDING_PLANNED"]
        implementation = events["FINDING_IMPLEMENTED"]
        effectiveness = events["FINDING_EFFECTIVENESS_ASSESSED"]
        closure = events.get("FINDING_CLOSED")
        payload = {
            "schema": "raei-knowledge-item-v1",
            "knowledge_id": "RS-KNOW-CLOSED-FINDING-001",
            "version": "1.0",
            "title": "Preserve the approved portrait aspect ratio through generation.",
            "domain": "RhemaScript generation workflow",
            "source_type": "RAEI_CLOSED_FINDING",
            "authority_level": "UNVERIFIED",
            "source_name": "RhemaScript RAEI closed finding",
            "source_version": "1.0",
            "source_reference": f"finding:{self.finding_id}@{self.finding_version}",
            "summary": "A closed, independently assessed finding documented a portrait aspect-ratio propagation correction.",
            "claims": ["The candidate request mapping preserves the selected 9:16 aspect ratio."],
            "limitations": ["Synthetic candidate evidence does not establish live provider behavior."],
            "tags": ["aspect-ratio", "generation", "closed-finding"],
            "evidence_id": "EV-KNOW-CLOSED-FINDING-001",
            "evidence_version": "1.0",
            "status": "PENDING_REVIEW",
            "source_authentication_status": "NOT_CHECKED",
            "claim_relevance_status": "NOT_ASSESSED",
            "created_at_utc": self.now.isoformat(),
            "supersedes": [],
            "source_finding_id": self.finding_id,
            "source_finding_version": self.finding_version,
            "source_lifecycle_lineage": {
                "plan_event_id": plan["event_id"],
                "implementation_event_id": implementation["event_id"],
                "effectiveness_event_id": effectiveness["event_id"],
                "closure_event_id": closure["event_id"] if closure else "MISSING-FINDING-CLOSED-EVENT",
                "plan_evidence_binding": plan["payload"]["evidence_binding"],
                "implementation_evidence_binding": implementation["payload"]["evidence_binding"],
                "effectiveness_evidence_binding": effectiveness["payload"]["evidence_binding"],
            },
            "learning_scope": "The exact prompt-to-generation ratio mapping used by this candidate.",
            "applicability_conditions": ["A project uses the same validated request-construction path."],
            "confidence_level": "Candidate-tested; not live-provider verified.",
            "known_counterexamples": ["Other providers or workflows may apply different aspect-ratio defaults."],
            "review_due_utc": "2026-12-13T00:00:00+00:00",
        }
        raw, evidence = self._write_report("inherited-knowledge.json", payload, payload["evidence_id"])
        return inherit_closed_finding_as_knowledge(self.registry, payload, evidence)

    def test_closed_finding_knowledge_inheritance_remains_pending_review(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        self._record_closure()
        inherited = self._inherit_closed_knowledge()
        self.assertEqual(inherited["knowledge_payload"]["status"], "PENDING_REVIEW")
        item = list_knowledge(self.registry)[0]
        self.assertEqual(item["status"], "PENDING_REVIEW")
        self.assertEqual(item["source_authentication_status"], "NOT_CHECKED")
        self.assertEqual(item["claim_relevance_status"], "NOT_ASSESSED")
        self.assertEqual(item["source_finding_id"], self.finding_id)

    def test_knowledge_inheritance_rejects_unclosed_finding(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        with self.assertRaisesRegex(Exception, "missing or wrong lifecycle events"):
            self._inherit_closed_knowledge()

    def test_closure_requires_effective_assessment_and_projects_closed(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="EFFECTIVE")
        result = self._record_closure()
        self.assertEqual(result["decision"], "CLOSED")
        finding = list_findings(self.registry)[0]
        self.assertEqual(finding["status"], "CLOSED")
        self.assertEqual(finding["closure_event_id"], result["event_id"])

    def test_closure_rejects_ineffective_assessment(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        self._record_effectiveness(outcome="INEFFECTIVE")
        with self.assertRaisesRegex(Exception, "only an EFFECTIVE assessment"):
            self._record_closure()
        self.assertEqual(list_findings(self.registry)[0]["status"], "INEFFECTIVE")
        self.assertFalse(any(
            event["event_type"] == "FINDING_CLOSED"
            for event in self.registry.list_activity_events()
        ))

    def test_effectiveness_binds_exact_implementation_and_projects_outcome(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        implementation = self._record_implementation()
        result = self._record_effectiveness(outcome="EFFECTIVE")
        self.assertEqual(result["status"], "EFFECTIVE")
        finding = list_findings(self.registry)[0]
        self.assertEqual(finding["status"], "EFFECTIVE")
        self.assertEqual(finding["implementation_event_id"], implementation["event_id"])
        self.assertEqual(finding["effectiveness_event_id"], result["event_id"])

    def test_effectiveness_rejects_implementer_reuse(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        self._record_implementation()
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "independent assessor"):
            self._record_effectiveness(subject_id="subject-implementer-001", session_id="session-assessor-new")
        self.assertEqual(list_findings(self.registry)[0]["status"], "IMPLEMENTED")
        self.assertFalse(any(
            event["event_type"] == "FINDING_EFFECTIVENESS_ASSESSED"
            for event in self.registry.list_activity_events()
        ))

    def test_implementation_requires_exact_plan_and_projects_implemented(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        plan = self._record_plan()
        result = self._record_implementation()
        self.assertEqual(result["status"], "IMPLEMENTED")
        finding = list_findings(self.registry)[0]
        self.assertEqual(finding["status"], "IMPLEMENTED")
        self.assertEqual(finding["plan_event_id"], plan["event_id"])
        self.assertEqual(finding["implementation_event_id"], result["event_id"])

    def test_implementation_rejects_planner_reuse(self):
        self._record_research()
        self._record_reproduction()
        self._record_accepted_disposition()
        self._record_plan()
        with self.assertRaisesRegex(RAEIFindingLifecycleError, "independent implementer"):
            self._record_implementation(subject_id="subject-planner-001", session_id="session-implementer-new")
        self.assertEqual(list_findings(self.registry)[0]["status"], "PLANNED")
        self.assertFalse(any(
            event["event_type"] == "FINDING_IMPLEMENTED"
            for event in self.registry.list_activity_events()
        ))

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


    def test_disposition_rejects_unlinked_evidence_even_when_byte_verified(self):
        self._record_research()
        unrelated_payload = {
            "schema": "raei-unrelated-note-v1",
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "note": "This evidence was never captured or submitted as research/reproduction.",
            "created_at_utc": self.now.isoformat(),
        }
        _, unrelated_evidence = self._write_report(
            "unrelated.json", unrelated_payload, "EV-FND-UNRELATED-001",
        )
        credentials = (
            self._v1_disposition_credential("FINDING_DISPOSITION_REVIEW", "reviewer-001", "unrelated-review-001"),
            self._v1_disposition_credential("FINDING_DISPOSITION_CONFIRM", "approver-001", "unrelated-confirm-001"),
        )
        with self.assertRaisesRegex(ValueError, "prior authenticated research/reproduction"):
            record_finding_disposition(
                self.registry, self.verifier, credentials,
                finding_id=self.finding_id, finding_version=self.finding_version,
                project_id=self.project_id, project_version=self.project_version,
                request_id=f"request-FINDING-DISPOSITION-{self.finding_id}",
                disposition="ACCEPTED", rationale="Attempt to cite unrelated evidence.",
                evidence_root=str(self.evidence_root), evidence=unrelated_evidence,
            )
        self.assertFalse(any(
            event["event_type"] == "FINDING_DISPOSITIONED"
            for event in self.registry.list_activity_events()
        ))

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
