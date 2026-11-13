import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry
from rhemascript.evidence.artifact_verification import EvidenceVersion, verify_artifact
from raei.governance import (
    RAEIGovernanceError, record_finding_disposition, record_knowledge_review,
    list_governed_reviews,
)


class RAEIGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = ReadinessRunRegistry(Path(self.temp.name) / "readiness.sqlite")
        self.evidence_root = Path(self.temp.name) / "evidence"
        self.evidence_root.mkdir()
        (self.evidence_root / "review.txt").write_bytes(b"independent review evidence")
        self.evidence = verify_artifact(
            self.evidence_root, "review.txt",
            evidence_id="EVIDENCE-001", version="1.0",
        )
        self.now = datetime.now(timezone.utc)
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.used = set()

        def consume_once(entries):
            ids = [(item.approval_id, item.nonce) for item in entries]
            if len(set(ids)) != len(ids) or any(item in self.used for item in ids):
                return False
            self.used.update(ids)
            return True

        governed_actions = (
            "FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM",
            "KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM",
        )
        self.verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=consume_once,
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    action: ["reviewer" if action.endswith("_REVIEW") else "approver"]
                    for action in governed_actions
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )

    def credential(self, action, actor, suffix):
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": f"approval-{suffix}",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": actor,
            "action": action,
            "project_id": "RS-PWW-001",
            "project_version": "3.2",
            "request_id": "review-request-0001",
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat(),
            "nonce": f"nonce-{suffix}",
            "key_id": "key-2026-01",
            "artifact_id": self.evidence.evidence_id,
            "artifact_version": self.evidence.version,
            "artifact_sha256": self.evidence.sha256,
            "artifact_size_bytes": self.evidence.size_bytes,
            "subject_id": f"subject-{actor}",
            "actor_role": "reviewer" if action.endswith("_REVIEW") else "approver",
            "authn_context": "mfa",
            "authenticated_at": self.now.isoformat(),
            "identity_session_id": f"session-{suffix}",
            "identity_policy_version": "identity-policy-v1",
            "identity_provider_id": "test-idp",
        }
        payload["signature"] = self.private_key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()
        return payload

    def credentials(self, first_action, second_action, actors=("reviewer-001", "approver-001")):
        return (
            self.credential(first_action, actors[0], "review-0001"),
            self.credential(second_action, actors[1], "approve-0001"),
        )

    def capture_finding(self, finding_id, version="1.0"):
        evidence_ref = {
            "evidence_id": self.evidence.evidence_id,
            "relative_path": self.evidence.relative_path,
            "version": self.evidence.version,
            "sha256": self.evidence.sha256,
            "size_bytes": self.evidence.size_bytes,
            "description": "Finding source evidence",
        }
        self.registry.append_activity_event(
            f"FINDING:{finding_id}@{version}", "FINDING_CAPTURED",
            {"finding_id": finding_id, "version": version,
             "evidence_refs": [evidence_ref]},
            project_id="RS-PWW-001", subject_id=finding_id,
        )

    def register_pending_knowledge(self, knowledge_id, version="0.1"):
        self.registry.record(
            f"KNOWLEDGE:{knowledge_id}:{version}",
            {
                "record_type": "RAEI_KNOWLEDGE_ITEM_V1",
                "knowledge_payload": {
                    "knowledge_id": knowledge_id, "version": version,
                    "status": "PENDING_REVIEW",
                },
                "evidence_binding": {
                    "evidence_id": self.evidence.evidence_id,
                    "evidence_version": self.evidence.version,
                    "evidence_sha256": self.evidence.sha256,
                },
            },
            (self.evidence,), (),
        )

    def test_finding_disposition_requires_two_distinct_signed_actors(self):
        self.capture_finding("RS-FND-001")
        result = record_finding_disposition(
            self.registry, self.verifier,
            self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"),
            finding_id="RS-FND-001", finding_version="1.0",
            project_id="RS-PWW-001", project_version="3.2",
            request_id="review-request-0001", disposition="ACCEPTED",
            rationale="Reproduced and independently confirmed.",
            evidence_root=str(self.evidence_root), evidence=self.evidence,
        )
        self.assertTrue(result["recorded"])
        reviews = list_governed_reviews(
            self.registry, event_type="FINDING_DISPOSITIONED",
            subject_id="RS-FND-001",
            evidence_root=self.evidence_root,
        )
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["payload"]["authorization"]["actor_ids"],
                         ["reviewer-001", "approver-001"])

    def test_knowledge_review_requires_two_distinct_signed_actors(self):
        self.register_pending_knowledge("BWSF-01")
        result = record_knowledge_review(
            self.registry, self.verifier,
            self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
            knowledge_id="BWSF-01", knowledge_version="0.1",
            project_id="RS-PWW-001", project_version="3.2",
            request_id="review-request-0001", decision="APPROVED",
            rationale="Sources and claims independently reviewed.",
            evidence_root=str(self.evidence_root), evidence=self.evidence,
        )
        self.assertTrue(result["recorded"])
        reviews = list_governed_reviews(
            self.registry, event_type="KNOWLEDGE_REVIEWED",
            subject_id="BWSF-01",
            evidence_root=self.evidence_root,
        )
        self.assertEqual(reviews[0]["payload"]["decision"], "APPROVED")

    def test_registry_rejects_signature_verified_but_unconsumed_review_objects(self):
        captured = []
        public_key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=lambda entries: (captured.extend(entries) or False),
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    "FINDING_DISPOSITION_REVIEW": ["reviewer"],
                    "FINDING_DISPOSITION_CONFIRM": ["approver"],
                    "KNOWLEDGE_REVIEW": ["reviewer"],
                    "KNOWLEDGE_CONFIRM": ["approver"],
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        credentials = self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM")
        artifact_binding = {
            "artifact_id": self.evidence.evidence_id,
            "artifact_version": self.evidence.version,
            "sha256": self.evidence.sha256,
            "size_bytes": self.evidence.size_bytes,
        }
        expectations = (
            {"action": "FINDING_DISPOSITION_REVIEW", "project_id": "RS-PWW-001",
             "project_version": "3.2", "request_id": "review-request-0001",
             "artifact_binding": artifact_binding},
            {"action": "FINDING_DISPOSITION_CONFIRM", "project_id": "RS-PWW-001",
             "project_version": "3.2", "request_id": "review-request-0001",
             "artifact_binding": artifact_binding},
        )
        with self.assertRaisesRegex(ApprovalError, "could not be consumed atomically"):
            verifier.verify_many_and_consume(credentials, expectations)
        self.assertEqual(len(captured), 2)
        with self.assertRaisesRegex(ValueError, "verifier-issued, consumed approvals"):
            self.registry.append_governed_activity_event(
                "FINDING_DISPOSITIONED:RS-FND-UNCONSUMED@1.0:req",
                "FINDING_DISPOSITIONED", {},
                project_id="RS-PWW-001", project_version="3.2",
                subject_id="RS-FND-UNCONSUMED", request_id="review-request-0001",
                approvals=tuple(captured),
                expected_actions=("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"),
            )

    def test_generic_append_cannot_forge_governed_review_event(self):
        with self.assertRaisesRegex(ValueError, "append_governed_activity_event"):
            self.registry.append_activity_event(
                "fake-review-001", "KNOWLEDGE_REVIEWED",
                {"knowledge_id": "BWSF-01", "decision": "APPROVED"},
                project_id="RS-PWW-001", subject_id="BWSF-01",
            )

    def test_same_actor_cannot_supply_both_reviews(self):
        self.capture_finding("RS-FND-002")
        with self.assertRaisesRegex(RAEIGovernanceError, "distinct authenticated actors"):
            record_finding_disposition(
                self.registry, self.verifier,
                self.credentials(
                    "FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM",
                    actors=("same-reviewer", "same-reviewer"),
                ),
                finding_id="RS-FND-002", finding_version="1.0",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", disposition="REJECTED",
                rationale="Insufficient evidence.",
                evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(self.used, set())

    def test_wrong_project_scope_is_rejected_without_event(self):
        self.capture_finding("RS-FND-003")
        credentials = (
            self.credential("FINDING_DISPOSITION_REVIEW", "reviewer-001", "review-0002"),
            self.credential("FINDING_DISPOSITION_CONFIRM", "approver-001", "approve-0002"),
        )
        credentials[1]["project_version"] = "3.3"
        # A changed scope invalidates the Ed25519 signature.
        with self.assertRaises(RAEIGovernanceError):
            record_finding_disposition(
                self.registry, self.verifier, credentials,
                finding_id="RS-FND-003", finding_version="1.0",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", disposition="ACCEPTED",
                rationale="Evidence checked.", evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(list_governed_reviews(self.registry, evidence_root=self.evidence_root), [])

    def test_unverified_evidence_object_is_rejected(self):
        self.register_pending_knowledge("BWSF-02")
        with self.assertRaises(RAEIGovernanceError):
            record_knowledge_review(
                self.registry, self.verifier,
                self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
                knowledge_id="BWSF-02", knowledge_version="0.1",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", decision="APPROVED",
                rationale="Review complete.", evidence_root=str(self.evidence_root),
                evidence=EvidenceVersion("EVIDENCE-001", "review.txt", "1.0", "0" * 64, 1),
            )
        self.assertEqual(self.used, set())


    def test_changed_evidence_bytes_are_rejected_before_approval_consumption(self):
        self.register_pending_knowledge("BWSF-03")
        (self.evidence_root / "review.txt").write_bytes(b"tampered evidence")
        with self.assertRaisesRegex(RAEIGovernanceError, "could not be reverified|bytes changed"):
            record_knowledge_review(
                self.registry, self.verifier,
                self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
                knowledge_id="BWSF-03", knowledge_version="0.1",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", decision="APPROVED",
                rationale="Review complete.", evidence_root=str(self.evidence_root),
                evidence=self.evidence,
            )
        self.assertEqual(self.used, set())

    def resign(self, credential):
        payload = {key: value for key, value in credential.items() if key != "signature"}
        credential["signature"] = self.private_key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()
        return credential

    def test_disposition_rejects_same_authenticated_subject_even_with_distinct_actor_ids(self):
        self.capture_finding("RS-FND-SUBJECT")
        credentials = list(self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"))
        credentials[1]["subject_id"] = credentials[0]["subject_id"]
        self.resign(credentials[1])
        with self.assertRaisesRegex(RAEIGovernanceError, "distinct authenticated subjects and sessions"):
            record_finding_disposition(
                self.registry, self.verifier, credentials,
                finding_id="RS-FND-SUBJECT", finding_version="1.0",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", disposition="ACCEPTED",
                rationale="Identity separation adversarial test.",
                evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(list_governed_reviews(self.registry, evidence_root=self.evidence_root), [])

    def test_knowledge_review_rejects_shared_authenticated_session(self):
        self.register_pending_knowledge("BWSF-SHARED-SESSION")
        credentials = list(self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"))
        credentials[1]["identity_session_id"] = credentials[0]["identity_session_id"]
        self.resign(credentials[1])
        with self.assertRaisesRegex(RAEIGovernanceError, "distinct authenticated subjects and sessions"):
            record_knowledge_review(
                self.registry, self.verifier, credentials,
                knowledge_id="BWSF-SHARED-SESSION", knowledge_version="0.1",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", decision="APPROVED",
                rationale="Shared-session adversarial test.",
                evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(list_governed_reviews(self.registry, evidence_root=self.evidence_root), [])

    def test_disposition_rejects_wrong_artifact_binding_before_consumption(self):
        self.capture_finding("RS-FND-WRONG-ARTIFACT")
        credentials = list(self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"))
        credentials[1]["artifact_sha256"] = "f" * 64
        self.resign(credentials[1])
        with self.assertRaisesRegex(RAEIGovernanceError, "binding does not match"):
            record_finding_disposition(
                self.registry, self.verifier, credentials,
                finding_id="RS-FND-WRONG-ARTIFACT", finding_version="1.0",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", disposition="ACCEPTED",
                rationale="Wrong artifact adversarial test.",
                evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(self.used, set())
        self.assertEqual(list_governed_reviews(self.registry, evidence_root=self.evidence_root), [])

    def test_governed_review_rejects_legacy_v1_credentials(self):
        self.capture_finding("RS-FND-LEGACY")
        credentials = list(self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"))
        for item in credentials:
            for field in (
                "artifact_id", "artifact_version", "artifact_sha256", "artifact_size_bytes",
                "subject_id", "actor_role", "authn_context", "authenticated_at",
                "identity_session_id", "identity_policy_version", "identity_provider_id",
            ):
                item.pop(field, None)
            item["schema"] = "RhemaScript.ApprovalCredential.v1"
            self.resign(item)
        with self.assertRaisesRegex(RAEIGovernanceError, "schema v2 or v3"):
            record_finding_disposition(
                self.registry, self.verifier, credentials,
                finding_id="RS-FND-LEGACY", finding_version="1.0",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", disposition="ACCEPTED",
                rationale="Legacy credential rejection test.",
                evidence_root=str(self.evidence_root), evidence=self.evidence,
            )
        self.assertEqual(self.used, set())
        self.assertEqual(list_governed_reviews(self.registry, evidence_root=self.evidence_root), [])

    def test_direct_governed_review_listing_reverifies_retained_evidence_bytes(self):
        self.register_pending_knowledge("BWSF-01")
        result = record_knowledge_review(
            self.registry, self.verifier,
            self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
            knowledge_id="BWSF-01", knowledge_version="0.1",
            project_id="RS-PWW-001", project_version="3.2",
            request_id="review-request-0001", decision="APPROVED",
            rationale="Sources and claims independently reviewed.",
            evidence_root=str(self.evidence_root), evidence=self.evidence,
        )
        self.assertTrue(result["recorded"])
        (self.evidence_root / "review.txt").write_bytes(b"tampered after review")
        with self.assertRaisesRegex(RAEIGovernanceError, "retained evidence integrity verification failed"):
            list_governed_reviews(self.registry, evidence_root=self.evidence_root)



if __name__ == "__main__":
    unittest.main()
