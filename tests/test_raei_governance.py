import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rhemascript.core.approvals import ApprovalVerifier
from rhemascript.evidence.readiness_registry import ReadinessRunRegistry
from raei.governance import (
    RAEIGovernanceError, record_finding_disposition, record_knowledge_review,
    list_governed_reviews,
)


class RAEIGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = ReadinessRunRegistry(Path(self.temp.name) / "readiness.sqlite")
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

        self.verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=consume_once,
            clock=lambda: self.now,
        )

    def credential(self, action, actor, suffix):
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v1",
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

    def binding(self):
        return {
            "evidence_id": "EVIDENCE-001",
            "evidence_version": "1.0",
            "sha256": "a" * 64,
            "size_bytes": 128,
        }

    def test_finding_disposition_requires_two_distinct_signed_actors(self):
        result = record_finding_disposition(
            self.registry, self.verifier,
            self.credentials("FINDING_DISPOSITION_REVIEW", "FINDING_DISPOSITION_CONFIRM"),
            finding_id="RS-FND-001", finding_version="1.0",
            project_id="RS-PWW-001", project_version="3.2",
            request_id="review-request-0001", disposition="ACCEPTED",
            rationale="Reproduced and independently confirmed.",
            evidence_binding=self.binding(),
        )
        self.assertTrue(result["recorded"])
        reviews = list_governed_reviews(
            self.registry, event_type="FINDING_DISPOSITIONED",
            subject_id="RS-FND-001",
        )
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["payload"]["authorization"]["actor_ids"],
                         ["reviewer-001", "approver-001"])

    def test_knowledge_review_requires_two_distinct_signed_actors(self):
        result = record_knowledge_review(
            self.registry, self.verifier,
            self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
            knowledge_id="BWSF-01", knowledge_version="0.1",
            project_id="RS-PWW-001", project_version="3.2",
            request_id="review-request-0001", decision="APPROVED",
            rationale="Sources and claims independently reviewed.",
            evidence_binding=self.binding(),
        )
        self.assertTrue(result["recorded"])
        reviews = list_governed_reviews(
            self.registry, event_type="KNOWLEDGE_REVIEWED",
            subject_id="BWSF-01",
        )
        self.assertEqual(reviews[0]["payload"]["decision"], "APPROVED")

    def test_generic_append_cannot_forge_governed_review_event(self):
        with self.assertRaisesRegex(ValueError, "append_governed_activity_event"):
            self.registry.append_activity_event(
                "fake-review-001", "KNOWLEDGE_REVIEWED",
                {"knowledge_id": "BWSF-01", "decision": "APPROVED"},
                project_id="RS-PWW-001", subject_id="BWSF-01",
            )

    def test_same_actor_cannot_supply_both_reviews(self):
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
                evidence_binding=self.binding(),
            )
        self.assertEqual(self.used, set())

    def test_wrong_project_scope_is_rejected_without_event(self):
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
                rationale="Evidence checked.", evidence_binding=self.binding(),
            )
        self.assertEqual(list_governed_reviews(self.registry), [])

    def test_missing_exact_evidence_binding_is_rejected(self):
        with self.assertRaises(RAEIGovernanceError):
            record_knowledge_review(
                self.registry, self.verifier,
                self.credentials("KNOWLEDGE_REVIEW", "KNOWLEDGE_CONFIRM"),
                knowledge_id="BWSF-02", knowledge_version="0.1",
                project_id="RS-PWW-001", project_version="3.2",
                request_id="review-request-0001", decision="APPROVED",
                rationale="Review complete.", evidence_binding={},
            )
        self.assertEqual(self.used, set())


if __name__ == "__main__":
    unittest.main()
