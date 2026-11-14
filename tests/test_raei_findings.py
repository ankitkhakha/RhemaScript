import json
import os
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rhemascript.core.approvals import ApprovalVerifier

from raei.findings import RAEIFindingError, capture_finding, list_findings, SCHEMA
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
            "reproduction_steps": ["Select portrait 9:16 before each clip request."] if reproduction_steps is None else reproduction_steps,
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
        path = self.evidence_root / f"{payload['finding_id']}.json"
        path.write_bytes(encoded)
        evidence = verify_artifact(
            self.evidence_root, path.name,
            evidence_id=payload["evidence_id"], version=payload["evidence_version"],
        )
        return encoded, evidence

    def signed_submitter_credential(self, payload, evidence, private_key, now):
        token = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": "approval-finding-submit-0001",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": "submitter-0001",
            "action": "FINDING_SUBMIT",
            "project_id": payload["project_id"],
            "project_version": "3.2",
            "request_id": "finding-submit-request-0001",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-finding-submit-0001",
            "key_id": "key-2026-01",
            "artifact_id": evidence.evidence_id,
            "artifact_version": evidence.version,
            "artifact_sha256": evidence.sha256,
            "artifact_size_bytes": evidence.size_bytes,
            "subject_id": "subject-submitter-0001",
            "actor_role": "submitter",
            "authn_context": "mfa",
            "authenticated_at": now.isoformat(),
            "identity_session_id": "session-submitter-0001",
            "identity_policy_version": "identity-policy-v1",
            "identity_provider_id": "test-idp",
        }
        token["signature"] = private_key.sign(
            json.dumps(token, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hex()
        return token

    def make_submitter_verifier(self, private_key, now, consume=None):
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": public_key},
            consume_many_once=consume or (lambda entries: True),
            clock=lambda: now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {"FINDING_SUBMIT": ["submitter"]},
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )

    def test_authenticated_finding_capture_binds_submitter_to_exact_observation(self):
        payload = self.payload("RS-FND-008")
        encoded, evidence = self.write_artifact(payload)
        now = datetime.now(timezone.utc)
        private_key = Ed25519PrivateKey.generate()
        credential = self.signed_submitter_credential(payload, evidence, private_key, now)
        verifier = self.make_submitter_verifier(private_key, now)
        result = capture_finding(
            self.registry, self.evidence_root, encoded, evidence,
            verifier=verifier, submitter_credential=credential,
            project_version="3.2", request_id="finding-submit-request-0001",
        )
        self.assertEqual(result["identity_authentication_status"], "VERIFIED")
        findings = list_findings(self.registry, project_id="RS-PWW-001", evidence_root=self.evidence_root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["identity_authentication_status"], "VERIFIED")
        self.assertEqual(findings[0]["submitter_identity"]["actor_id"], "submitter-0001")
        self.assertEqual(findings[0]["submitter_identity"]["subject_id"], "subject-submitter-0001")
        self.assertEqual(findings[0]["submitter_authorization"]["approval_id"], "approval-finding-submit-0001")
        self.assertTrue(self.registry.verify())

    def test_authenticated_finding_capture_rejects_wrong_artifact_binding(self):
        payload = self.payload("RS-FND-009")
        encoded, evidence = self.write_artifact(payload)
        now = datetime.now(timezone.utc)
        private_key = Ed25519PrivateKey.generate()
        credential = self.signed_submitter_credential(payload, evidence, private_key, now)
        credential["artifact_sha256"] = "f" * 64
        credential["signature"] = private_key.sign(
            json.dumps({k: v for k, v in credential.items() if k != "signature"},
                       sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hex()
        verifier = self.make_submitter_verifier(private_key, now)
        with self.assertRaises(RAEIFindingError):
            capture_finding(
                self.registry, self.evidence_root, encoded, evidence,
                verifier=verifier, submitter_credential=credential,
                project_version="3.2", request_id="finding-submit-request-0001",
            )
        self.assertEqual(list_findings(self.registry, evidence_root=self.evidence_root), [])

    def test_generic_event_append_cannot_forge_authenticated_submitter(self):
        with self.assertRaisesRegex(ValueError, "authenticated finding capture"):
            self.registry.append_activity_event(
                "FINDING:RS-FND-010@1.0", "FINDING_CAPTURED",
                {
                    "finding_id": "RS-FND-010", "version": "1.0",
                    "identity_authentication_status": "VERIFIED",
                    "submitter_identity": {"actor_id": "forged-actor"},
                },
                project_id="RS-PWW-001", subject_id="RS-FND-010",
            )

    def test_capture_preserves_exact_evidence_and_starts_unapproved(self):
        payload = self.payload()
        encoded, evidence = self.write_artifact(payload)
        result = capture_finding(self.registry, self.evidence_root, encoded, evidence)
        self.assertTrue(result["recorded"])
        self.assertEqual(result["status"], "SUBMITTED")
        self.assertEqual(result["suggested_evidence_level"], "E2")
        self.assertEqual(result["identity_authentication_status"], "UNVERIFIED")
        findings = list_findings(self.registry, project_id="RS-PWW-001", evidence_root=self.evidence_root)
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
        encoded = json.dumps(
            changed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        (self.evidence_root / "finding-replay.json").write_bytes(encoded)
        evidence = verify_artifact(
            self.evidence_root, "finding-replay.json",
            evidence_id=changed["evidence_id"], version=changed["evidence_version"],
        )
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


    def test_direct_list_findings_reverifies_retained_evidence_bytes(self):
        payload = self.payload("RS-FND-DIRECT-001")
        encoded, evidence = self.write_artifact(payload)
        capture_finding(self.registry, self.evidence_root, encoded, evidence)
        (self.evidence_root / evidence.relative_path).write_bytes(b"tampered after capture")
        with self.assertRaisesRegex(RAEIFindingError, "integrity verification failed"):
            list_findings(self.registry, evidence_root=self.evidence_root)



if __name__ == "__main__":
    unittest.main()
