import unittest
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rhemascript.core.approvals import ApprovalVerifier, ApprovalError
from rhemascript.core.approval_issuer import (
    AuthenticatedIdentity, DirectoryIdentity, ApprovalPolicyDecision,
    ApprovalIssuerError, TrustedApprovalIssuer,
    ApprovalCredentialSource, ApprovalScope, required_publish_scopes,
    request_publish_approval_credentials,
)


class FakeIdentityAdapter:
    def __init__(self, identity):
        self.identity = identity
    def authenticate(self, scope):
        return self.identity


class FakeDirectoryAdapter:
    def __init__(self, record):
        self.record = record
    def resolve_subject(self, subject_id):
        if self.record.subject_id != subject_id:
            raise LookupError("unknown subject")
        return self.record


class FakePolicyEngine:
    def __init__(self, decision):
        self.decision = decision
    def authorize(self, scope, identity, directory_identity):
        return self.decision


class FakeSigningKeyProvider:
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.calls = []
    def active_key_id(self):
        return "key-2026-01"
    def sign(self, key_id, canonical_payload):
        self.calls.append((key_id, canonical_payload))
        return self.private_key.sign(canonical_payload).hex()


class FakeIssuanceLedger:
    def __init__(self):
        self.entries = []
    def reserve(self, approval_id, nonce, scope, subject_id, identity_session_id):
        if any(row[2].request_id == scope.request_id and row[2].action != scope.action
               and (row[3] == subject_id or row[4] == identity_session_id)
               for row in self.entries):
            return False
        if any(row[0] == approval_id or row[1] == nonce for row in self.entries):
            return False
        self.entries.append((approval_id, nonce, scope, subject_id, identity_session_id))
        return True


class FakeAuditSink:
    def __init__(self, fail=False):
        self.events = []
        self.fail = fail
    def record(self, event):
        if self.fail:
            raise OSError("audit sink unavailable")
        self.events.append(dict(event))


class ApprovalIssuerBoundaryTests(unittest.TestCase):
    def make_trusted_issuer(self, *, identity=None, directory=None, decision=None, audit=None, ledger=None):
        now = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
        identity = identity or AuthenticatedIdentity(
            identity_provider_id="test-idp", subject_id="subject-human-0001",
            authn_context="mfa", authenticated_at=now,
            identity_session_id="session-human-0001",
        )
        directory = directory or DirectoryIdentity(
            subject_id=identity.subject_id, actor_id="directory-actor-0001",
            active=True, roles=frozenset({"director", "publisher"}),
            project_ids=frozenset({"RS-PWW-001"}),
        )
        decision = decision or ApprovalPolicyDecision(
            allowed=True, identity_policy_version="identity-policy-v1",
            identity_provider_id="test-idp", max_authentication_age_seconds=300,
            clock_skew_seconds=30, actor_role="director",
        )
        signer = FakeSigningKeyProvider()
        ledger = ledger or FakeIssuanceLedger()
        audit = audit or FakeAuditSink()
        issuer = TrustedApprovalIssuer(
            issuer_id="trusted-approval-issuer",
            identity_adapter=FakeIdentityAdapter(identity),
            directory_adapter=FakeDirectoryAdapter(directory),
            policy_engine=FakePolicyEngine(decision),
            signing_key_provider=signer,
            issuance_ledger=ledger,
            audit_sink=audit,
            clock=lambda: now,
        )
        return issuer, signer, ledger, audit, now

    def test_synthetic_issuer_emits_verifiable_v3_from_directory_identity(self):
        issuer, signer, ledger, audit, now = self.make_trusted_issuer()
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-001",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        credential = issuer.request_approval(scope)
        self.assertEqual(credential["schema"], "RhemaScript.ApprovalCredential.v3")
        self.assertEqual(credential["actor_id"], "directory-actor-0001")
        self.assertEqual(credential["subject_id"], "subject-human-0001")
        self.assertEqual(credential["identity_provider_id"], "test-idp")
        self.assertEqual(len(ledger.entries), 1)
        self.assertEqual(audit.events[-1]["event"], "approval_issued")
        verifier = ApprovalVerifier(
            issuer="trusted-approval-issuer",
            verification_keys={"key-2026-01": signer.public_key},
            consume_many_once=lambda entries: True,
            clock=lambda: now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {"FINAL_ACCEPTANCE": ["director"], "PUBLISH": ["publisher"]},
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        verified = verifier.verify_many_and_consume(
            (credential,),
            ({
                "action": "FINAL_ACCEPTANCE", "project_id": "RS-PWW-001",
                "project_version": "3.2", "request_id": "request-publish-001",
                "artifact_binding": {
                    "artifact_id": "ART-FINAL-001", "artifact_version": "7",
                    "sha256": "a" * 64, "size_bytes": 987654,
                },
            },),
        )[0]
        self.assertEqual(verified.actor_id, "directory-actor-0001")
        self.assertEqual(verified.artifact_sha256, "a" * 64)

    def test_synthetic_issuer_fails_closed_for_inactive_or_unassigned_approver(self):
        now = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
        identity = AuthenticatedIdentity(
            identity_provider_id="test-idp", subject_id="subject-human-0002",
            authn_context="mfa", authenticated_at=now,
            identity_session_id="session-human-0002",
        )
        directory = DirectoryIdentity(
            subject_id=identity.subject_id, actor_id="directory-actor-0002",
            active=False, roles=frozenset({"director"}),
            project_ids=frozenset({"RS-PWW-001"}),
        )
        issuer, signer, ledger, audit, _ = self.make_trusted_issuer(identity=identity, directory=directory)
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-002",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        with self.assertRaisesRegex(ApprovalIssuerError, "inactive"):
            issuer.request_approval(scope)
        self.assertEqual(signer.calls, [])
        self.assertEqual(ledger.entries, [])
        self.assertEqual(audit.events[-1]["event"], "approval_denied")

        unassigned_directory = DirectoryIdentity(
            subject_id=identity.subject_id, actor_id="directory-actor-0002",
            active=True, roles=frozenset({"director"}),
            project_ids=frozenset({"OTHER-PROJECT"}),
        )
        unassigned_issuer, unassigned_signer, unassigned_ledger, unassigned_audit, _ = self.make_trusted_issuer(
            identity=identity, directory=unassigned_directory,
        )
        with self.assertRaisesRegex(ApprovalIssuerError, "not assigned"):
            unassigned_issuer.request_approval(scope)
        self.assertEqual(unassigned_signer.calls, [])
        self.assertEqual(unassigned_ledger.entries, [])
        self.assertEqual(unassigned_audit.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_rejects_stale_authentication_before_signing(self):
        now = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)
        identity = AuthenticatedIdentity(
            identity_provider_id="test-idp", subject_id="subject-human-0003",
            authn_context="mfa", authenticated_at=now - timedelta(minutes=6),
            identity_session_id="session-human-0003",
        )
        issuer, signer, ledger, audit, _ = self.make_trusted_issuer(identity=identity)
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-003",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        with self.assertRaisesRegex(ApprovalIssuerError, "stale or future-dated"):
            issuer.request_approval(scope)
        self.assertEqual(signer.calls, [])
        self.assertEqual(ledger.entries, [])
        self.assertEqual(audit.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_ledger_rejects_same_human_for_both_actions(self):
        issuer, signer, ledger, audit, _ = self.make_trusted_issuer()
        final, publish = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-004",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )
        issuer.request_approval(final)
        with self.assertRaisesRegex(ApprovalIssuerError, "subject separation"):
            issuer.request_approval(publish)
        self.assertEqual(len(ledger.entries), 1)
        self.assertEqual(audit.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_rejects_policy_provider_and_role_mismatch(self):
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-006",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        cases = (
            (ApprovalPolicyDecision(
                allowed=False, identity_policy_version="identity-policy-v1",
                identity_provider_id="test-idp", max_authentication_age_seconds=300,
                clock_skew_seconds=30,
            ), "policy denied"),
            (ApprovalPolicyDecision(
                allowed=True, identity_policy_version="identity-policy-v1",
                identity_provider_id="other-idp", max_authentication_age_seconds=300,
                clock_skew_seconds=30, actor_role="director",
            ), "provider or directory role"),
            (ApprovalPolicyDecision(
                allowed=True, identity_policy_version="identity-policy-v1",
                identity_provider_id="test-idp", max_authentication_age_seconds=300,
                clock_skew_seconds=30, actor_role="administrator",
            ), "provider or directory role"),
        )
        for decision, message in cases:
            with self.subTest(message=message):
                issuer, signer, ledger, audit, _ = self.make_trusted_issuer(decision=decision)
                with self.assertRaisesRegex(ApprovalIssuerError, message):
                    issuer.request_approval(scope)
                self.assertEqual(signer.calls, [])
                self.assertEqual(ledger.entries, [])
                self.assertEqual(audit.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_fails_closed_when_directory_is_unavailable(self):
        class UnavailableDirectory:
            def resolve_subject(self, subject_id):
                raise ConnectionError("directory unavailable")

        issuer, signer, ledger, audit, now = self.make_trusted_issuer()
        issuer._directory = UnavailableDirectory()
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-007",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        with self.assertRaisesRegex(ApprovalIssuerError, "dependency failed"):
            issuer.request_approval(scope)
        self.assertEqual(signer.calls, [])
        self.assertEqual(ledger.entries, [])
        self.assertEqual(audit.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_ledger_rejects_shared_session_for_different_subjects(self):
        ledger = FakeIssuanceLedger()
        final, publish = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-shared-session",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )
        issuer_one, _, _, _, now = self.make_trusted_issuer(ledger=ledger)
        issuer_one.request_approval(final)
        second_identity = AuthenticatedIdentity(
            identity_provider_id="test-idp", subject_id="subject-human-0002",
            authn_context="mfa", authenticated_at=now,
            identity_session_id="session-human-0001",
        )
        second_directory = DirectoryIdentity(
            subject_id="subject-human-0002", actor_id="directory-actor-0002",
            active=True, roles=frozenset({"publisher"}),
            project_ids=frozenset({"RS-PWW-001"}),
        )
        issuer_two, signer_two, _, audit_two, _ = self.make_trusted_issuer(
            identity=second_identity, directory=second_directory, ledger=ledger,
            decision=ApprovalPolicyDecision(
                allowed=True, identity_policy_version="identity-policy-v1",
                identity_provider_id="test-idp", max_authentication_age_seconds=300,
                clock_skew_seconds=30, actor_role="publisher",
            ),
        )
        with self.assertRaisesRegex(ApprovalIssuerError, "subject separation"):
            issuer_two.request_approval(publish)
        self.assertEqual(len(signer_two.calls), 1)
        self.assertEqual(len(ledger.entries), 1)
        self.assertEqual(audit_two.events[-1]["event"], "approval_denied")

    def test_synthetic_issuer_does_not_return_credential_if_audit_fails(self):
        audit = FakeAuditSink(fail=True)
        issuer, signer, ledger, _, _ = self.make_trusted_issuer(audit=audit)
        scope = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-005",
            artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                              "sha256": "a" * 64, "size_bytes": 987654},
        )[0]
        with self.assertRaisesRegex(ApprovalIssuerError, "dependency failed"):
            issuer.request_approval(scope)
        self.assertEqual(len(ledger.entries), 1)
        self.assertEqual(len(signer.calls), 1)

    def test_publish_scopes_require_distinct_actions_and_same_exact_request(self):
        final, publish = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-001", artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7", "sha256": "a" * 64, "size_bytes": 987654},
        )
        self.assertEqual(final.action, "FINAL_ACCEPTANCE")
        self.assertEqual(publish.action, "PUBLISH")
        self.assertEqual(final.project_id, publish.project_id)
        self.assertEqual(final.project_version, publish.project_version)
        self.assertEqual(final.request_id, publish.request_id)
        self.assertEqual(final.artifact_id, publish.artifact_id)
        self.assertEqual(final.artifact_version, publish.artifact_version)
        self.assertEqual(final.artifact_sha256, publish.artifact_sha256)
        self.assertEqual(final.artifact_size_bytes, publish.artifact_size_bytes)

    def test_scope_rejects_missing_identity_fields(self):
        with self.assertRaisesRegex(ValueError, "request_id"):
            ApprovalScope(
                action="PUBLISH", project_id="RS-PWW-001",
                project_version="3.2", request_id="",
            )

    def test_issuer_protocol_does_not_require_caller_supplied_actor_identity(self):
        class TestIssuer:
            def request_approval(self, scope):
                return {"signed_by_issuer": True, "action": scope.action}

        self.assertIsInstance(TestIssuer(), ApprovalCredentialSource)
        self.assertNotIn("actor_id", ApprovalScope.__dataclass_fields__)


    def test_request_helper_obtains_two_scoped_credentials_without_actor_input(self):
        class TestIssuer:
            def __init__(self):
                self.scopes = []
            def request_approval(self, scope):
                self.scopes.append(scope)
                return {"action": scope.action, "request_id": scope.request_id}

        issuer = TestIssuer()
        final, publish = request_publish_approval_credentials(
            issuer, project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-001", artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7", "sha256": "a" * 64, "size_bytes": 987654},
        )
        self.assertEqual(final["action"], "FINAL_ACCEPTANCE")
        self.assertEqual(publish["action"], "PUBLISH")
        self.assertEqual(len(issuer.scopes), 2)
        self.assertEqual(issuer.scopes[0].request_id, issuer.scopes[1].request_id)

    def test_request_helper_rejects_noncredential_issuer_response(self):
        class InvalidIssuer:
            def request_approval(self, scope):
                return "not-a-credential"

        with self.assertRaisesRegex(TypeError, "credential object"):
            request_publish_approval_credentials(
                InvalidIssuer(), project_id="RS-PWW-001",
                project_version="3.2", request_id="request-publish-001",
                artifact_binding={"artifact_id": "ART-FINAL-001", "artifact_version": "7", "sha256": "a" * 64, "size_bytes": 987654},
            )


if __name__ == "__main__":
    unittest.main()
