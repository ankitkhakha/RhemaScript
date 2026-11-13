import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import unittest
from datetime import datetime, timedelta, timezone

from rhemascript.core.approvals import ApprovalError, ApprovalVerifier, is_verified_approval, is_consumed_verified_approval


class ApprovalVerifierTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc)
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.used = set()
        self.revoked = set()
        self.consume_calls = []

        def consume_many_once(entries):
            self.consume_calls.append(entries)
            identities = [(item.approval_id, item.nonce) for item in entries]
            if (len(set(identities)) != len(identities)
                    or any(identity in self.used or identity in self.revoked
                           for identity in identities)
                    or any(item.expires_at <= self.now for item in entries)):
                return False
            # Atomic test adapter: validate every entry before recording any.
            self.used.update(identities)
            return True

        self.verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": self.key},
            consume_many_once=consume_many_once,
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {
                    "FINAL_ACCEPTANCE": ["director"],
                    "PUBLISH": ["publisher"],
                },
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )

    def credential(self, identity_overrides=None, **overrides):
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v3",
            "approval_id": "approval-0001",
            "issuer": "RhemaScript-Approval-Service",
            "actor_id": "director-0001",
            "action": "PUBLISH",
            "project_id": "RS-PWW-001",
            "project_version": "3.2",
            "request_id": "publish-request-0001",
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-00000001",
            "key_id": "key-2026-01",
        }
        payload.update(overrides)
        if payload["schema"] == "RhemaScript.ApprovalCredential.v3":
            action = payload["action"]
            for name, value in {
                "artifact_id": "ART-FINAL-001",
                "artifact_version": "7",
                "artifact_sha256": "a" * 64,
                "artifact_size_bytes": 987654,
            }.items():
                payload.setdefault(name, value)
            payload.update({
                "subject_id": "subject-" + payload["actor_id"],
                "actor_role": "director" if action == "FINAL_ACCEPTANCE" else "publisher",
                "authn_context": "mfa",
                "authenticated_at": payload["issued_at"],
                "identity_session_id": "session-" + payload["actor_id"],
                "identity_policy_version": "identity-policy-v1",
                "identity_provider_id": "test-idp",
            })
            payload.update(identity_overrides or {})
        payload["signature"] = self.private_key.sign(
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
        ).hex()
        return payload

    def verify(self, credential):
        return self.verifier.verify_many_and_consume(
            (credential,), (self.expectations("PUBLISH"),),
        )[0]

    def expectations(self, action):
        return {"action": action, "project_id": "RS-PWW-001",
                "project_version": "3.2", "request_id": "publish-request-0001",
                "artifact_binding": {"artifact_id": "ART-FINAL-001", "artifact_version": "7",
                                     "sha256": "a" * 64, "size_bytes": 987654}}

    def test_live_key_registry_rejects_verify_only_key_for_new_authorization(self):
        from rhemascript.core.verification_keys import VerificationKeyRecord

        class Registry:
            def resolve_key(inner, key_id, *, issuer, environment):
                return VerificationKeyRecord(
                    key_id=key_id, issuer=issuer, environment=environment,
                    status="VERIFY_ONLY", public_key=self.key,
                    valid_from=self.now - timedelta(days=30),
                    valid_until=None, registry_revision="registry-revision-001",
                    resolved_at=self.now,
                )

        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service", key_registry=Registry(),
            key_registry_environment="production", consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(ApprovalError, "not active"):
            verifier.verify_many_and_consume(
                (self.credential(),), (self.expectations("PUBLISH"),),
            )

    def test_live_key_registry_fails_closed_on_stale_registry_response(self):
        from rhemascript.core.verification_keys import VerificationKeyRecord

        class Registry:
            def resolve_key(inner, key_id, *, issuer, environment):
                return VerificationKeyRecord(
                    key_id=key_id, issuer=issuer, environment=environment,
                    status="ACTIVE", public_key=self.key,
                    valid_from=self.now - timedelta(days=30),
                    valid_until=None, registry_revision="registry-revision-002",
                    resolved_at=self.now - timedelta(minutes=2),
                )

        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service", key_registry=Registry(),
            key_registry_environment="production", consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(ApprovalError, "stale or future-dated"):
            verifier.verify_many_and_consume(
                (self.credential(),), (self.expectations("PUBLISH"),),
            )

    def test_live_key_registry_rejects_revoked_key_for_new_authorization(self):
        from rhemascript.core.verification_keys import VerificationKeyRecord

        class Registry:
            def resolve_key(inner, key_id, *, issuer, environment):
                return VerificationKeyRecord(
                    key_id=key_id, issuer=issuer, environment=environment,
                    status="REVOKED", public_key=self.key,
                    valid_from=self.now - timedelta(days=30),
                    valid_until=None, registry_revision="registry-revision-003",
                    resolved_at=self.now, revoked_at=self.now - timedelta(seconds=1),
                )

        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service", key_registry=Registry(),
            key_registry_environment="production", consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(ApprovalError, "not active"):
            verifier.verify_many_and_consume(
                (self.credential(),), (self.expectations("PUBLISH"),),
            )

    def test_live_key_registry_preserves_historical_signature_audit_for_verify_only_key(self):
        from rhemascript.core.verification_keys import VerificationKeyRecord

        token = self.credential()
        record = {
            "credential_schema": token["schema"],
            **{key: value for key, value in token.items() if key != "schema"},
        }

        class Registry:
            def resolve_key(inner, key_id, *, issuer, environment):
                return VerificationKeyRecord(
                    key_id=key_id, issuer=issuer, environment=environment,
                    status="VERIFY_ONLY", public_key=self.key,
                    valid_from=self.now - timedelta(days=30),
                    valid_until=None, registry_revision="registry-revision-004",
                    resolved_at=self.now,
                )

        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service", key_registry=Registry(),
            key_registry_environment="production", consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        result = verifier.verify_persisted_record(record)
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["issuer_trusted"])
        self.assertEqual(result["key_status_at_verification"], "VERIFY_ONLY")
        self.assertTrue(result["key_trusted_at_issuance"])

    def test_live_key_registry_marks_historical_signature_issued_after_revocation_untrusted(self):
        from rhemascript.core.verification_keys import VerificationKeyRecord

        token = self.credential()
        record = {
            "credential_schema": token["schema"],
            **{key: value for key, value in token.items() if key != "schema"},
        }

        class Registry:
            def resolve_key(inner, key_id, *, issuer, environment):
                return VerificationKeyRecord(
                    key_id=key_id, issuer=issuer, environment=environment,
                    status="REVOKED", public_key=self.key,
                    valid_from=self.now - timedelta(days=30),
                    valid_until=None, registry_revision="registry-revision-005",
                    resolved_at=self.now, revoked_at=self.now - timedelta(seconds=1),
                )

        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service", key_registry=Registry(),
            key_registry_environment="production", consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        result = verifier.verify_persisted_record(record)
        self.assertTrue(result["signature_valid"])
        self.assertFalse(result["issuer_trusted"])
        self.assertEqual(result["key_status_at_verification"], "REVOKED")
        self.assertFalse(result["key_trusted_at_issuance"])

    def test_high_risk_approval_fails_closed_without_identity_policy(self):
        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": self.key},
            consume_many_once=lambda entries: True,
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(ApprovalError, "policy is not configured"):
            verifier.verify_many_and_consume(
                (self.credential(),), (self.expectations("PUBLISH"),),
            )

    def test_identity_policy_is_immutable_after_verifier_construction(self):
        roles = ["publisher"]
        contexts = ["mfa"]
        policy = {
            "provider_id": "test-idp",
            "allowed_roles_by_action": {"PUBLISH": roles},
            "allowed_authn_contexts": contexts,
            "max_authentication_age_seconds": 300,
        }
        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": self.key},
            consume_many_once=lambda entries: True,
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": policy},
        )
        roles[:] = ["administrator"]
        contexts[:] = ["password-only"]
        result = verifier.verify_many_and_consume(
            (self.credential(),), (self.expectations("PUBLISH"),),
        )[0]
        self.assertEqual(result.actor_role, "publisher")
        self.assertEqual(result.authn_context, "mfa")

    def test_rejects_identity_role_escalation(self):
        with self.assertRaisesRegex(ApprovalError, "role or authentication context"):
            self.verify(self.credential(identity_overrides={"actor_role": "administrator"}))

    def test_rejects_identity_provider_mismatch(self):
        with self.assertRaisesRegex(ApprovalError, "identity provider"):
            self.verify(self.credential(identity_overrides={"identity_provider_id": "other-idp"}))

    def test_rejects_authentication_context_downgrade(self):
        with self.assertRaisesRegex(ApprovalError, "role or authentication context"):
            self.verify(self.credential(identity_overrides={"authn_context": "password-only"}))

    def test_rejects_stale_authentication(self):
        stale = (self.now - timedelta(minutes=6)).isoformat()
        with self.assertRaisesRegex(ApprovalError, "stale or future-dated"):
            self.verify(self.credential(identity_overrides={"authenticated_at": stale}))

    def test_rejects_future_authentication(self):
        future = (self.now + timedelta(minutes=2)).isoformat()
        with self.assertRaisesRegex(ApprovalError, "after credential issuance"):
            self.verify(self.credential(identity_overrides={"authenticated_at": future}))

    def test_rejects_authentication_after_credential_issue_time(self):
        later = (self.now + timedelta(seconds=45)).isoformat()
        with self.assertRaisesRegex(ApprovalError, "after credential issuance"):
            self.verify(self.credential(identity_overrides={"authenticated_at": later}))

    def test_rejects_identity_claim_tampering_without_resigning(self):
        token = self.credential()
        token["subject_id"] = "subject-attacker-01"
        with self.assertRaisesRegex(ApprovalError, "signature is invalid"):
            self.verify(token)

    def test_verifier_object_is_not_authorized_until_atomic_consumption_succeeds(self):
        captured = []
        verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": self.key},
            consume_many_once=lambda entries: (captured.extend(entries) or False),
            clock=lambda: self.now,
            identity_policies={"identity-policy-v1": {
                "provider_id": "test-idp",
                "allowed_roles_by_action": {"PUBLISH": ["publisher"]},
                "allowed_authn_contexts": ["mfa"],
                "max_authentication_age_seconds": 300,
            }},
        )
        with self.assertRaisesRegex(ApprovalError, "could not be consumed atomically"):
            verifier.verify_many_and_consume(
                (self.credential(),), (self.expectations("PUBLISH"),),
            )
        self.assertEqual(len(captured), 1)
        self.assertTrue(is_verified_approval(captured[0]))
        self.assertFalse(is_consumed_verified_approval(captured[0]))

    def test_successfully_consumed_approval_has_consumed_capability(self):
        verified = self.verify(self.credential())
        self.assertTrue(is_verified_approval(verified))
        self.assertTrue(is_consumed_verified_approval(verified))

    def test_accepts_valid_signed_scoped_approval_once(self):
        result = self.verify(self.credential())
        self.assertEqual(result.actor_id, "director-0001")
        self.assertEqual(result.project_id, "RS-PWW-001")
        self.assertEqual(result.action, "PUBLISH")
        self.assertEqual(result.request_id, "publish-request-0001")

    def test_rejects_replay(self):
        token = self.credential()
        self.verify(token)
        with self.assertRaisesRegex(ApprovalError, "replayed"):
            self.verify(token)

    def test_rejects_tampered_actor_even_if_signature_is_unchanged(self):
        token = self.credential()
        token["actor_id"] = "other-director"
        with self.assertRaisesRegex(ApprovalError, "signature is invalid"):
            self.verify(token)

    def test_rejects_wrong_action_project_version_and_request(self):
        cases = [
            ({"action": "GENERATE"}, "action or project scope"),
            ({"project_id": "OTHER-PROJECT"}, "action or project scope"),
            ({"project_version": "3.3"}, "version or request scope"),
            ({"request_id": "other-request"}, "version or request scope"),
        ]
        for override, message in cases:
            with self.subTest(override=override):
                with self.assertRaisesRegex(ApprovalError, message):
                    self.verify(self.credential(**override))

    def test_rejects_untrusted_issuer(self):
        with self.assertRaisesRegex(ApprovalError, "issuer is not trusted"):
            self.verify(self.credential(issuer="untrusted-issuer"))

    def test_rejects_expired_approval(self):
        token = self.credential(
            issued_at=(self.now - timedelta(minutes=4)).isoformat(),
            expires_at=(self.now - timedelta(seconds=1)).isoformat(),
        )
        with self.assertRaisesRegex(ApprovalError, "expired"):
            self.verify(token)

    def test_rejects_excessive_lifetime(self):
        token = self.credential(expires_at=(self.now + timedelta(hours=2)).isoformat())
        with self.assertRaisesRegex(ApprovalError, "lifetime exceeds"):
            self.verify(token)

    def test_rejects_future_issued_approval(self):
        token = self.credential(issued_at=(self.now + timedelta(minutes=2)).isoformat())
        with self.assertRaisesRegex(ApprovalError, "future"):
            self.verify(token)

    def test_rejects_revoked_approval(self):
        self.revoked.add(("approval-0001", "nonce-00000001"))
        with self.assertRaisesRegex(ApprovalError, "revoked"):
            self.verify(self.credential())

    def test_rejects_extra_or_missing_fields(self):
        token = self.credential()
        token["extra"] = "not signed"
        with self.assertRaisesRegex(ApprovalError, "invalid shape"):
            self.verify(token)
        token = self.credential()
        del token["actor_id"]
        with self.assertRaisesRegex(ApprovalError, "invalid shape"):
            self.verify(token)

    def test_requires_atomic_batch_consumption_callback(self):
        with self.assertRaisesRegex(ValueError, "consume_many_once"):
            ApprovalVerifier(
                issuer="trusted-issuer", verification_keys={"key": self.key},
                consume_many_once=None,
            )

    def test_rejects_weak_verification_keys(self):
        with self.assertRaisesRegex(ValueError, "32 public-key bytes"):
            ApprovalVerifier(
                issuer="trusted-issuer", verification_keys={"key": b"weak"},
                consume_many_once=lambda *_: True,
            )

    def test_consumes_final_acceptance_and_publish_as_one_atomic_batch(self):
        final = self.credential(
            approval_id="approval-final-0001", nonce="nonce-final-0001",
            action="FINAL_ACCEPTANCE", actor_id="director-0001",
        )
        publish = self.credential(
            approval_id="approval-publish-0001", nonce="nonce-publish-0001",
            action="PUBLISH", actor_id="publisher-0001",
        )
        results = self.verifier.verify_many_and_consume(
            (final, publish),
            (self.expectations("FINAL_ACCEPTANCE"), self.expectations("PUBLISH")),
        )
        self.assertEqual([item.action for item in results],
                         ["FINAL_ACCEPTANCE", "PUBLISH"])
        self.assertNotEqual(results[0].actor_id, results[1].actor_id)
        self.assertEqual(len(self.consume_calls), 1)
        self.assertEqual(len(self.consume_calls[0]), 2)
        self.assertEqual(len(self.used), 2)

    def test_batch_rejects_one_invalid_credential_without_consuming_any(self):
        final = self.credential(
            approval_id="approval-final-0001", nonce="nonce-final-0001",
            action="FINAL_ACCEPTANCE",
        )
        publish = self.credential(
            approval_id="approval-publish-0001", nonce="nonce-publish-0001",
            action="PUBLISH",
        )
        publish["actor_id"] = "tampered-publisher"
        with self.assertRaisesRegex(ApprovalError, "signature is invalid"):
            self.verifier.verify_many_and_consume(
                (final, publish),
                (self.expectations("FINAL_ACCEPTANCE"), self.expectations("PUBLISH")),
            )
        self.assertEqual(self.used, set())
        self.assertEqual(self.consume_calls, [])

    def test_batch_storage_refusal_consumes_neither_approval(self):
        self.revoked.add(("approval-publish-0001", "nonce-publish-0001"))
        final = self.credential(
            approval_id="approval-final-0001", nonce="nonce-final-0001",
            action="FINAL_ACCEPTANCE",
        )
        publish = self.credential(
            approval_id="approval-publish-0001", nonce="nonce-publish-0001",
            action="PUBLISH", actor_id="publisher-0001",
        )
        with self.assertRaisesRegex(ApprovalError, "batch is revoked"):
            self.verifier.verify_many_and_consume(
                (final, publish),
                (self.expectations("FINAL_ACCEPTANCE"), self.expectations("PUBLISH")),
            )
        self.assertEqual(self.used, set())

    def test_batch_requires_distinct_actors_by_default(self):
        final = self.credential(
            approval_id="approval-final-same-actor", nonce="nonce-final-same-actor",
            action="FINAL_ACCEPTANCE", actor_id="same-director",
        )
        publish = self.credential(
            approval_id="approval-publish-same-actor", nonce="nonce-publish-same-actor",
            action="PUBLISH", actor_id="same-director",
        )
        with self.assertRaisesRegex(ApprovalError, "distinct authenticated actors"):
            self.verifier.verify_many_and_consume(
                (final, publish),
                (self.expectations("FINAL_ACCEPTANCE"), self.expectations("PUBLISH")),
            )
        self.assertEqual(self.used, set())

    def test_batch_rejects_duplicate_ids_or_nonces(self):
        token = self.credential()
        with self.assertRaisesRegex(ApprovalError, "duplicate IDs or nonces"):
            self.verifier.verify_many_and_consume(
                (token, token),
                (self.expectations("PUBLISH"), self.expectations("PUBLISH")),
            )
        self.assertEqual(self.consume_calls, [])



    def artifact_binding(self):
        return {
            "artifact_id": "ART-FINAL-001",
            "artifact_version": "7",
            "sha256": "a" * 64,
            "size_bytes": 987654,
        }

    def v2_expectation(self, action="PUBLISH"):
        return {**self.expectations(action), "artifact_binding": self.artifact_binding()}

    def test_accepts_v2_approval_bound_to_exact_final_film_bytes(self):
        binding = self.artifact_binding()
        token = self.credential(
            schema="RhemaScript.ApprovalCredential.v3",
            artifact_id=binding["artifact_id"],
            artifact_version=binding["artifact_version"],
            artifact_sha256=binding["sha256"],
            artifact_size_bytes=binding["size_bytes"],
        )
        verified = self.verifier.verify_many_and_consume(
            (token,), (self.v2_expectation(),),
        )[0]
        self.assertEqual(verified.artifact_id, binding["artifact_id"])
        self.assertEqual(verified.artifact_version, binding["artifact_version"])
        self.assertEqual(verified.artifact_sha256, binding["sha256"])
        self.assertEqual(verified.artifact_size_bytes, binding["size_bytes"])

    def test_rejects_v2_approval_for_different_artifact_digest(self):
        binding = self.artifact_binding()
        token = self.credential(
            schema="RhemaScript.ApprovalCredential.v3",
            artifact_id=binding["artifact_id"],
            artifact_version=binding["artifact_version"],
            artifact_sha256="b" * 64,
            artifact_size_bytes=binding["size_bytes"],
        )
        with self.assertRaisesRegex(ApprovalError, "binding does not match"):
            self.verifier.verify_many_and_consume((token,), (self.v2_expectation(),))
        self.assertEqual(self.used, set())

    def test_rejects_v2_approval_for_different_artifact_version_or_size(self):
        binding = self.artifact_binding()
        for index, overrides in enumerate((
            {"artifact_version": "8", "artifact_size_bytes": binding["size_bytes"]},
            {"artifact_version": binding["artifact_version"], "artifact_size_bytes": binding["size_bytes"] + 1},
        )):
            token = self.credential(
                schema="RhemaScript.ApprovalCredential.v3",
                artifact_id=binding["artifact_id"],
                artifact_version=overrides["artifact_version"],
                artifact_sha256=binding["sha256"],
                artifact_size_bytes=overrides["artifact_size_bytes"],
                approval_id=f"approval-version-{index}",
                nonce=f"nonce-version-{index}",
            )
            with self.assertRaisesRegex(ApprovalError, "binding does not match"):
                self.verifier.verify_many_and_consume((token,), (self.v2_expectation(),))
        self.assertEqual(self.used, set())

    def test_rejects_v3_credential_without_exact_artifact_expectation(self):
        binding = self.artifact_binding()
        token = self.credential(
            schema="RhemaScript.ApprovalCredential.v3",
            artifact_id=binding["artifact_id"],
            artifact_version=binding["artifact_version"],
            artifact_sha256=binding["sha256"],
            artifact_size_bytes=binding["size_bytes"],
        )
        with self.assertRaisesRegex(ApprovalError, "exact artifact expectation"):
            self.verifier.verify_many_and_consume(
                (token,),
                ({"action": "PUBLISH", "project_id": "RS-PWW-001",
                  "project_version": "3.2", "request_id": "publish-request-0001"},),
            )

    def test_rejects_legacy_v1_credential_when_artifact_binding_is_required(self):
        with self.assertRaisesRegex(ApprovalError, "schema v2 or v3"):
            self.verifier.verify_many_and_consume(
                (self.credential(schema="RhemaScript.ApprovalCredential.v1"),), (self.v2_expectation(),),
            )

if __name__ == "__main__":
    unittest.main()
