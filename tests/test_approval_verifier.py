import hashlib
import hmac
import json
import unittest
from datetime import datetime, timedelta, timezone

from rhemascript.core.approvals import ApprovalError, ApprovalVerifier


class ApprovalVerifierTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc)
        self.key = b"test-only-signing-key-material-32-bytes-minimum"
        self.used = set()
        self.revoked = set()

        def consume_once(approval_id, nonce, expires_at):
            identity = (approval_id, nonce)
            if identity in self.used or identity in self.revoked or expires_at <= self.now:
                return False
            self.used.add(identity)
            return True

        self.verifier = ApprovalVerifier(
            issuer="RhemaScript-Approval-Service",
            verification_keys={"key-2026-01": self.key},
            consume_once=consume_once,
            clock=lambda: self.now,
        )

    def credential(self, **overrides):
        payload = {
            "schema": "RhemaScript.ApprovalCredential.v1",
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
        payload["signature"] = hmac.new(
            self.key,
            json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode(),
            hashlib.sha256,
        ).hexdigest()
        return payload

    def verify(self, credential):
        return self.verifier.verify_and_consume(
            credential, action="PUBLISH", project_id="RS-PWW-001",
            project_version="3.2", request_id="publish-request-0001",
        )

    def test_accepts_valid_signed_scoped_approval_once(self):
        result = self.verify(self.credential())
        self.assertEqual(result.actor_id, "director-0001")
        self.assertEqual(result.project_id, "RS-PWW-001")
        self.assertEqual(result.action, "PUBLISH")
        self.assertEqual(result.request_id, "publish-request-0001")

    def test_rejects_replay(self):
        token = self.credential()
        self.verify(token)
        with self.assertRaisesRegex(ApprovalError, "already been consumed"):
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
            issued_at=(self.now - timedelta(minutes=6)).isoformat(),
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

    def test_requires_atomic_replay_and_revocation_callback(self):
        with self.assertRaisesRegex(ValueError, "consume_once"):
            ApprovalVerifier(
                issuer="trusted-issuer", verification_keys={"key": self.key},
                consume_once=None,
            )

    def test_rejects_weak_verification_keys(self):
        with self.assertRaisesRegex(ValueError, "32 secret bytes"):
            ApprovalVerifier(
                issuer="trusted-issuer", verification_keys={"key": b"weak"},
                consume_once=lambda *_: True,
            )


if __name__ == "__main__":
    unittest.main()
