import base64
import json
import unittest

from raei.api_auth import TokenError, issue_lab_token, verify_bearer_token


SECRET = b"local-test-secret-material-32-bytes-minimum!!"
ISSUER = "raei-lab"
AUDIENCE = "rhemascript-training-api"
ROLES = {"reader", "contributor", "administrator"}


def token(**overrides):
    values = {"subject": "alice", "roles": ["contributor"], "secret": SECRET,
              "issuer": ISSUER, "audience": AUDIENCE, "expires_at": 2000}
    values.update(overrides)
    return issue_lab_token(**values)


class TokenVerificationTests(unittest.TestCase):
    def verify(self, value, now=1000, **kwargs):
        args = {"secret": SECRET, "issuer": ISSUER, "audience": AUDIENCE,
                "allowed_roles": ROLES, "clock": lambda: now}
        args.update(kwargs)
        return verify_bearer_token(value, **args)

    def test_valid_token_produces_authenticated_principal(self):
        principal = self.verify(token())
        self.assertEqual(principal.subject, "alice")
        self.assertEqual(principal.roles, frozenset({"contributor"}))
        self.assertTrue(principal.authenticated)

    def test_expired_token_rejected(self):
        with self.assertRaisesRegex(TokenError, "expired"):
            self.verify(token(expires_at=999))

    def test_future_not_before_rejected(self):
        with self.assertRaisesRegex(TokenError, "not yet valid"):
            self.verify(token(not_before=1100))

    def test_wrong_issuer_and_audience_rejected(self):
        with self.assertRaisesRegex(TokenError, "issuer"):
            self.verify(token(), issuer="other")
        with self.assertRaisesRegex(TokenError, "audience"):
            self.verify(token(), audience="other-api")

    def test_tampered_payload_rejected(self):
        parts = token().split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload["sub"] = "admin"
        parts[1] = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).rstrip(b"=").decode()
        with self.assertRaisesRegex(TokenError, "signature"):
            self.verify(".".join(parts))

    def test_none_and_other_algorithms_rejected(self):
        for alg in ("none", "HS384", "RS256"):
            with self.subTest(alg=alg):
                parts = token().split(".")
                header = base64.urlsafe_b64encode(
                    json.dumps({"alg": alg, "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                parts[0] = header
                with self.assertRaises(TokenError):
                    self.verify(".".join(parts))

    def test_unknown_role_rejected(self):
        with self.assertRaisesRegex(TokenError, "roles"):
            self.verify(token(roles=["superuser"]))

    def test_short_secret_rejected(self):
        with self.assertRaisesRegex(TokenError, "32 bytes"):
            self.verify(token(), secret=b"short")

    def test_malformed_and_oversized_tokens_rejected(self):
        for value in ("x.y", "not-a-token", "a" * 8193):
            with self.subTest(value=value[:12]):
                with self.assertRaises(TokenError):
                    self.verify(value)

    def test_boolean_expiry_is_rejected(self):
        with self.assertRaises(TokenError):
            self.verify(token(expires_at=True))

    def test_duplicate_json_claim_is_rejected(self):
        head = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            b'{"sub":"alice","sub":"mallory","roles":["contributor"],"iss":"raei-lab","aud":"rhemascript-training-api","exp":2000}'
        ).rstrip(b"=").decode()
        import hashlib, hmac
        message = f"{head}.{body}".encode()
        signature = base64.urlsafe_b64encode(hmac.new(SECRET, message, hashlib.sha256).digest()).rstrip(b"=").decode()
        with self.assertRaisesRegex(TokenError, "duplicate"):
            self.verify(f"{head}.{body}.{signature}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
