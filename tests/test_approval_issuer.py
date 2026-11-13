import unittest

from rhemascript.core.approval_issuer import (
    ApprovalCredentialSource, ApprovalScope, required_publish_scopes,
    request_publish_approval_credentials,
)


class ApprovalIssuerBoundaryTests(unittest.TestCase):
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
