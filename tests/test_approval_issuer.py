import unittest

from rhemascript.core.approval_issuer import (
    ApprovalCredentialSource, ApprovalScope, required_publish_scopes,
)


class ApprovalIssuerBoundaryTests(unittest.TestCase):
    def test_publish_scopes_require_distinct_actions_and_same_exact_request(self):
        final, publish = required_publish_scopes(
            project_id="RS-PWW-001", project_version="3.2",
            request_id="request-publish-001",
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


if __name__ == "__main__":
    unittest.main()
