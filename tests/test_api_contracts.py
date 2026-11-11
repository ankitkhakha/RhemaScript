import unittest

from raei.api_contracts import (
    AuthorizationError, Policy, Principal, RequestError, Rule,
    validate_assessment_payload, validate_unit_payload,
)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy((
            Rule("learner", "read", "curriculum"),
            Rule("assessor", "assess", "learning_record"),
            Rule("admin", "manage", "policy"),
        ))

    def test_exact_grant_permits(self):
        self.assertTrue(self.policy.permits(Principal("u1", frozenset({"learner"})),
                                            "read", "curriculum"))

    def test_unknown_role_is_denied(self):
        self.assertFalse(self.policy.permits(Principal("u2", frozenset({"visitor"})),
                                             "read", "curriculum"))

    def test_missing_or_unauthenticated_principal_is_denied(self):
        self.assertFalse(self.policy.permits(None, "read", "curriculum"))
        self.assertFalse(self.policy.permits(Principal("u1", frozenset({"learner"}), False),
                                             "read", "curriculum"))

    def test_role_cannot_cross_resource_or_action(self):
        principal = Principal("u1", frozenset({"learner"}))
        with self.assertRaises(AuthorizationError):
            self.policy.require(principal, "delete", "learning_record")

    def test_no_implicit_admin_or_wildcard_privileges(self):
        principal = Principal("u1", frozenset({"admin"}))
        self.assertFalse(self.policy.permits(principal, "delete", "learning_record"))


class RequestValidationTests(unittest.TestCase):
    def test_valid_unit_payload_is_normalised_without_mutating_input(self):
        source = {"unit_id": "ENG-01", "title": "  Data structures  ",
                  "prerequisites": ["ENG-00"]}
        result = validate_unit_payload(source)
        self.assertEqual(result["title"], "Data structures")
        self.assertEqual(source["title"], "  Data structures  ")

    def test_unit_rejects_unknown_fields(self):
        with self.assertRaises(RequestError):
            validate_unit_payload({"unit_id": "ENG-01", "title": "X", "is_admin": True})

    def test_unit_rejects_self_dependency_and_duplicate_prerequisites(self):
        with self.assertRaises(RequestError):
            validate_unit_payload({"unit_id": "ENG-01", "title": "X",
                                   "prerequisites": ["ENG-01"]})
        with self.assertRaises(RequestError):
            validate_unit_payload({"unit_id": "ENG-01", "title": "X",
                                   "prerequisites": ["ENG-02", "ENG-02"]})

    def test_unit_rejects_wrong_types_and_oversized_values(self):
        with self.assertRaises(RequestError):
            validate_unit_payload([])
        with self.assertRaises(RequestError):
            validate_unit_payload({"unit_id": "ENG-01", "title": "X" * 161})

    def test_valid_assessment_payload(self):
        result = validate_assessment_payload({
            "score": 3, "evidence_ref": "tests/test_api_contracts.py",
            "evidence_status": "verified", "expected_version": 1,
        })
        self.assertEqual(result["score"], 3)

    def test_boolean_score_and_version_are_rejected(self):
        valid = {"score": True, "evidence_ref": "x",
                 "evidence_status": "verified", "expected_version": 1}
        with self.assertRaises(RequestError):
            validate_assessment_payload(valid)
        valid["score"] = 3
        valid["expected_version"] = True
        with self.assertRaises(RequestError):
            validate_assessment_payload(valid)

    def test_verified_evidence_requires_reference(self):
        with self.assertRaises(RequestError):
            validate_assessment_payload({"score": 4, "evidence_ref": "",
                "evidence_status": "verified", "expected_version": 1})

    def test_unknown_assessment_fields_are_rejected(self):
        with self.assertRaises(RequestError):
            validate_assessment_payload({"score": 3, "evidence_ref": "x",
                "evidence_status": "verified", "expected_version": 1, "role": "admin"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
