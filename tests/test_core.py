import unittest
from rhemascript.core.envelope import validate_record, ContractError
from rhemascript.core.authority import authorise_action, AuthorityError, final_acceptance_allowed
from rhemascript.core.disclosure import disclose, DisclosureError

BASE = {"record_id":"RSN-TEST-0001","record_type":"TEST_RECORD","schema_version":"1.0.0","project_id":"RSN-SYNTHETIC-001","status":"DRAFT","classification":"OPERATIONAL","version":"1.0.0"}

class EnvelopeTests(unittest.TestCase):
    def test_valid_record_passes(self): self.assertEqual(validate_record(BASE.copy())["record_id"],"RSN-TEST-0001")
    def test_missing_required_field_fails(self):
        record=BASE.copy(); del record["project_id"]
        with self.assertRaises(ContractError): validate_record(record)
    def test_invalid_status_fails(self):
        record=BASE.copy(); record["status"]="PUBLISHED_WITHOUT_APPROVAL"
        with self.assertRaises(ContractError): validate_record(record)
    def test_invalid_classification_fails(self):
        record=BASE.copy(); record["classification"]="PUBLIC_EVERYTHING"
        with self.assertRaises(ContractError): validate_record(record)

class AuthorityTests(unittest.TestCase):
    def test_generation_without_authorisation_is_denied(self):
        with self.assertRaises(AuthorityError): authorise_action("GENERATE",{})
    def test_generation_with_explicit_authorisation_passes(self):
        self.assertTrue(authorise_action("GENERATE",{"generation_authorisation":True}))
    def test_publishing_without_separate_authorisation_is_denied(self):
        with self.assertRaises(AuthorityError): authorise_action("PUBLISH",{"human_director_acceptance":True})
    def test_human_director_acceptance_is_required(self):
        self.assertFalse(final_acceptance_allowed(human_director_acceptance=False))
        self.assertTrue(final_acceptance_allowed(human_director_acceptance=True))

class DisclosureTests(unittest.TestCase):
    def test_minimum_necessary_disclosure_passes(self):
        self.assertTrue(disclose(item_classification="CONTROLLED",recipient_clearance="CONTROLLED",task_need=True,approved_scope=True))
    def test_unnecessary_disclosure_is_denied(self):
        with self.assertRaises(DisclosureError): disclose(item_classification="PROTECTED",recipient_clearance="PROTECTED",task_need=False,approved_scope=True)
    def test_insufficient_clearance_is_denied(self):
        with self.assertRaises(DisclosureError): disclose(item_classification="PROTECTED",recipient_clearance="OPERATIONAL",task_need=True,approved_scope=True)

if __name__=="__main__": unittest.main(verbosity=2)
