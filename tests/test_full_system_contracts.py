import unittest
from rhemascript.registry.system_registry import CAPABILITIES, INTERFACES, REQUIRED_GATES, SEPARATE_AUTHORITIES
from rhemascript.core.envelope import validate_record
from rhemascript.core.authority import authorise_action, AuthorityError
from rhemascript.core.disclosure import disclose, DisclosureError

class FullSystemRegistryTests(unittest.TestCase):
    def test_all_15_capability_ids_are_registered(self): self.assertEqual(set(CAPABILITIES),{f"CAP-{i:02d}" for i in range(1,16)})
    def test_every_capability_has_a_nonempty_name(self): self.assertEqual(len(CAPABILITIES),15); self.assertTrue(all(isinstance(v,str) and v.strip() for v in CAPABILITIES.values()))
    def test_all_18_interface_ids_are_registered(self): self.assertEqual(set(INTERFACES),{f"IF-{i:02d}" for i in range(1,19)})
    def test_six_approval_gates_are_preserved(self): self.assertEqual(set(REQUIRED_GATES),{"PROJECT_CREATIVE_DIRECTION","SCRIPT_BIBLICAL_ACCURACY","VISUAL_DEVELOPMENT","PRODUCTION_PLAN_PROMPT","GENERATION_AUTHORISATION","FINAL_FILM"})
    def test_four_authority_states_remain_distinct(self): self.assertEqual(set(SEPARATE_AUTHORITIES),{"APPROVAL","EXECUTION_AUTHORISATION","FINAL_ACCEPTANCE","PUBLISHING_AUTHORISATION"})

class CrossCuttingContractTests(unittest.TestCase):
    def test_valid_synthetic_records_are_accepted(self):
        for i in range(1,16):
            record={"record_id":f"RSN-CAP-{i:02d}-SYN","record_type":"CAPABILITY_CONTRACT","schema_version":"1.0.0","project_id":"RSN-SYNTHETIC-FULL-CI","status":"DRAFT","classification":"OPERATIONAL","version":"1.0.0"}
            self.assertIs(validate_record(record),record)
    def test_protected_records_cannot_be_disclosed_without_need(self):
        with self.assertRaises(DisclosureError): disclose(item_classification="PROTECTED",recipient_clearance="PROTECTED",task_need=False,approved_scope=True)
    def test_unapproved_external_write_is_denied(self):
        with self.assertRaises(AuthorityError): authorise_action("EXTERNAL_WRITE",{})
    def test_unapproved_spending_is_denied(self):
        with self.assertRaises(AuthorityError): authorise_action("SPEND",{})
    def test_unknown_consequential_action_fails_closed(self):
        with self.assertRaises(AuthorityError): authorise_action("UNRECOGNISED_ACTION",{})

if __name__=="__main__": unittest.main(verbosity=2)
