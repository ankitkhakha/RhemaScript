import unittest
from rhemascript.capabilities import CapabilityEngine, CapabilityError
from rhemascript.interfaces import InterfaceGateway, InterfaceError
from rhemascript.integration import SyntheticWorkflow
from rhemascript.registry.system_registry import CAPABILITIES, INTERFACES

RECORD={"record_id":"RSN-SYN-001","record_type":"SYNTHETIC_PROJECT","schema_version":"1.0","project_id":"RSN-PRJ-SYN-001","status":"DRAFT","classification":"OPERATIONAL","version":"1.0"}

class CapabilityRuntimeTests(unittest.TestCase):
    def test_all_15_capabilities_are_executable(self):
        engine=CapabilityEngine()
        for cid in CAPABILITIES:
            result=engine.execute(cid,RECORD,actor_role="TEST",evidence={})
            self.assertEqual(result.capability_id,cid); self.assertEqual(result.status,"NOT_ASSESSED"); self.assertTrue(result.missing_evidence)
    def test_unknown_capability_fails_closed(self):
        with self.assertRaises(CapabilityError): CapabilityEngine().execute("CAP-99",RECORD,actor_role="TEST",evidence={})
    def test_invalid_record_rejected(self):
        with self.assertRaises(CapabilityError): CapabilityEngine().execute("CAP-01",{},actor_role="TEST",evidence={})
    def test_complete_evidence_only_ready_for_human_review(self):
        from rhemascript.capabilities.runtime import EVIDENCE_REQUIREMENTS
        ev={"sources":[{"source_id":"S1","reference":"John 1:1","version":"HINOVBSI"}]}
        self.assertEqual(CapabilityEngine().execute("CAP-01",RECORD,actor_role="TEST",evidence=ev).status,"READY_FOR_HUMAN_REVIEW")

class InterfaceRuntimeTests(unittest.TestCase):
    def request(self,op="VALIDATE"): return {"request_id":"req-1","project_id":RECORD["project_id"],"operation":op,"payload":{"x":1},"source_version":"v1"}
    def test_all_18_adapters_registered_and_callable(self):
        gateway=InterfaceGateway(); self.assertEqual(len(gateway.adapters),18)
        for iid in INTERFACES: self.assertEqual(gateway.invoke(iid,self.request()).status,"ACCEPTED_FOR_LOCAL_PROCESSING")
    def test_missing_fields_rejected(self):
        with self.assertRaises(InterfaceError): InterfaceGateway().invoke("IF-01",{})
    def test_protected_data_denied_to_operational_recipient(self):
        req=self.request(); req["classification"]="PROTECTED"
        with self.assertRaises(InterfaceError): InterfaceGateway().invoke("IF-01",req)
    def test_external_write_requires_authority(self):
        with self.assertRaises(InterfaceError): InterfaceGateway().invoke("IF-01",self.request("EXTERNAL_WRITE"))
    def test_idempotent_repeat_returns_same_response(self):
        g=InterfaceGateway(); self.assertEqual(g.invoke("IF-01",self.request()),g.invoke("IF-01",self.request()))
    def test_raei_read_operation_is_acknowledged_not_dispatched_by_generic_gateway(self):
        response = InterfaceGateway().invoke(
            "IF-01",
            self.request("READ_LEARNING_UNIT"),
        )
        self.assertEqual(response.status, "ACCEPTED_FOR_LOCAL_PROCESSING")
        self.assertNotEqual(response.status, "COMPLETED_READ_ONLY")

    def test_unknown_interface_rejected(self):
        with self.assertRaises(InterfaceError): InterfaceGateway().invoke("IF-99",self.request())

class SyntheticE2ETests(unittest.TestCase):
    def test_full_registry_contract_flow(self):
        result=SyntheticWorkflow().run(RECORD,capability_evidence={})
        self.assertEqual(result["capabilities_exercised"],15); self.assertEqual(result["interfaces_exercised"],18)
        self.assertEqual(result["status"],"SYNTHETIC_CONTRACT_FLOW_COMPLETE")
        self.assertTrue(all(x.status=="NOT_ASSESSED" for x in result["capability_results"]))
if __name__=="__main__": unittest.main()
