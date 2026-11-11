import unittest
from rhemascript.core.gates import GateDecision, GateError, GateRecord, ProjectGateState, authorise_generation
from rhemascript.registry.system_registry import REQUIRED_GATES

class ProjectGateTests(unittest.TestCase):
    def approved_state(self):
        state=ProjectGateState("RSN-SYNTHETIC-GATE-001")
        for index,gate in enumerate(REQUIRED_GATES,start=1):
            state=state.record(GateRecord(state.project_id,gate,GateDecision.APPROVED,f"ROLE-SYNTHETIC-{index}",f"RSN-EVD-SYN-{index:02d}"))
        return state
    def test_project_starts_at_first_gate(self):
        state=ProjectGateState("RSN-SYNTHETIC-GATE-001"); self.assertEqual(state.next_gate,REQUIRED_GATES[0]); self.assertFalse(state.all_gates_approved)
    def test_approved_gates_progress_in_order(self):
        self.assertTrue(self.approved_state().all_gates_approved)
    def test_out_of_order_gate_is_denied(self):
        with self.assertRaises(GateError): ProjectGateState("P-1").record(GateRecord("P-1",REQUIRED_GATES[1],GateDecision.APPROVED,"R-1","E-1"))
    def test_rejected_gate_blocks_progression(self):
        with self.assertRaises(GateError): ProjectGateState("P-1").record(GateRecord("P-1",REQUIRED_GATES[0],GateDecision.REJECTED,"R-1","E-1"))
    def test_project_mismatch_is_denied(self):
        with self.assertRaises(GateError): ProjectGateState("P-1").record(GateRecord("P-2",REQUIRED_GATES[0],GateDecision.APPROVED,"R-1","E-1"))
    def test_empty_evidence_reference_is_denied(self):
        with self.assertRaises(GateError): GateRecord("P-1",REQUIRED_GATES[0],GateDecision.APPROVED,"R-1"," ")
    def test_generation_requires_all_gates(self):
        with self.assertRaises(GateError): authorise_generation(generation_authorisation=True,gate_state=ProjectGateState("P-1"))
    def test_generation_requires_separate_execution_authorisation(self):
        with self.assertRaises(GateError): authorise_generation(generation_authorisation=False,gate_state=self.approved_state())
    def test_all_gates_plus_separate_authorisation_pass(self):
        self.assertTrue(authorise_generation(generation_authorisation=True,gate_state=self.approved_state()))
    def test_cannot_record_more_than_six_gates(self):
        state=self.approved_state()
        with self.assertRaises(GateError): state.record(GateRecord(state.project_id,REQUIRED_GATES[-1],GateDecision.APPROVED,"ROLE-EXTRA","EVIDENCE-EXTRA"))

if __name__=="__main__": unittest.main(verbosity=2)
