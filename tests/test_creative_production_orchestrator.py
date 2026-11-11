import unittest

from rhemascript.capabilities.runtime import CapabilityResult
from rhemascript.orchestration import CreativeProductionOrchestrator, OrchestrationError
from rhemascript.registry.system_registry import REQUIRED_GATES

PROJECT = {
    "record_id":"RSN-ORCH-001",
    "record_type":"SYNTHETIC_PROJECT",
    "schema_version":"1.0",
    "project_id":"RSN-ORCH-PROJECT-001",
    "status":"DRAFT",
    "classification":"OPERATIONAL",
    "version":"1.0",
}

class ReadyStubEngine:
    """Test double only; it never performs provider or production actions."""
    def execute(self, capability_id, record, *, actor_role, evidence, authority=None):
        return CapabilityResult(
            capability_id=capability_id,
            project_id=record["project_id"],
            status="READY_FOR_HUMAN_REVIEW",
            outputs={"specialist_assessment":{"synthetic":True}},
            missing_evidence=(),
        )

def approved_gates(project_id):
    return [
        {
            "project_id":project_id,
            "gate":gate,
            "decision":"APPROVED",
            "actor_id":f"HUMAN-DIRECTOR-{index}",
            "evidence_ref":f"approval-evidence:{index}",
        }
        for index,gate in enumerate(REQUIRED_GATES, start=1)
    ]

class CreativeProductionOrchestratorTests(unittest.TestCase):
    def test_missing_source_evidence_blocks_dependent_capabilities_with_exact_reason(self):
        result=CreativeProductionOrchestrator().run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS"
        )
        self.assertEqual(result.capability_results["CAP-01"]["status"],"NOT_ASSESSED")
        self.assertEqual(result.capability_results["CAP-01"]["missing_evidence"],["sources"])
        self.assertEqual(result.capability_results["CAP-02"]["status"],"BLOCKED_DEPENDENCY")
        self.assertEqual(result.capability_results["CAP-02"]["missing_dependencies"],["CAP-01"])
        self.assertFalse(result.generation_preconditions_met)
        self.assertFalse(result.generation_action_performed)
        self.assertFalse(result.external_action_performed)
        self.assertFalse(result.publishing_performed)

    def test_capability_order_is_dependency_safe_and_auditable(self):
        result=CreativeProductionOrchestrator(ReadyStubEngine()).run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS",
            run_id="ORCH-RUN-001"
        )
        positions={row["capability_id"]:i for i,row in enumerate(result.audit_trace)}
        self.assertLess(positions["CAP-12"],positions["CAP-09"])
        self.assertLess(positions["CAP-13"],positions["CAP-10"])
        self.assertLess(positions["CAP-10"],positions["CAP-08"])
        self.assertLess(positions["CAP-08"],positions["CAP-11"])
        self.assertEqual(result.audit_trace[0]["run_id"],"ORCH-RUN-001")
        self.assertEqual(result.status,"ASSESSMENTS_READY_FOR_HUMAN_REVIEW")
        self.assertEqual(result.capability_results["CAP-06"]["status"],"NOT_ASSESSED_OPTIONAL")
        self.assertFalse(result.generation_action_performed)

    def test_out_of_order_gate_is_blocked_and_never_authorises_generation(self):
        records=approved_gates(PROJECT["project_id"])
        records[0],records[1]=records[1],records[0]
        result=CreativeProductionOrchestrator(ReadyStubEngine()).run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS",
            gate_records=records, generation_authorisation=True
        )
        self.assertEqual(result.gate_status["gate_status"],"BLOCKED")
        self.assertFalse(result.generation_preconditions_met)
        self.assertEqual(result.status,"GOVERNANCE_BLOCKED")
        self.assertFalse(result.generation_action_performed)

    def test_all_six_gates_and_separate_authorisation_only_satisfy_preconditions(self):
        result=CreativeProductionOrchestrator(ReadyStubEngine()).run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS",
            gate_records=approved_gates(PROJECT["project_id"]),
            generation_authorisation=True
        )
        self.assertTrue(result.gate_status["all_gates_approved"])
        self.assertTrue(result.generation_preconditions_met)
        self.assertFalse(result.generation_action_performed)
        self.assertFalse(result.external_action_performed)
        self.assertFalse(result.publishing_performed)

    def test_wrong_project_gate_record_is_rejected(self):
        records=approved_gates(PROJECT["project_id"])
        records[0]["project_id"]="A-DIFFERENT-PROJECT"
        result=CreativeProductionOrchestrator(ReadyStubEngine()).run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS",
            gate_records=records, generation_authorisation=True
        )
        self.assertEqual(result.gate_status["gate_status"],"BLOCKED")
        self.assertFalse(result.generation_preconditions_met)

    def test_invalid_evidence_container_fails_closed(self):
        evidence={"CAP-01":"not-an-object"}
        with self.assertRaises(OrchestrationError):
            CreativeProductionOrchestrator().run(
                PROJECT, capability_evidence=evidence, actor_role="TEST_HARNESS"
            )

if __name__=="__main__":
    unittest.main()
