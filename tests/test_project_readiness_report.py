import unittest

from rhemascript.capabilities.runtime import CapabilityResult
from rhemascript.orchestration import CreativeProductionOrchestrator
from rhemascript.registry.system_registry import REQUIRED_GATES
from rhemascript.reports import build_readiness_report

PROJECT = {
    "record_id": "RS-REPORT-001",
    "record_type": "SYNTHETIC_PROJECT",
    "schema_version": "1.0",
    "project_id": "RS-REPORT-PROJECT-001",
    "status": "DRAFT",
    "classification": "OPERATIONAL",
    "version": "1.0",
}

class ReadyEngine:
    def execute(self, capability_id, record, *, actor_role, evidence, authority=None):
        return CapabilityResult(
            capability_id=capability_id, project_id=record["project_id"],
            status="READY_FOR_HUMAN_REVIEW", outputs={"synthetic": True},
            missing_evidence=(),
        )

def approved_gates():
    return [{
        "project_id": PROJECT["project_id"], "gate": gate, "decision": "APPROVED",
        "actor_id": f"SYNTHETIC-{i}", "evidence_ref": f"fixture:{i}",
    } for i, gate in enumerate(REQUIRED_GATES, 1)]

class ReadinessReportTests(unittest.TestCase):
    def test_missing_evidence_report_names_blockers_and_next_gate(self):
        result = CreativeProductionOrchestrator().run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS"
        )
        report = build_readiness_report(result)
        self.assertEqual(report["project_id"], PROJECT["project_id"])
        self.assertTrue(any(
            item["capability_id"] == "CAP-01" and item["missing_evidence"] == ["sources"]
            for item in report["blockers"]
        ))
        self.assertEqual(report["governance"]["next_required_gate"], REQUIRED_GATES[0])
        self.assertFalse(report["generation_preconditions_met"])
        self.assertFalse(report["execution"]["generation_performed"])
        self.assertFalse(report["execution"]["assessment_is_execution_authorisation"])

    def test_all_assessments_and_synthetic_gates_still_do_not_execute(self):
        result = CreativeProductionOrchestrator(ReadyEngine()).run(
            PROJECT, capability_evidence={}, actor_role="TEST_HARNESS",
            gate_records=approved_gates(), generation_authorisation=True,
        )
        report = build_readiness_report(result)
        self.assertTrue(report["generation_preconditions_met"])
        self.assertEqual(report["blockers"], [])
        self.assertTrue(report["governance"]["all_gates_approved"])
        self.assertFalse(report["execution"]["generation_performed"])
        self.assertFalse(report["execution"]["external_action_performed"])
        self.assertFalse(report["execution"]["publishing_performed"])
        self.assertIn("does not execute", report["interpretation"])

    def test_rejects_non_orchestration_input(self):
        with self.assertRaises(TypeError):
            build_readiness_report({"status": "READY"})

if __name__ == "__main__":
    unittest.main()
