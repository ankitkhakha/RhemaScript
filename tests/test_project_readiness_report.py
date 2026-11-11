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


    def test_one_call_pipeline_validates_manifest_assesses_and_reports(self):
        from rhemascript.reports import run_project_assessment
        manifest = {
            "manifest_id": "RS-ONE-CALL-001",
            "schema_version": "1.0",
            "project_record": dict(PROJECT),
            "artifacts": [{
                "artifact_id": "SOURCE-1",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "BIBLICAL_SOURCE",
                "version": "1",
                "status": "VERIFIED",
                "evidence_refs": ["synthetic:source"],
            }],
            "evidence_records": [{
                "evidence_id": "CAP01-EVIDENCE",
                "capability_id": "CAP-01",
                "payload": {"sources": [{"source_ref": "synthetic:source"}]},
                "evidence_refs": ["synthetic:source"],
                "artifact_refs": ["SOURCE-1"],
            }],
            "source_to_final_links": [],
        }
        validated, result, report = run_project_assessment(
            manifest,
            actor_role="SYNTHETIC_TEST_HARNESS",
            orchestrator=CreativeProductionOrchestrator(ReadyEngine()),
        )
        self.assertEqual(validated.manifest_id, "RS-ONE-CALL-001")
        self.assertEqual(result.project_id, PROJECT["project_id"])
        self.assertEqual(report["run_id"], result.run_id)
        self.assertEqual(report["project_id"], validated.project_id)
        self.assertFalse(report["generation_preconditions_met"])
        self.assertFalse(report["execution"]["generation_performed"])
        self.assertFalse(report["execution"]["external_action_performed"])
        self.assertFalse(report["execution"]["publishing_performed"])

if __name__ == "__main__":
    unittest.main()
