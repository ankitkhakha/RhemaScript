import unittest

from rhemascript.capabilities.runtime import CapabilityResult
from rhemascript.evidence import EvidencePackError, run_evidence_pack
from rhemascript.orchestration import CreativeProductionOrchestrator
from rhemascript.registry.system_registry import CAPABILITIES, REQUIRED_GATES

PROJECT = {
    "record_id": "RS-E2E-001",
    "record_type": "SYNTHETIC_PROJECT",
    "schema_version": "1.0",
    "project_id": "RS-E2E-PROJECT-001",
    "status": "DRAFT",
    "classification": "OPERATIONAL",
    "version": "1.0",
}

class SyntheticReadyEngine:
    """Deterministic test double; no provider or production action exists."""
    def execute(self, capability_id, record, *, actor_role, evidence, authority=None):
        return CapabilityResult(
            capability_id=capability_id,
            project_id=record["project_id"],
            status="READY_FOR_HUMAN_REVIEW",
            outputs={"synthetic_assessment": True},
            missing_evidence=(),
        )

def make_pack():
    evidence_records = [
        {
            "evidence_id": f"E2E-{capability_id}",
            "capability_id": capability_id,
            "payload": {"synthetic_fixture": True},
            "evidence_refs": [f"test-fixture:{capability_id}"],
            "artifact_refs": ["SOURCE-1"],
        }
        for capability_id in CAPABILITIES
    ]
    return {
        "manifest_id": "RS-E2E-MANIFEST-001",
        "schema_version": "1.0",
        "project_record": dict(PROJECT),
        "artifacts": [{
            "artifact_id": "SOURCE-1",
            "project_id": PROJECT["project_id"],
            "project_version": PROJECT["version"],
            "artifact_type": "BIBLICAL_SOURCE",
            "version": "1",
            "status": "VERIFIED",
            "evidence_refs": ["test-fixture:source"],
        }],
        "evidence_records": evidence_records,
        "source_to_final_links": [],
        "gate_records": [
            {
                "project_id": PROJECT["project_id"],
                "gate": gate,
                "decision": "APPROVED",
                "actor_id": f"SYNTHETIC-TEST-ACTOR-{index}",
                "evidence_ref": f"synthetic-approval-fixture:{index}",
            }
            for index, gate in enumerate(REQUIRED_GATES, start=1)
        ],
    }

class ProjectEvidencePackEndToEndTests(unittest.TestCase):
    def test_manifest_compiles_all_capabilities_and_runs_in_dependency_order(self):
        validated, result = run_evidence_pack(
            make_pack(),
            actor_role="SYNTHETIC_TEST_HARNESS",
            orchestrator=CreativeProductionOrchestrator(SyntheticReadyEngine()),
        )
        self.assertEqual(validated.project_id, PROJECT["project_id"])
        self.assertEqual(set(validated.capability_evidence), set(CAPABILITIES))
        self.assertEqual(result.status, "ASSESSMENTS_READY_FOR_HUMAN_REVIEW")
        self.assertTrue(result.gate_status["all_gates_approved"])
        self.assertTrue(all(
            row["status"] == "ASSESSED_FOR_HUMAN_REVIEW"
            for row in result.capability_results.values()
        ))
        self.assertEqual(len(result.audit_trace), len(CAPABILITIES))
        self.assertTrue(all(row["run_id"] == result.run_id for row in result.audit_trace))
        # Human approvals in a synthetic fixture do not replace the separate
        # generation-authorisation input or cause any execution.
        self.assertFalse(result.generation_preconditions_met)
        self.assertFalse(result.generation_action_performed)
        self.assertFalse(result.external_action_performed)
        self.assertFalse(result.publishing_performed)

    def test_bad_gate_order_remains_governance_blocked_through_manifest_handoff(self):
        manifest = make_pack()
        manifest["gate_records"][0], manifest["gate_records"][1] = (
            manifest["gate_records"][1], manifest["gate_records"][0]
        )
        _, result = run_evidence_pack(
            manifest,
            actor_role="SYNTHETIC_TEST_HARNESS",
            generation_authorisation=True,
            orchestrator=CreativeProductionOrchestrator(SyntheticReadyEngine()),
        )
        self.assertEqual(result.status, "GOVERNANCE_BLOCKED")
        self.assertEqual(result.gate_status["gate_status"], "BLOCKED")
        self.assertFalse(result.generation_preconditions_met)
        self.assertFalse(result.generation_action_performed)

    def test_manifest_rejects_unsupported_schema_version_before_orchestration(self):
        manifest = make_pack()
        manifest["schema_version"] = "99.0"
        with self.assertRaisesRegex(EvidencePackError, "unsupported schema_version"):
            run_evidence_pack(
                manifest,
                actor_role="SYNTHETIC_TEST_HARNESS",
                orchestrator=CreativeProductionOrchestrator(SyntheticReadyEngine()),
            )

if __name__ == "__main__":
    unittest.main()
