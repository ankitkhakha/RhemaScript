import unittest

from raei.execution.validate_project_integrity import (
    CHAIN, GATES, validate_project, readiness_report,
)


def ready_project():
    return {
        "record_type": "rhemascript_project_readiness",
        "source_to_final_chain": [
            {"stage": stage, "status": "present", "evidence_ref": f"evidence/{stage}"}
            for stage in CHAIN
        ],
        "approval_gates": [
            {"gate": gate, "decision": "approved",
             "approval_evidence_ref": f"approvals/{gate}", "approver": "synthetic-fixture"}
            for gate in GATES
        ],
        "authorities": {
            "generation_authorisation": "not_authorised",
            "publishing_authorisation": "not_authorised",
            "deployment_authorisation": "not_authorised",
            "merge_authorisation": "not_authorised",
        },
        "generation_executed": False,
        "publishing_executed": False,
        "production_authority": "not_granted",
    }


class ProjectIntegrityTests(unittest.TestCase):
    def test_synthetic_complete_traceability_passes_without_authority(self):
        record = ready_project()
        self.assertEqual(validate_project(record), [])
        result = readiness_report(record)
        self.assertEqual(result["result"], "PROJECT_TRACEABILITY_COMPLETE")
        self.assertEqual(result["production_authority"], "not_granted")

    def test_missing_chain_stage_blocks(self):
        record = ready_project()
        record["source_to_final_chain"].pop(2)
        self.assertTrue(any("approved_narration" in e for e in validate_project(record)))

    def test_missing_chain_evidence_blocks(self):
        record = ready_project()
        record["source_to_final_chain"][0]["evidence_ref"] = ""
        self.assertTrue(any("biblical_source is missing evidence_ref" in e
                            for e in validate_project(record)))

    def test_chain_order_is_enforced(self):
        record = ready_project()
        record["source_to_final_chain"][0], record["source_to_final_chain"][1] = (
            record["source_to_final_chain"][1], record["source_to_final_chain"][0])
        self.assertTrue(any("canonical order" in e for e in validate_project(record)))

    def test_missing_gate_approval_blocks(self):
        record = ready_project()
        record["approval_gates"][4]["decision"] = "pending"
        self.assertTrue(any("generation_authorisation is not approved" in e
                            for e in validate_project(record)))

    def test_missing_gate_evidence_blocks(self):
        record = ready_project()
        record["approval_gates"][0]["approval_evidence_ref"] = None
        self.assertTrue(any("missing approval evidence" in e for e in validate_project(record)))

    def test_gate_order_is_enforced(self):
        record = ready_project()
        record["approval_gates"][0], record["approval_gates"][1] = (
            record["approval_gates"][1], record["approval_gates"][0])
        self.assertTrue(any("approval gates are out of canonical order"
                            in e for e in validate_project(record)))

    def test_execution_flag_cannot_be_hidden_by_approval(self):
        record = ready_project()
        record["generation_executed"] = True
        self.assertTrue(any("generation_executed must be false"
                            in e for e in validate_project(record)))

    def test_authority_fields_must_be_explicit(self):
        record = ready_project()
        del record["authorities"]["publishing_authorisation"]
        self.assertTrue(any("publishing_authorisation must be explicitly"
                            in e for e in validate_project(record)))

    def test_production_authority_cannot_be_granted_by_validator(self):
        record = ready_project()
        record["production_authority"] = "granted"
        self.assertTrue(any("production_authority must remain not_granted"
                            in e for e in validate_project(record)))

    def test_malformed_input_fails_closed(self):
        self.assertTrue(validate_project(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
