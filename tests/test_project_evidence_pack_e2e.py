import unittest

from rhemascript.capabilities.runtime import CapabilityResult
from rhemascript.evidence import EvidencePackError, run_evidence_pack, validate_evidence_pack
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
    def test_analytics_snapshots_and_comparison_bind_exact_artifact_ids(self):
        manifest = make_pack()
        manifest["artifacts"].extend([
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "a" * 64,
            },
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "b" * 64,
            },
            {
                "artifact_id": "ANALYTICS-COMPARISON-1",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
                "version": "1",
                "status": "DRAFT",
                "comparison_sha256": "c" * 64,
                "current_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "previous_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "current_snapshot_sha256": "b" * 64,
                "previous_snapshot_sha256": "a" * 64,
            },
        ])
        manifest["source_to_final_links"] = [
            {"from_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
             "to_artifact_id": "ANALYTICS-COMPARISON-1", "relationship": "DERIVED_FROM"},
            {"from_artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
             "to_artifact_id": "ANALYTICS-COMPARISON-1", "relationship": "DERIVED_FROM"},
        ]
        validated = validate_evidence_pack(manifest)
        artifacts = {item["artifact_id"]: item for item in validated.artifacts}
        comparison = artifacts["ANALYTICS-COMPARISON-1"]
        self.assertEqual(comparison["previous_snapshot_artifact_id"], "ANALYTICS-SNAPSHOT-PREV")
        self.assertEqual(comparison["current_snapshot_artifact_id"], "ANALYTICS-SNAPSHOT-CURRENT")
        self.assertEqual(
            {link["from_artifact_id"] for link in validated.source_to_final_links},
            {"ANALYTICS-SNAPSHOT-PREV", "ANALYTICS-SNAPSHOT-CURRENT"},
        )

    def test_analytics_comparison_rejects_source_snapshot_digest_substitution(self):
        manifest = make_pack()
        manifest["artifacts"].extend([
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "a" * 64,
            },
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "b" * 64,
            },
            {
                "artifact_id": "ANALYTICS-COMPARISON-1",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
                "version": "1",
                "status": "DRAFT",
                "comparison_sha256": "c" * 64,
                "current_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "previous_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "current_snapshot_sha256": "d" * 64,
                "previous_snapshot_sha256": "a" * 64,
            },
        ])
        manifest["source_to_final_links"] = [
            {"from_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
             "to_artifact_id": "ANALYTICS-COMPARISON-1", "relationship": "DERIVED_FROM"},
            {"from_artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
             "to_artifact_id": "ANALYTICS-COMPARISON-1", "relationship": "DERIVED_FROM"},
        ]
        with self.assertRaisesRegex(EvidencePackError, "digest does not match"):
            validate_evidence_pack(manifest)

    def test_analytics_comparison_requires_both_derived_from_links(self):
        manifest = make_pack()
        manifest["artifacts"].extend([
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "a" * 64,
            },
            {
                "artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
                "version": "1",
                "status": "DRAFT",
                "snapshot_sha256": "b" * 64,
            },
            {
                "artifact_id": "ANALYTICS-COMPARISON-1",
                "project_id": PROJECT["project_id"],
                "project_version": PROJECT["version"],
                "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
                "version": "1",
                "status": "DRAFT",
                "comparison_sha256": "c" * 64,
                "current_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-CURRENT",
                "previous_snapshot_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
                "current_snapshot_sha256": "b" * 64,
                "previous_snapshot_sha256": "a" * 64,
            },
        ])
        manifest["source_to_final_links"] = [
            {"from_artifact_id": "ANALYTICS-SNAPSHOT-PREV",
             "to_artifact_id": "ANALYTICS-COMPARISON-1", "relationship": "DERIVED_FROM"},
        ]
        with self.assertRaisesRegex(EvidencePackError, "both exact snapshot artifacts"):
            validate_evidence_pack(manifest)

    def test_analytics_comparison_rejects_missing_or_non_snapshot_source(self):
        manifest = make_pack()
        manifest["artifacts"].append({
            "artifact_id": "ANALYTICS-COMPARISON-1",
            "project_id": PROJECT["project_id"],
            "project_version": PROJECT["version"],
            "artifact_type": "YOUTUBE_ANALYTICS_COMPARISON",
            "version": "1",
            "status": "DRAFT",
            "comparison_sha256": "c" * 64,
            "current_snapshot_artifact_id": "NOT-A-SNAPSHOT",
            "previous_snapshot_artifact_id": "ALSO-NOT-A-SNAPSHOT",
            "current_snapshot_sha256": "b" * 64,
            "previous_snapshot_sha256": "a" * 64,
        })
        with self.assertRaisesRegex(EvidencePackError, "missing or non-snapshot"):
            validate_evidence_pack(manifest)

    def test_analytics_snapshot_requires_canonical_sha256(self):
        manifest = make_pack()
        manifest["artifacts"].append({
            "artifact_id": "ANALYTICS-SNAPSHOT-BAD",
            "project_id": PROJECT["project_id"],
            "project_version": PROJECT["version"],
            "artifact_type": "YOUTUBE_ANALYTICS_SNAPSHOT",
            "version": "1",
            "status": "DRAFT",
            "snapshot_sha256": "NOT-A-DIGEST",
        })
        with self.assertRaisesRegex(EvidencePackError, "lowercase SHA-256"):
            validate_evidence_pack(manifest)

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
