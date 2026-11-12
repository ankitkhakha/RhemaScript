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


    def test_readiness_assessment_retains_exact_resolved_source_version(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from rhemascript.evidence.local_source_resolver import LocalSourceEntry, LocalSourceResolver
        from rhemascript.evidence.readiness_registry import ReadinessRunRegistry
        from rhemascript.reports import run_project_assessment

        with tempfile.TemporaryDirectory() as root:
            content = b"source bytes for readiness traceability"
            (Path(root) / "source.txt").write_bytes(content)
            reference = "local-source:readiness:source"
            digest = hashlib.sha256(content).hexdigest()
            manifest = {
                "manifest_id": "RS-READINESS-SOURCE-001",
                "schema_version": "1.0",
                "project_record": dict(PROJECT),
                "artifacts": [{
                    "artifact_id": "SOURCE-1",
                    "project_id": PROJECT["project_id"],
                    "project_version": PROJECT["version"],
                    "artifact_type": "BIBLICAL_SOURCE",
                    "version": "source-v7",
                    "status": "VERIFIED",
                    "local_source_reference": reference,
                    "sha256": digest,
                }],
                "evidence_records": [{
                    "evidence_id": "CAP01-SOURCE-EVIDENCE",
                    "capability_id": "CAP-01",
                    "payload": {"sources": [{"source_ref": reference}]},
                    "evidence_refs": [reference],
                    "artifact_refs": ["SOURCE-1"],
                }],
                "source_to_final_links": [],
            }
            resolver = LocalSourceResolver(root, {
                reference: LocalSourceEntry(
                    reference=reference,
                    source_id="SOURCE-1",
                    relative_path="source.txt",
                    version="source-v7",
                    expected_sha256=digest,
                    media_type="text/plain",
                    catalog_revision="catalog-v7",
                    project_id=PROJECT["project_id"],
                    project_version=PROJECT["version"],
                )
            })
            registry = ReadinessRunRegistry(Path(root) / "readiness.sqlite3")
            validated, result, report = run_project_assessment(
                manifest,
                actor_role="TEST_HARNESS",
                run_id="RUN-READINESS-SOURCE-001",
                orchestrator=CreativeProductionOrchestrator(ReadyEngine()),
                local_source_resolver=resolver,
                readiness_registry=registry,
            )
            self.assertEqual(len(validated.source_resolution_receipts), 1)
            receipt = validated.source_resolution_receipts[0]
            self.assertEqual(receipt.version, "source-v7")
            self.assertEqual(receipt.sha256, digest)
            self.assertEqual(report["evidence_integrity"]["source_resolution_receipts"][0]["catalog_revision"],
                             "catalog-v7")
            trace = report["evidence_traceability"]["artifacts"][0]["local_source_resolution"]
            self.assertEqual(trace["version"], "source-v7")
            self.assertEqual(trace["sha256"], digest)
            saved = registry.get(result.run_id)
            saved_receipt = saved["source_resolution_receipts"][0]
            self.assertEqual(saved_receipt["catalog_fingerprint"], receipt.catalog_fingerprint)
            self.assertEqual(saved_receipt["project_id"], PROJECT["project_id"])
            self.assertEqual(saved_receipt["project_version"], PROJECT["version"])
            self.assertFalse(report["execution"]["generation_performed"])
            self.assertFalse(report["execution"]["publishing_performed"])

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
        trace = report["evidence_traceability"]
        self.assertEqual(trace["records"][0]["capability_id"], "CAP-01")
        self.assertEqual(trace["records"][0]["artifact_refs"], ["SOURCE-1"])
        self.assertEqual(trace["records"][0]["evidence_refs"][0]["resolution_status"],
                         "UNRESOLVED_BY_LOCAL_ARTIFACT_VERIFIER")
        self.assertEqual(trace["artifacts"][0]["capability_ids"], ["CAP-01"])
        self.assertEqual(trace["artifacts"][0]["integrity_status"], "NOT_BYTE_VERIFIED")
        self.assertFalse(report["generation_preconditions_met"])
        self.assertFalse(report["execution"]["generation_performed"])
        self.assertFalse(report["execution"]["external_action_performed"])
        self.assertFalse(report["execution"]["publishing_performed"])

if __name__ == "__main__":
    unittest.main()
