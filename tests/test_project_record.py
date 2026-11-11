import unittest

from raei.integrity import GATES, STAGES, IntegrityError
from raei.project_record import create_project_record, revise_stage


class ProjectRecordTests(unittest.TestCase):
    def test_new_record_starts_with_all_gates_pending_and_no_authority(self):
        project = create_project_record("RS-LOCAL-TEST-001")
        self.assertEqual(set(GATES), set(project["approvals"]))
        self.assertTrue(all(x["status"] == "pending" for x in project["approvals"].values()))
        self.assertFalse(project["generation"]["authorized"])
        self.assertFalse(project["generation"]["performed"])
        self.assertFalse(project["published"])

    def test_stages_can_be_recorded_in_order_with_revision_history(self):
        project = create_project_record("RS-LOCAL-TEST-002")
        for index, stage in enumerate(STAGES):
            upstream = [] if index == 0 else [project["stages"][STAGES[index - 1]]["artifact_ref"]]
            project = revise_stage(
                project, stage, stage + "-artifact-v1", "source:" + stage,
                "Initial local practical record", upstream,
            )
        self.assertEqual(len(STAGES), len(project["revision_history"]))
        self.assertEqual(1, project["stages"]["edited_film"]["revision"])

    def test_revision_invalidates_its_gate_and_downstream_gates(self):
        project = create_project_record("RS-LOCAL-TEST-003")
        project["approvals"] = {
            gate: {"status": "approved", "approval_ref": "approval:" + gate,
                   "artifact_ref": "old:" + gate}
            for gate in GATES
        }
        project["stages"]["biblical_source"] = {
            "status": "present", "artifact_ref": "source-v1",
            "source_ref": "bible:reference", "revision": 1, "upstream_refs": [],
        }
        revised = revise_stage(
            project, "biblical_source", "source-v2", "bible:updated-reference",
            "Corrected source reference",
        )
        self.assertEqual("approved", project["approvals"]["creative_direction"]["status"])
        self.assertTrue(all(x["status"] == "pending" for x in revised["approvals"].values()))
        self.assertEqual(1, project["stages"]["biblical_source"]["revision"])
        self.assertEqual(2, revised["stages"]["biblical_source"]["revision"])
        self.assertEqual("source-v1", revised["revision_history"][0]["previous_artifact_ref"])

    def test_downstream_stage_requires_predecessor(self):
        project = create_project_record("RS-LOCAL-TEST-004")
        with self.assertRaises(IntegrityError):
            revise_stage(project, "approved_script", "script-v1", "source:script", "Initial")

    def test_wrong_dependency_is_rejected(self):
        project = create_project_record("RS-LOCAL-TEST-005")
        project = revise_stage(project, "biblical_source", "source-v1", "bible:ref", "Initial")
        with self.assertRaises(IntegrityError):
            revise_stage(project, "approved_script", "script-v1", "script:ref", "Initial", ["wrong-ref"])

    def test_original_record_is_not_mutated(self):
        project = create_project_record("RS-LOCAL-TEST-006")
        revised = revise_stage(project, "biblical_source", "source-v1", "bible:ref", "Initial")
        self.assertEqual({}, project["stages"])
        self.assertEqual("source-v1", revised["stages"]["biblical_source"]["artifact_ref"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
