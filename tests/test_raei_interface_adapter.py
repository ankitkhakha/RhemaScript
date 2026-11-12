"""Tests for the read-only RAEI service boundary."""
import tempfile
import unittest
from pathlib import Path

from raei.integrity import GATES, STAGES
from raei.interface_adapter import RAEIAdapterError, RAEIReadOnlyAdapter
from raei.store import EvidenceStore


def valid_project():
    stages = {}
    previous = None
    for index, stage in enumerate(STAGES):
        artifact = f"artifact-{index}"
        stages[stage] = {
            "status": "present",
            "artifact_ref": artifact,
            "source_ref": f"source-{index}",
            "revision": 1,
            "upstream_refs": [] if previous is None else [previous],
        }
        previous = artifact
    return {
        "project_id": "RS-ADAPTER-TEST",
        "stages": stages,
        "approvals": {
            gate: {
                "status": "approved",
                "approval_ref": f"approval-{gate}",
                "artifact_ref": stages[{
                    "creative_direction": "biblical_source",
                    "biblical_accuracy": "approved_script",
                    "visual_development": "storyboard",
                    "production_plan_prompt": "clip_prompt",
                    "generation_authorisation": "asset",
                    "final_film": "edited_film",
                }[gate]]["artifact_ref"],
            }
            for gate in GATES
        },
        "generation": {
            "authorized": False, "performed": False,
            "authorization_ref": None, "asset_ref": None,
        },
        "published": False,
        "revision_history": [],
    }


class RAEIReadOnlyAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.temp.name) / "evidence.sqlite")
        self.adapter = RAEIReadOnlyAdapter(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_project_validation_is_read_only_and_grants_no_authority(self):
        project = valid_project()
        result = self.adapter.validate_project_snapshot(project)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["generation_authority"], "not_granted_by_adapter")
        self.assertEqual(result["publishing_authority"], "not_granted_by_adapter")
        self.assertEqual(project["generation"]["authorized"], False)
        self.assertEqual(project["published"], False)

    def test_snapshot_comparison_is_read_only(self):
        before = valid_project()
        after = valid_project()
        result = self.adapter.compare_project_snapshots(before, after)
        self.assertFalse(result["requires_review"])
        self.assertEqual(result["generation_authority"], "not_granted_by_adapter")
        self.assertEqual(before, after)

    def test_learning_unit_read_returns_detached_read_only_result(self):
        self.store.create_unit("UNIT-1", "Read-only adapter test")
        result = self.adapter.read_learning_unit("UNIT-1")
        self.assertEqual(result["unit"]["unit_id"], "UNIT-1")
        self.assertFalse(result["write_performed"])
        result["unit"]["title"] = "caller mutation"
        self.assertEqual(self.store.get_unit("UNIT-1")["title"], "Read-only adapter test")

    def test_unknown_learning_unit_fails_without_leaking_store_details(self):
        with self.assertRaisesRegex(RAEIAdapterError, "could not be read"):
            self.adapter.read_learning_unit("missing")

    def test_invalid_project_snapshot_fails_closed(self):
        with self.assertRaises(RAEIAdapterError):
            self.adapter.validate_project_snapshot({"project_id": "incomplete"})

    def test_service_dispatcher_exposes_only_named_read_operations(self):
        self.store.create_unit("UNIT-DISPATCH", "Dispatcher read")
        result = self.adapter.invoke("READ_LEARNING_UNIT", {"unit_id": "UNIT-DISPATCH"})
        self.assertEqual(result["status"], "COMPLETED_READ_ONLY")
        self.assertFalse(result["write_performed"])
        self.assertEqual(result["result"]["unit"]["unit_id"], "UNIT-DISPATCH")

    def test_service_dispatcher_rejects_write_and_unknown_operations(self):
        for operation in ("RECORD_LEARNING_ASSESSMENT", "PUBLISH", "GENERATE", "UNKNOWN"):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(RAEIAdapterError, "not registered"):
                    self.adapter.invoke(operation, {})

    def test_service_dispatcher_rejects_extra_payload_fields(self):
        with self.assertRaisesRegex(RAEIAdapterError, "only unit_id"):
            self.adapter.invoke("READ_LEARNING_UNIT", {
                "unit_id": "UNIT-1", "authorize_write": True,
            })

    def test_adapter_requires_explicit_evidence_store(self):
        with self.assertRaises(RAEIAdapterError):
            RAEIReadOnlyAdapter(None)


if __name__ == "__main__":
    unittest.main()
