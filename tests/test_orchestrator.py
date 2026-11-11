import json
import tempfile
import unittest
from pathlib import Path

from raei.curriculum import BIBLE_BOOKS
from raei.orchestrator import (
    DOMAIN_ORDER, execution_brief, initialise, next_unit, seed_ledger,
)
from raei.ledger import LedgerError, load, save
from raei.learning import record_practice, record_rubric_assessment


class OrchestratorTests(unittest.TestCase):
    def test_seed_registers_complete_scope_without_claiming_mastery(self):
        data = seed_ledger()
        self.assertEqual(len(data["units"]), 17 + 66 + 10 + 46 + 1)
        self.assertEqual(data["units"]["BIBLE-01"]["title"], BIBLE_BOOKS[0])
        self.assertTrue(all(u["status"] == "not_started" for u in data["units"].values()))
        self.assertFalse(data["events"][-1]["details"]["mastery_claim"])

    def test_seeded_ledger_carries_prerequisites_into_assessment_contract(self):
        data = seed_ledger()
        self.assertEqual(["CS-FOUND"], data["units"]["PROG-CORE"]["prerequisites"])
        self.assertEqual(["BIBLE-01"], data["units"]["BIBLE-02"]["prerequisites"])
        self.assertEqual(["ETH-TRUTH"], data["units"]["ETH-STEWARD"]["prerequisites"])
        self.assertEqual(["QC-COMPLIANCE"], data["units"]["RS-CIE"]["prerequisites"])
        self.assertEqual(4, len(data["units"]["INTEGRATED-CAPSTONE"]["prerequisites"]))
        self.assertNotIn("INTEGRATED-CAPSTONE", data["units"]["INTEGRATED-CAPSTONE"]["prerequisites"])

    def test_next_task_uses_canonical_domain_and_registry_order(self):
        data = seed_ledger()
        unit = next_unit(data)
        self.assertEqual(unit["id"], "CS-FOUND")
        self.assertEqual(unit["domain"], DOMAIN_ORDER[0])

    def test_task_brief_contains_evidence_and_authority_constraints(self):
        unit = seed_ledger()["units"]["BIBLE-01"]
        brief = execution_brief(unit)
        self.assertIn("original_work_or_study", brief["required_deliverables"])
        self.assertEqual(brief["authority_boundary"]["production_authority"], "not_granted")

    def test_initialise_persists_valid_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            result = initialise(str(path))
            saved = load(path)
            self.assertEqual(result["unit_count"], len(saved["units"]))
            self.assertEqual(saved["units"]["CS-FOUND"]["status"], "not_started")

    def test_seeded_curriculum_connects_to_original_learning_functions(self):
        data = seed_ledger()
        unit = data["units"]["CS-FOUND"]
        record_practice(data, "CS-FOUND", "evidence/cs-found.md", "original exercise", "result inspected")
        scores = {criterion: 3 for criterion in unit["rubric"]}
        record_rubric_assessment(data, "CS-FOUND", scores, "evidence/cs-found.md", "verified")
        self.assertEqual(unit["status"], "passed")
        self.assertEqual(unit["score"], 3)

    def test_cli_practice_and_assess_commands_persist_seeded_unit(self):
        from raei.orchestrator import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            save(path, seed_ledger())
            self.assertEqual(main(["--ledger", str(path), "practice", "CS-FOUND",
                                   "evidence/cs-found.md", "original exercise", "result inspected"]), 0)
            scores = json.dumps({criterion: 3 for criterion in load(path)["units"]["CS-FOUND"]["rubric"]})
            self.assertEqual(main(["--ledger", str(path), "assess", "CS-FOUND",
                                   scores, "evidence/cs-found.md"]), 0)
            self.assertEqual(load(path)["units"]["CS-FOUND"]["status"], "passed")

    def test_initialise_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            initialise(str(path))
            with self.assertRaises(LedgerError):
                initialise(str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
