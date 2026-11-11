import tempfile
import unittest
from pathlib import Path

from raei.curriculum import BIBLE_BOOKS
from raei.orchestrator import (
    DOMAIN_ORDER, execution_brief, initialise, next_unit, seed_ledger,
)
from raei.ledger import LedgerError, load


class OrchestratorTests(unittest.TestCase):
    def test_seed_registers_complete_scope_without_claiming_mastery(self):
        data = seed_ledger()
        self.assertEqual(len(data["units"]), 17 + 66 + 10 + 46 + 1)
        self.assertEqual(data["units"]["BIBLE-01"]["title"], BIBLE_BOOKS[0])
        self.assertTrue(all(u["status"] == "not_started" for u in data["units"].values()))
        self.assertFalse(data["events"][-1]["details"]["mastery_claim"])

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

    def test_initialise_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            initialise(str(path))
            with self.assertRaises(LedgerError):
                initialise(str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
