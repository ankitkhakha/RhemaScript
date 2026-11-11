import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from raei.ledger import empty_ledger, add_unit, record_assessment, validate, LedgerError, append_event

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.data = empty_ledger()
        append_event(self.data, "ledger_initialized", None, {})
    def test_verified_pass_and_prerequisite(self):
        add_unit(self.data, "A", "Foundations", [])
        record_assessment(self.data, "A", 3, "tests/test_a.py::test_ok", "verified")
        add_unit(self.data, "B", "Next", ["A"])
        self.assertEqual(self.data["units"]["B"]["status"], "not_started")
    def test_blocks_prerequisite_bypass(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            add_unit(self.data, "B", "Next", ["A"])
    def test_unverified_cannot_pass(self):
        add_unit(self.data, "A", "Foundations", [])
        record_assessment(self.data, "A", 4, "claimed only", "reported_unverified")
        self.assertEqual(self.data["units"]["A"]["status"], "needs_correction")
    def test_missing_evidence_cannot_pass(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 4, "", "verified")
    def test_duplicate_ids_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            add_unit(self.data, "A", "Duplicate", [])
    def test_bad_score_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 5, "ref", "verified")
    def test_event_tampering_detected(self):
        add_unit(self.data, "A", "Foundations", [])
        self.data["events"][1]["details"]["title"] = "Tampered"
        with self.assertRaises(LedgerError):
            validate(self.data)
    def test_unrecorded_unit_state_tampering_detected(self):
        add_unit(self.data, "A", "Foundations", [])
        self.data["units"]["A"]["title"] = "Tampered title"
        with self.assertRaises(LedgerError):
            validate(self.data)
    def test_passed_unit_is_immutable(self):
        add_unit(self.data, "A", "Foundations", [])
        record_assessment(self.data, "A", 3, "test-output", "verified")
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 4, "new-output", "verified")
    def test_cycle_and_self_dependency_rejected(self):
        with self.assertRaises(LedgerError):
            add_unit(self.data, "A", "Bad", ["A"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
