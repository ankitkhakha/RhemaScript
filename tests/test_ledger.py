import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from raei.ledger import empty_ledger, add_unit, record_assessment, validate, LedgerError, append_event, main, load

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
    def test_boolean_score_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", True, "ref", "verified")

    def test_whitespace_evidence_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 4, "   ", "verified")

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
    def test_cli_assessment_defaults_to_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "ledger.json")
            with patch("sys.stdout"):
                self.assertEqual(main(["--ledger", path, "init"]), 0)
                self.assertEqual(main(["--ledger", path, "add-unit", "A", "Foundations"]), 0)
                self.assertEqual(main(["--ledger", path, "assess", "A", "4", "claimed-evidence"]), 0)
            data = load(path)
            self.assertEqual(data["units"]["A"]["evidence_status"], "reported_unverified")
            self.assertEqual(data["units"]["A"]["status"], "needs_correction")

    def test_cycle_and_self_dependency_rejected(self):
        with self.assertRaises(LedgerError):
            add_unit(self.data, "A", "Bad", ["A"])

    def test_malformed_ledger_root_fails_with_ledger_error(self):
        with self.assertRaises(LedgerError):
            validate([])

    def test_malformed_event_fails_with_ledger_error(self):
        self.data["events"].append(None)
        with self.assertRaises(LedgerError):
            validate(self.data)

    def test_non_string_or_duplicate_prerequisites_are_rejected(self):
        for prerequisites in (["A", 7], ["A", "A"], {}):
            with self.subTest(prerequisites=prerequisites), self.assertRaises(LedgerError):
                add_unit(self.data, "B", "Next", prerequisites)

    def test_non_string_verified_evidence_is_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 4, 123, "verified")

    def test_unhashable_evidence_status_is_rejected(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 4, "ref", [])

    def test_malformed_unit_and_status_fail_cleanly(self):
        self.data["units"]["A"] = []
        with self.assertRaises(LedgerError):
            validate(self.data)
        self.data["units"]["A"] = {"id": "A", "status": [], "prerequisites": []}
        append_event(self.data, "tampered_fixture", None, {})
        with self.assertRaises(LedgerError):
            validate(self.data)

    def test_dependency_cycle_in_imported_ledger_is_rejected(self):
        self.data["units"] = {
            "A": {"id": "A", "status": "in_progress", "prerequisites": ["B"]},
            "B": {"id": "B", "status": "in_progress", "prerequisites": ["A"]},
        }
        append_event(self.data, "fixture", None, {})
        with self.assertRaises(LedgerError):
            validate(self.data)

    def test_assessment_rejects_unhashable_unit_and_invalid_note(self):
        add_unit(self.data, "A", "Foundations", [])
        with self.assertRaises(LedgerError):
            record_assessment(self.data, [], 3, "ref", "verified")
        with self.assertRaises(LedgerError):
            record_assessment(self.data, "A", 3, "ref", "verified", note=[])

    def test_boolean_schema_version_is_rejected(self):
        self.data["schema_version"] = True
        with self.assertRaises(LedgerError):
            validate(self.data)

if __name__ == "__main__":
    unittest.main(verbosity=2)
