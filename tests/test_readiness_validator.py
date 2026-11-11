import unittest
from raei.execution.validate_ledger import (
    BIBLE_BOOKS, ETHICS_CASES, RHEMA_IDS, ENGINEERING_CAPSTONES, validate, report
)


def evidence(identifier):
    return {"id": identifier, "status": "verified", "evidence_ref": f"evidence/{identifier}", "score": 3}


def passed_domain(evidence_items):
    return {"status": "passed", "competency_score": 3, "critical_failure": False, "evidence": evidence_items}


def ready_ledger():
    return {
        "domains": {
            "engineering": {**passed_domain([evidence(x) for x in ENGINEERING_CAPSTONES]),
                            "required_capstones": ENGINEERING_CAPSTONES},
            "whole_bible": {"status": "passed", "competency_score": 3, "evidence": ["books/66-book-review"], "books": [
                {"book_id": book, "status": "passed", "evidence_status": "verified",
                 "evidence_ref": f"books/{book}", "score": 3} for book in BIBLE_BOOKS]},
            "bible_only_ethics": {"status": "passed", "competency_score": 3, "evidence": ["ethics/case-review"], "cases": [
                {"case_id": case, "status": "passed", "score": 3, "evidence_ref": f"ethics/{case}",
                 "biblical_context_reviewed": True, "explicit_vs_inference_recorded": True}
                for case in ETHICS_CASES]},
            "rhemascript": {"status": "passed", "competency_score": 3, "evidence": ["rhemascript/capability-review"], "capabilities": [
                {"capability_id": cap, "status": "passed", "score": 3, "evidence_ref": f"rs/{cap}"}
                for cap in RHEMA_IDS]},
            "integrated_capstone": {"status": "passed", "competency_score": 3,
                                    "critical_failure": False, "evidence": ["capstone/report.md"]},
        },
        "independent_assurance": {"status": "not_satisfied"},
        "production_authority": "not_granted",
    }


class ReadinessValidatorTests(unittest.TestCase):
    def test_complete_synthetic_fixture_passes_evidence_gate(self):
        data = ready_ledger()
        self.assertEqual(validate(data), [])
        self.assertEqual(report(data)["result"], "LEARNING_READINESS_EVIDENCE_COMPLETE")
        self.assertEqual(report(data)["production_authority"], "not_granted")

    def test_empty_ledger_fails_closed(self):
        self.assertTrue(validate({"domains": {}}))

    def test_missing_bible_book_fails(self):
        data = ready_ledger()
        data["domains"]["whole_bible"]["books"].pop()
        self.assertTrue(any("Revelation" in x for x in validate(data)))

    def test_duplicate_book_fails(self):
        data = ready_ledger()
        data["domains"]["whole_bible"]["books"].append(data["domains"]["whole_bible"]["books"][0])
        self.assertTrue(any("duplicate book_id" in x for x in validate(data)))

    def test_unverified_ethics_case_fails(self):
        data = ready_ledger()
        data["domains"]["bible_only_ethics"]["cases"][0]["biblical_context_reviewed"] = False
        self.assertTrue(any("ETH-TRUTH" in x for x in validate(data)))

    def test_missing_rhemascript_capability_fails(self):
        data = ready_ledger()
        data["domains"]["rhemascript"]["capabilities"].pop()
        self.assertTrue(any("QC-COMPLIANCE" in x for x in validate(data)))

    def test_missing_engineering_capstone_fails(self):
        data = ready_ledger()
        data["domains"]["engineering"]["evidence"].pop(0)
        self.assertTrue(any("integrated_frontend_backend_database" in x for x in validate(data)))

    def test_integrated_capstone_cannot_pass_without_score(self):
        data = ready_ledger()
        data["domains"]["integrated_capstone"]["competency_score"] = None
        self.assertTrue(any("competency_score" in x for x in validate(data)))

    def test_critical_failure_blocks(self):
        data = ready_ledger()
        data["domains"]["engineering"]["critical_failure"] = True
        self.assertTrue(any("critical failure" in x for x in validate(data)))

    def test_boolean_score_is_not_numeric_pass(self):
        data = ready_ledger()
        data["domains"]["integrated_capstone"]["competency_score"] = True
        self.assertTrue(any("competency_score" in x for x in validate(data)))

    def test_malformed_domain_fails_closed(self):
        data = ready_ledger()
        data["domains"]["engineering"] = []
        self.assertTrue(validate(data))


if __name__ == "__main__":
    unittest.main()
