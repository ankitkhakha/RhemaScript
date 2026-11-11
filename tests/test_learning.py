import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from raei.ledger import empty_ledger, add_unit, validate, append_event, LedgerError
from raei.learning import create_lesson, record_practice, record_rubric_assessment, record_correction

class LearningWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.data=empty_ledger(); append_event(self.data,"ledger_initialized",None,{})
        add_unit(self.data,"U1","Foundations",[])
    def lesson(self):
        create_lesson(self.data,"U1",["Explain core concept"],["official-doc:section-1"],
            "Build a minimal working example",{"correctness":"All expected cases pass","reasoning":"Explain design choices"})
    def test_lesson_requires_all_parts(self):
        with self.assertRaises(LedgerError):
            create_lesson(self.data,"U1",[],["source"],"practice",{"criterion":"pass"})
    def test_practice_requires_lesson(self):
        with self.assertRaises(LedgerError):
            record_practice(self.data,"U1","artifact","python test","passed")
    def test_practice_and_rubric_assessment_pass(self):
        self.lesson()
        record_practice(self.data,"U1","tests/output.txt","python -m unittest","2 tests passed")
        record_rubric_assessment(self.data,"U1",{"correctness":3,"reasoning":4},"tests/output.txt","verified")
        self.assertEqual(self.data["units"]["U1"]["status"],"passed")
        validate(self.data)
    def test_every_rubric_criterion_must_be_scored(self):
        self.lesson()
        record_practice(self.data,"U1","artifact","method","result")
        with self.assertRaises(LedgerError):
            record_rubric_assessment(self.data,"U1",{"correctness":4},"artifact","verified")
    def test_weakest_criterion_controls_pass(self):
        self.lesson()
        record_practice(self.data,"U1","artifact","method","result")
        record_rubric_assessment(self.data,"U1",{"correctness":4,"reasoning":2},"artifact","verified")
        self.assertEqual(self.data["units"]["U1"]["status"],"needs_correction")
        self.assertEqual(self.data["units"]["U1"]["score"],2)
    def test_unverified_practice_cannot_support_assessment(self):
        self.lesson()
        record_practice(self.data,"U1","claim","not executed","claimed pass","reported_unverified")
        with self.assertRaises(LedgerError):
            record_rubric_assessment(self.data,"U1",{"correctness":4,"reasoning":4},"claim","verified")
    def test_correction_requires_failed_or_incomplete_state(self):
        self.lesson()
        with self.assertRaises(LedgerError):
            record_correction(self.data,"U1","fix","new","method","result")
    def test_correction_appends_and_preserves_history(self):
        self.lesson()
        record_practice(self.data,"U1","artifact","method","result")
        record_rubric_assessment(self.data,"U1",{"correctness":1,"reasoning":2},"artifact","verified")
        record_correction(self.data,"U1","fixed edge case","new-artifact","fresh test","all pass")
        self.assertEqual(self.data["units"]["U1"]["status"],"in_progress")
        self.assertEqual(len(self.data["units"]["U1"]["corrections"]),1)
        validate(self.data)

if __name__=="__main__":
    unittest.main(verbosity=2)
