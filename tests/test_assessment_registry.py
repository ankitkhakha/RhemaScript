import tempfile
import unittest
from pathlib import Path

from rhemascript.evidence.artifact_verification import AssessmentBinding, EvidenceIntegrityError
from rhemascript.evidence.assessment_registry import AssessmentRegistry, AssessmentReplayError


class AssessmentRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "assessments.sqlite3"
        self.registry = AssessmentRegistry(self.db)
        self.binding = AssessmentBinding("AS-1", "EV-1", "v1", "a" * 64, 4)

    def tearDown(self):
        self.tmp.cleanup()

    def test_forged_binding_cannot_be_persisted(self):
        from rhemascript.evidence.artifact_verification import AssessmentBinding, EvidenceIntegrityError
        forged = AssessmentBinding("AS-FORGED", "EV-1", "v1", "a" * 64, 4)
        with self.assertRaises(EvidenceIntegrityError):
            self.registry.record(forged)

    def test_persists_exact_binding(self):
        self.assertTrue(self.registry.record(self.binding))
        reopened = AssessmentRegistry(self.db)
        self.assertEqual(reopened.get("AS-1"), self.binding)
        self.assertTrue(reopened.verify())

    def test_identical_replay_is_idempotent(self):
        self.assertTrue(self.registry.record(self.binding))
        self.assertFalse(self.registry.record(self.binding))

    def test_replayed_assessment_id_with_changed_evidence_is_rejected(self):
        self.registry.record(self.binding)
        forged = AssessmentBinding("AS-1", "EV-2", "v1", "b" * 64, 4)
        with self.assertRaises(AssessmentReplayError):
            self.registry.record(forged)

    def test_replayed_assessment_id_with_changed_score_is_rejected(self):
        self.registry.record(self.binding)
        changed = AssessmentBinding("AS-1", "EV-1", "v1", "a" * 64, 2)
        with self.assertRaises(AssessmentReplayError):
            self.registry.record(changed)

    def test_rejects_non_binding(self):
        with self.assertRaises(EvidenceIntegrityError):
            self.registry.record({"status": "VERIFIED"})

    def test_rejects_symlink_database(self):
        link = Path(self.tmp.name) / "alias.sqlite3"
        link.symlink_to(self.db)
        with self.assertRaises(EvidenceIntegrityError):
            AssessmentRegistry(link)


if __name__ == "__main__":
    unittest.main()
