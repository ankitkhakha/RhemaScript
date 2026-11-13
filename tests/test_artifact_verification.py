import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rhemascript.evidence.artifact_verification import (
    AssessmentBinding, EvidenceIntegrityError, EvidenceVersion, IntegrityLedger,
    bind_assessment, verify_artifact, verify_assessment_binding,
)


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "proof.txt").write_text("approved evidence", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self):
        return verify_artifact(self.root, "proof.txt", evidence_id="EV-1", version="v1")

    def test_verifies_existing_file_and_digest(self):
        item = self.verify()
        self.assertEqual(item.sha256, __import__("hashlib").sha256(b"approved evidence").hexdigest())
        self.assertEqual(item.size_bytes, len(b"approved evidence"))

    def test_missing_artifact_rejected(self):
        with self.assertRaises(EvidenceIntegrityError):
            verify_artifact(self.root, "missing", evidence_id="EV-1", version="v1")

    def test_path_traversal_rejected(self):
        with self.assertRaises(EvidenceIntegrityError):
            verify_artifact(self.root, "../outside", evidence_id="EV-1", version="v1")

    def test_empty_normalized_path_rejected(self):
        with self.assertRaises(EvidenceIntegrityError):
            verify_artifact(self.root, ".", evidence_id="EV-1", version="v1")

    def test_intermediate_symlink_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "proof.txt").write_text("outside", encoding="utf-8")
        (self.root / "linked-dir").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(EvidenceIntegrityError):
            verify_artifact(self.root, "linked-dir/proof.txt", evidence_id="EV-1", version="v1")

    def test_symlink_rejected(self):
        target = self.root / "outside.txt"
        target.write_text("outside", encoding="utf-8")
        link = self.root / "link.txt"
        link.symlink_to(target)
        with self.assertRaises(EvidenceIntegrityError):
            verify_artifact(self.root, "link.txt", evidence_id="EV-1", version="v1")

    def test_assessment_bound_to_exact_digest_and_version(self):
        evidence = self.verify()
        assessment = bind_assessment("AS-1", evidence, 4)
        self.assertTrue(verify_assessment_binding(assessment, evidence))
        (self.root / "proof.txt").write_text("changed evidence", encoding="utf-8")
        changed = self.verify()
        self.assertFalse(verify_assessment_binding(assessment, changed))
        newer = verify_artifact(self.root, "proof.txt", evidence_id="EV-1", version="v2")
        self.assertFalse(verify_assessment_binding(assessment, newer))

    def test_forged_evidence_dataclass_cannot_be_assessed(self):
        forged = EvidenceVersion("EV-1", "proof.txt", "v1", "a" * 64, 10)
        with self.assertRaises(EvidenceIntegrityError):
            bind_assessment("AS-1", forged, 4)

    def test_forged_assessment_binding_cannot_verify(self):
        evidence = self.verify()
        forged = AssessmentBinding("AS-1", "EV-1", "v1", evidence.sha256, 4)
        self.assertFalse(verify_assessment_binding(forged, evidence))

    def test_dataclass_copy_cannot_forge_verified_evidence(self):
        verified = self.verify()
        copied = replace(verified, sha256="a" * 64)
        with self.assertRaises(EvidenceIntegrityError):
            bind_assessment("AS-COPY", copied, 4)

    def test_dataclass_copy_cannot_forge_assessment_binding(self):
        evidence = self.verify()
        binding = bind_assessment("AS-1", evidence, 4)
        copied = replace(binding, evidence_sha256="a" * 64)
        self.assertFalse(verify_assessment_binding(copied, evidence))

    def test_forged_string_status_cannot_be_assessed(self):
        with self.assertRaises(EvidenceIntegrityError):
            bind_assessment("AS-1", {"status": "VERIFIED", "ref": "anything"}, 4)

    def test_invalid_score_rejected(self):
        with self.assertRaises(EvidenceIntegrityError):
            bind_assessment("AS-1", self.verify(), 5)

    def test_ledger_detects_rewritten_history(self):
        ledger = IntegrityLedger()
        ledger.append({"action": "verify", "evidence_id": "EV-1"})
        self.assertTrue(ledger.verify())
        ledger._events[0]["payload"]["evidence_id"] = "EV-FORGED"
        self.assertFalse(ledger.verify())

    def test_ledger_detaches_nested_caller_and_reader_values(self):
        ledger = IntegrityLedger()
        original = {"action": "verify", "details": {"evidence_id": "EV-1"}}
        ledger.append(original)
        original["details"]["evidence_id"] = "EV-FORGED"
        self.assertTrue(ledger.verify())
        exposed = ledger.events
        exposed[0]["payload"]["details"]["evidence_id"] = "EV-ALTERED"
        self.assertTrue(ledger.verify())
        self.assertEqual(ledger.events[0]["payload"]["details"]["evidence_id"], "EV-1")

    def test_ledger_rejects_non_finite_numbers(self):
        ledger = IntegrityLedger()
        with self.assertRaises(EvidenceIntegrityError):
            ledger.append({"score": float("nan")})

    def test_checkpoint_detects_rewrite_replay_and_wrong_key(self):
        key = b"k" * 32
        ledger = IntegrityLedger()
        ledger.append({"action": "assessment", "id": "AS-1"})
        checkpoint = ledger.checkpoint(key)
        self.assertTrue(ledger.verify_checkpoint(checkpoint, key))
        self.assertFalse(ledger.verify_checkpoint(checkpoint, b"x" * 32))
        ledger.append({"action": "assessment", "id": "AS-2"})
        self.assertFalse(ledger.verify_checkpoint(checkpoint, key))
        checkpoint["sequence"] = 2
        self.assertFalse(ledger.verify_checkpoint(checkpoint, key))

    def test_checkpoint_rejects_short_key(self):
        with self.assertRaises(EvidenceIntegrityError):
            IntegrityLedger().checkpoint(b"short")


if __name__ == "__main__":
    unittest.main()
