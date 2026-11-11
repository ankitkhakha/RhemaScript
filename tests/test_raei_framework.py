"""Structural and governance contract tests for RAEI's versioned framework."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

class RAEIFrameworkTests(unittest.TestCase):
    def read_doc(self, name):
        path = DOCS / name
        self.assertTrue(path.is_file(), f"Missing RAEI document: {name}")
        content = path.read_text(encoding="utf-8")
        self.assertIn("V1.0", content)
        return content

    def test_all_versioned_documents_exist(self):
        for name in (
            "RAEI_ENGINEERING_CONSTITUTION_V1.md",
            "RAEI_EDUCATION_FRAMEWORK_V1.md",
            "RAEI_COMPETENCY_AND_EVALUATION_V1.md",
            "RAEI_ACTIVATION_AND_GOVERNANCE_V1.md",
        ):
            self.read_doc(name)

    def test_constitution_preserves_gates_and_authority_separation(self):
        text = self.read_doc("RAEI_ENGINEERING_CONSTITUTION_V1.md")
        for phrase in (
            "Project/Creative Direction", "Script/Biblical Accuracy",
            "Visual Development", "Production Plan/Prompt",
            "Generation Authorisation", "Final Film",
            "approval, execution authorisation, final acceptance",
            "Human Director", "ACTIVATE RAEI", "unhackable",
        ):
            self.assertIn(phrase, text)

    def test_education_is_progressive_and_competency_based(self):
        text = self.read_doc("RAEI_EDUCATION_FRAMEWORK_V1.md")
        for level in range(7):
            self.assertIn(f"Level {level}", text)
        for phrase in ("prerequisite diagnostic", "Independent practice",
                       "assessment", "retention check", "Capstone"):
            self.assertIn(phrase.lower(), text.lower())

    def test_evaluation_has_critical_failure_and_evidence_requirements(self):
        text = self.read_doc("RAEI_COMPETENCY_AND_EVALUATION_V1.md")
        self.assertIn("automatic failure", text)
        self.assertIn("Evidence record", text)
        self.assertIn("INDEPENDENTLY_REVIEWED", text)

    def test_activation_does_not_grant_permissions(self):
        text = self.read_doc("RAEI_ACTIVATION_AND_GOVERNANCE_V1.md")
        self.assertIn("Activation is not an authorisation token", text)
        self.assertIn("DEACTIVATE RAEI", text)

if __name__ == "__main__":
    unittest.main()
