import json
import unittest
from pathlib import Path

from rhemascript.evidence import validate_evidence_pack

ROOT = Path(__file__).resolve().parents[1]

class CanonicalManifestTemplateTests(unittest.TestCase):
    def test_canonical_template_loads_and_passes_runtime_validator(self):
        template_path = ROOT / "templates" / "project-evidence-pack-v1.template.json"
        schema_path = ROOT / "schemas" / "project-evidence-pack-v1.schema.json"
        manifest = json.loads(template_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], manifest["schema_version"])
        validated = validate_evidence_pack(manifest)
        self.assertEqual(validated.project_id, "RS-PROJECT-001")
        self.assertEqual(validated.project_version, "1.0")
        self.assertEqual(validated.artifacts, ())
        self.assertEqual(validated.evidence_records, ())
        self.assertEqual(validated.gate_records, ())

    def test_schema_declares_analytics_artifact_types_and_digest_requirements(self):
        schema = json.loads(
            (ROOT / "schemas" / "project-evidence-pack-v1.schema.json").read_text(encoding="utf-8")
        )
        artifact_schema = schema["properties"]["artifacts"]["items"]
        allowed = artifact_schema["properties"]["artifact_type"]["enum"]
        self.assertIn("YOUTUBE_ANALYTICS_SNAPSHOT", allowed)
        self.assertIn("YOUTUBE_ANALYTICS_COMPARISON", allowed)
        rules = artifact_schema["allOf"]
        snapshot_rule = next(
            rule for rule in rules
            if rule.get("if", {}).get("properties", {}).get("artifact_type", {}).get("const")
            == "YOUTUBE_ANALYTICS_SNAPSHOT"
        )
        comparison_rule = next(
            rule for rule in rules
            if rule.get("if", {}).get("properties", {}).get("artifact_type", {}).get("const")
            == "YOUTUBE_ANALYTICS_COMPARISON"
        )
        self.assertIn("snapshot_sha256", snapshot_rule["then"]["required"])
        self.assertIn("comparison_sha256", comparison_rule["then"]["required"])
        self.assertIn("current_snapshot_artifact_id", comparison_rule["then"]["required"])
        self.assertIn("previous_snapshot_artifact_id", comparison_rule["then"]["required"])
        self.assertIn("current_snapshot_sha256", comparison_rule["then"]["required"])
        self.assertIn("previous_snapshot_sha256", comparison_rule["then"]["required"])

    def test_template_is_intentionally_not_generation_authorisation(self):
        manifest = json.loads((ROOT / "templates" / "project-evidence-pack-v1.template.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["gate_records"], [])
        self.assertNotIn("generation_authorisation", manifest)

if __name__ == "__main__":
    unittest.main()
