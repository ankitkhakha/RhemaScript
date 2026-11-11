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

    def test_template_is_intentionally_not_generation_authorisation(self):
        manifest = json.loads((ROOT / "templates" / "project-evidence-pack-v1.template.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["gate_records"], [])
        self.assertNotIn("generation_authorisation", manifest)

if __name__ == "__main__":
    unittest.main()
