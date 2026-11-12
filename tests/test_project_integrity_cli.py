import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raei.execution.project_integrity_cli import load_record, main
from raei.execution.validate_project_integrity import CHAIN, GATES


def synthetic_record():
    return {
        "record_type": "rhemascript_project_readiness",
        "source_to_final_chain": [
            {"stage": stage, "status": "present", "evidence_ref": f"fixture/{stage}"}
            for stage in CHAIN
        ],
        "approval_gates": [
            {"gate": gate, "decision": "approved",
             "approval_evidence_ref": f"fixture/approval/{gate}",
             "approver": "synthetic-fixture"}
            for gate in GATES
        ],
        "authorities": {
            "generation_authorisation": "not_authorised",
            "publishing_authorisation": "not_authorised",
            "deployment_authorisation": "not_authorised",
            "merge_authorisation": "not_authorised",
        },
        "generation_executed": False,
        "publishing_executed": False,
        "production_authority": "not_granted",
    }


class ProjectIntegrityCliTests(unittest.TestCase):
    def test_valid_synthetic_record_returns_success_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-project.json"
            path.write_text(json.dumps(synthetic_record()), encoding="utf-8")
            with patch("builtins.print") as output:
                code = main([str(path), "--json"])
        self.assertEqual(code, 0)
        report = json.loads(output.call_args.args[0])
        self.assertEqual(report["result"], "PROJECT_TRACEABILITY_COMPLETE")
        self.assertEqual(report["production_authority"], "not_granted")
        self.assertFalse(report["generation_executed"])
        self.assertFalse(report["publishing_executed"])

    def test_incomplete_record_returns_blocked_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incomplete.json"
            path.write_text("{}", encoding="utf-8")
            code = main([str(path)])
        self.assertEqual(code, 1)

    def test_missing_file_returns_invalid_input_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            with patch("sys.stderr"):
                code = main([str(path)])
        self.assertEqual(code, 2)

    def test_invalid_json_reports_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1, column"):
                load_record(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
