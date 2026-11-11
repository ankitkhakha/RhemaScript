import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raei.execution.project_integrity_cli import load_record, main
from tests.test_project_integrity import ready_project


class ProjectIntegrityCliTests(unittest.TestCase):
    def test_valid_synthetic_record_returns_success_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-project.json"
            path.write_text(json.dumps(ready_project()), encoding="utf-8")
            with patch("builtins.print") as output:
                code = main([str(path), "--json"])
        self.assertEqual(code, 0)
        rendered = output.call_args.args[0]
        report = json.loads(rendered)
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
