"""Guard the remote event-triggered CI workflow contract."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RemoteCIWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    def test_push_event_is_enabled(self):
        self.assertRegex(self.workflow, r"(?m)^  push:\s*$")

    def test_pull_request_event_is_enabled(self):
        self.assertRegex(self.workflow, r"(?m)^  pull_request:\s*$")

    def test_manual_dispatch_is_enabled(self):
        self.assertRegex(self.workflow, r"(?m)^  workflow_dispatch:\s*$")

    def test_least_privilege_permissions(self):
        self.assertRegex(self.workflow, r"(?ms)^permissions:\s*\n\s+contents:\s*read\s*$")

    def test_if18_validation_harness_is_invoked(self):
        self.assertIn(
            ".venv/bin/python ci/validate_if18_read_only.py --report-file if18-validation-report.json",
            self.workflow,
        )

    def test_job_has_timeout(self):
        self.assertRegex(self.workflow, r"(?m)^    timeout-minutes: 10$")

    def test_test_job_waits_for_generated_lock(self):
        self.assertRegex(self.workflow, r"(?ms)^  test:\n    needs: generate-lock-candidate$")

    def test_clean_environment_uses_hash_locked_dependencies(self):
        self.assertIn("--require-hashes -r lock-candidate/requirements-ci.lock", self.workflow)
        self.assertIn("sha256sum --check requirements-ci.lock.sha256", self.workflow)
        self.assertIn("--no-deps --no-build-isolation -e .", self.workflow)
        self.assertIn(".venv/bin/python -m pip check", self.workflow)


if __name__ == "__main__":
    unittest.main()
