import os
import stat
import tempfile
import unittest
from pathlib import Path

from ci.validate_if18_read_only import write_report


class ValidationReportWriterTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("secure report creation requires POSIX O_NOFOLLOW")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)

    def test_creates_owner_only_report(self):
        report = self.root / "report.json"
        write_report(report, '{"overall_status":"PASS"}\n')
        self.assertEqual(report.read_text(), '{"overall_status":"PASS"}\n')
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(report.stat().st_uid, os.getuid())

    def test_refuses_symlink_without_touching_target(self):
        target = self.root / "target.json"
        target.write_text("do not change")
        link = self.root / "report.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            write_report(link, '{"overall_status":"PASS"}\n')
        self.assertEqual(target.read_text(), "do not change")

    def test_refuses_missing_parent(self):
        with self.assertRaises(OSError):
            write_report(self.root / "missing" / "report.json", "{}\n")


if __name__ == "__main__":
    unittest.main()
