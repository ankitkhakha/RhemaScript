import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from raei.cli import main


class RAEICLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        os.chmod(self.private, 0o700)
        self.database = self.private / "learning.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(list(args))
        return code, output.getvalue(), errors.getvalue()

    def test_init_creates_private_registry(self):
        code, output, errors = self.run_cli("init", "--database", str(self.database))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["status"], "INITIALIZED")
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)

    def test_init_refuses_existing_database(self):
        self.run_cli("init", "--database", str(self.database))
        code, _, errors = self.run_cli("init", "--database", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("already exists", errors)

    def test_status_requires_existing_database(self):
        code, _, errors = self.run_cli("status", "--database", str(self.database))
        self.assertEqual(code, 2)
        self.assertIn("does not exist", errors)

    def test_status_and_next_after_initialization(self):
        self.run_cli("init", "--database", str(self.database))
        code, output, errors = self.run_cli("status", "--database", str(self.database))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["recorded_units"], 0)
        code, output, errors = self.run_cli("next", "--database", str(self.database))
        self.assertEqual(code, 0, errors)
        self.assertIsNotNone(json.loads(output))

    def test_registry_path_symlink_is_rejected(self):
        self.run_cli("init", "--database", str(self.database))
        link = self.private / "link.sqlite3"
        link.symlink_to(self.database)
        code, _, errors = self.run_cli("status", "--database", str(link))
        self.assertEqual(code, 2)
        self.assertIn("symlink", errors)

    def test_private_parent_is_required(self):
        public = self.root / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        code, _, errors = self.run_cli("init", "--database", str(public / "learning.sqlite3"))
        self.assertEqual(code, 2)
        self.assertIn("private", errors)


if __name__ == "__main__":
    unittest.main()
