"""fastx32shell read against the /error/assets mock."""
import os
import shutil
import subprocess
import tempfile
import unittest

from tests import mocks
from tests.cmd import read_cmd


class ReadForms(unittest.TestCase):
    def run_read(self, mode, extra=(), outdir=None):
        mock = mocks.ReadMock(mode=mode)
        srv, port = mocks.serve(mocks.read_handler(mock))
        self.addCleanup(mocks.stop, srv)
        args = read_cmd() + ["--base", "http://127.0.0.1:%d" % port,
                             "--file", "/etc/passwd", "--timeout", "5"]
        args += list(extra)
        if outdir is not None:
            args += ["--outdir", outdir]
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=60)

    def test_absolute_form_preferred(self):
        proc = self.run_read("both")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("absolute", proc.stdout)
        self.assertIn("root:x:0:0", proc.stdout,
                      "file content was not previewed")

    def test_falls_back_to_relative(self):
        proc = self.run_read("relative_only")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("relative/", proc.stdout)
        self.assertIn("root:x:0:0", proc.stdout,
                      "file content was not previewed")

    def test_400_on_relative_is_survivable(self):
        proc = self.run_read("absolute_only")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("absolute", proc.stdout)
        self.assertIn("root:x:0:0", proc.stdout,
                      "file content was not previewed")

    def test_empty_200_is_no_read(self):
        """The 3.3.71 allowlist answers an empty 200; that is not a read."""
        proc = self.run_read("patched")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("NO READ", proc.stdout,
                      "an empty 200 should report NO READ, not a "
                      "successful read")

    def test_outdir_writes_the_body(self):
        tmp = tempfile.mkdtemp(prefix="fastx32shell-test-")
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = self.run_read("both", outdir=tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("root:x:0:0", proc.stdout,
                      "file content was not previewed")
        dest = os.path.join(tmp, "etc_passwd")
        self.assertTrue(os.path.exists(dest), "no file written to --outdir")
        with open(dest) as fh:
            self.assertEqual(fh.read(), mocks.VFS["/etc/passwd"],
                             "saved file does not match the served content")

    def test_check_reports_a_verdict(self):
        proc = self.run_read("both", extra=["--check"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("verdict", proc.stdout)
        self.assertIn("root:x:0:0", proc.stdout,
                      "file content was not previewed")
