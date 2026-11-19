"""The public name, pinned: --help, subcommand usage, --version, and the
scan JSON tool field all say fastx32shell, and no fastx package remains."""
import json
import os
import subprocess
import sys
import unittest

from tests.cmd import ROOT

NAME = "fastx32shell"


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", NAME] + list(args),
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, PYTHONPATH=ROOT))


class PublicName(unittest.TestCase):
    def test_help_usage_line_names_the_tool(self):
        proc = run("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.startswith("usage: fastx32shell"),
                        proc.stdout.splitlines()[0])

    def test_subcommand_usage_line_names_the_tool(self):
        proc = run("scan", "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage: fastx32shell scan", proc.stdout)

    def test_version_comes_from_the_package(self):
        from fastx32shell import VERSION
        proc = run("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), VERSION)

    def test_the_old_package_directory_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(ROOT, "fastx")))

    def test_json_tool_field_names_the_new_package(self):
        proc = run("scan", "--build", "3.3.69", "--json")
        # 3.3.69 is vulnerable, so scan exits 1 by contract: the JSON still
        # lands on stdout.
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["tool"],
                         "fastx32shell_version_scan")

    def test_subcommand_help_examples_use_the_new_name(self):
        # forge takes a key, not a base URL, so it is pinned separately.
        examples = {"read": "--base", "rce": "--base",
                    "scan": "--base", "forge": "-k"}
        for name, flag in examples.items():
            proc = run(name, "--help")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("fastx32shell %s %s" % (name, flag), proc.stdout,
                          "%s --help must show a %s example" % (name, NAME))
            self.assertNotIn("    fastx %s " % name, proc.stdout,
                             "%s --help still shows an old-name example"
                             % name)
