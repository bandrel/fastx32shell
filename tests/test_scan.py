"""fastx32shell scan as a child process."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from tests import mocks
from tests.cmd import scan_cmd


def run_scan(*args, timeout=60):
    return subprocess.run(scan_cmd() + list(args), capture_output=True,
                          text=True, timeout=timeout)


class _TmpMixin:
    def tmpdir(self):
        d = tempfile.mkdtemp(prefix="fastx32shell-scan-")
        self.addCleanup(shutil.rmtree, d, True)
        return d


class ScanOffline(_TmpMixin, unittest.TestCase):
    """--build / --build-file: verdicts, exit codes, and --json."""

    def test_build_and_build_file_and_json(self):
        proc = run_scan("--build", "3.1.27")
        self.assertEqual(proc.returncode, 1, "a flagged build must exit 1")
        self.assertIn("read:vulnerable", proc.stdout, "read verdict missing")
        self.assertIn("rce:vulnerable", proc.stdout, "rce verdict missing")
        self.assertIn("confirmed", proc.stdout,
                      "basis missing from the line")

        proc = run_scan("--build", "3.3.71")
        self.assertEqual(proc.returncode, 0, "a clean build must exit 0")
        self.assertIn("clean", proc.stdout, "a clean build must say so")

        proc = run_scan("--build", "3.2.10")
        self.assertEqual(proc.returncode, 1,
                         "an inferred-vulnerable build is still a finding")
        self.assertIn("read:vulnerable (inferred)", proc.stdout,
                      "inferred not shown")
        self.assertIn("rce:unknown (not sampled)", proc.stdout,
                      "gap not shown")

        proc = run_scan("--build", "FastX3 4.0.45-700")
        self.assertIn("fastx4:vulnerable (unverified)", proc.stdout,
                      "FastX 4 line missing or not labelled unverified")

        proc = run_scan("--build", "not-a-version")
        self.assertEqual(proc.returncode, 2, "unparsable input must exit 2")
        self.assertIn("no version", proc.stdout,
                      "unparsable must say no version")
        self.assertIn("unparsable", proc.stdout,
                      "the reason must be named")

        proc = run_scan("--build", "3.3.69", "--json")
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["tool"], "fastx32shell_version_scan", "json tool name")
        host = doc["hosts"][0]
        self.assertEqual(host["build"], "3.3.69", "json build")
        self.assertEqual(host["input"], "3.3.69",
                         "json input echoes what was given")
        found = {f["issue"]: (f["verdict"], f["basis"])
                 for f in host["findings"]}
        self.assertEqual(found["read"], ("vulnerable", "confirmed"),
                         "json read finding")
        from fastx32shell import versions
        self.assertEqual(len(host["findings"]),
                         len(versions.ISSUES),
                         "json must carry every issue, including clean ones")

        path = os.path.join(self.tmpdir(), "builds.txt")
        with open(path, "w", newline="") as fh:
            fh.write("# a comment\r\n\r\n  3.1.27  \r\n3.3.71\r\n")
        proc = run_scan("--build-file", path)
        self.assertEqual(proc.returncode, 1,
                         "one flagged build in a file exits 1")
        self.assertGreaterEqual(proc.stdout.count("\n"), 2,
                                "expected a line per build")

        proc = run_scan("--build", "3.3.71", "--build-file", path)
        self.assertEqual(proc.returncode, 64,
                         "two inputs must be a usage error")
        proc = run_scan()
        self.assertEqual(proc.returncode, 64,
                         "no input must be a usage error")


class ScanFetch(unittest.TestCase):
    """--base: pulling result.build out of whatever the endpoint answers."""

    def check_mode(self, mode, expect_code, needle):
        mock = mocks.ApiMock(mode=mode)
        srv, port = mocks.serve(mocks.api_handler(mock))
        self.addCleanup(mocks.stop, srv)
        proc = run_scan("--base", "http://127.0.0.1:%d" % port,
                        "--timeout", "5")
        self.assertEqual(proc.returncode, expect_code,
                         "%s: expected exit %d, got %d\n%s"
                         % (mode, expect_code, proc.returncode, proc.stderr))
        self.assertIn(needle, proc.stdout,
                      "%s: expected %r in output" % (mode, needle))
        self.assertEqual(mock.hits, 1,
                         "%s: expected one request, saw %d"
                         % (mode, mock.hits))
        self.assertTrue("\x1b" not in proc.stdout
                        and "\x07" not in proc.stdout,
                        "%s: an escape sequence from the target reached "
                        "stdout" % mode)
        self.assertLess(max((len(line) for line in proc.stdout.splitlines()),
                            default=0), 200,
                        "%s: a 400-byte build string was echoed unbounded"
                        % mode)

    def test_nested(self):
        self.check_mode("nested", 1, "3.3.69")

    def test_toplevel(self):
        self.check_mode("toplevel", 1, "3.1.27")

    def test_html(self):
        self.check_mode("html", 1, "3.2.60")

    def test_absent(self):
        self.check_mode("absent", 2, "no build key")

    def test_auth(self):
        self.check_mode("auth", 2, "http 401")

    def test_missing(self):
        self.check_mode("missing", 2, "http 404")

    def test_redirect(self):
        self.check_mode("redirect", 2, "http 302")

    def test_garbage(self):
        self.check_mode("garbage", 2, "no build key")

    def test_bogus(self):
        self.check_mode("bogus", 2, "unparsable")

    def test_hostile(self):
        self.check_mode("hostile", 1, "3.3.69")

    def test_long(self):
        self.check_mode("long", 1, "3.3.69")

    def test_dead_host_is_a_transport_error(self):
        proc = run_scan("--base", "http://127.0.0.1:1", "--timeout", "1")
        self.assertEqual(proc.returncode, 4,
                         "a dead host must exit 4, got %d" % proc.returncode)
        self.assertIn("transport", proc.stdout,
                      "a dead host must say transport")


class ScanBaseFile(_TmpMixin, unittest.TestCase):
    """--base-file: one line per host, and a bad host must not end the
    sweep."""

    def test_sweep_does_not_abort_on_failure(self):
        servers = []
        ports = []
        for mode in ("nested", "toplevel", "auth"):
            # nested -> 3.3.69, toplevel -> 3.1.27 (still flagged), and auth
            # refuses the endpoint.
            srv, port = mocks.serve(mocks.api_handler(mocks.ApiMock(mode=mode)))
            self.addCleanup(mocks.stop, srv)
            ports.append(port)
        gport, cport, rport = ports
        d = self.tmpdir()
        # The mocks speak plain HTTP, so the answerable lines carry a scheme.
        # The bare line is checked on a dead port: a bare host normalises to
        # https:// and cannot reach a plain-HTTP mock, and that is the
        # normalisation being pinned, not the fetch.
        path = os.path.join(d, "hosts.txt")
        with open(path, "w", newline="") as fh:
            fh.write("# scope\r\n"
                     "\r\n"
                     "http://127.0.0.1:%d\r\n"    # nested    -> 3.3.69
                     "  http://127.0.0.1:%d/  \r\n"  # toplevel -> 3.1.27
                     "http://127.0.0.1:%d\r\n"    # refuses the endpoint
                     "http://127.0.0.1:1\r\n"     # nothing listening
                     "127.0.0.1:1\r\n"            # bare -> normalised to https
                     % (gport, cport, rport))
        proc = run_scan("--base-file", path, "--timeout", "2", timeout=120)
        self.assertEqual(proc.returncode, 1,
                         "two flagged hosts in a mixed sweep exit 1, got %d"
                         % proc.returncode)
        self.assertIn("3.3.69", proc.stdout, "first host's build missing")
        self.assertIn("3.1.27", proc.stdout, "second host's build missing")
        self.assertIn("http 401", proc.stdout,
                      "refusal not reported distinctly")
        self.assertGreaterEqual(proc.stdout.count("transport"), 2,
                                "both unreachable hosts must be reported, "
                                "not just the last")
        self.assertGreaterEqual(proc.stdout.count("127.0.0.1"), 5,
                                "expected a line per host, dead ones "
                                "included")
        self.assertIn("5 hosts", proc.stdout, "summary line missing")

        empty = os.path.join(d, "empty.txt")
        with open(empty, "w") as fh:
            fh.write("# nothing here\n\n")
        proc = run_scan("--base-file", empty)
        self.assertEqual(proc.returncode, 64,
                         "a list with no hosts is a usage error, got %d"
                         % proc.returncode)

        dead = os.path.join(d, "dead.txt")
        with open(dead, "w") as fh:
            fh.write("http://127.0.0.1:1\nhttp://127.0.0.1:1\n")
        proc = run_scan("--base-file", dead, "--timeout", "1")
        self.assertEqual(proc.returncode, 4,
                         "every host unreachable exits 4, got %d"
                         % proc.returncode)

        proc = run_scan("--base-file", path, "--json", "--timeout", "2",
                        timeout=120)
        doc = json.loads(proc.stdout)
        self.assertEqual(len(doc["hosts"]), 5,
                         "json must carry one object per host")
        self.assertEqual(doc["hosts"][2]["error"], "http 401",
                         "json error text")
        self.assertEqual(doc["hosts"][4]["input"], "https://127.0.0.1:1",
                         "a bare host must be normalised with https://")
        self.assertEqual(doc["hosts"][1]["input"],
                         "http://127.0.0.1:%d" % cport,
                         "a trailing slash must be trimmed")
