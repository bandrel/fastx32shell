"""fastx32shell rce against the /gritty mock, as a child process."""
import os
import select
import signal
import subprocess
import time
import unittest

from tests import mocks
from tests.cmd import rce_cmd


class Rce(unittest.TestCase):
    CMD = "echo uid=1000(tester); printf 'space and semicolon survive'\n"

    def run_rce(self, mode, dry_run=False, auth=None):
        mock = mocks.GrittyMock(mode=mode)
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        self.addCleanup(mocks.stop, srv)
        args = rce_cmd() + ["--base", "http://127.0.0.1:%d" % port,
                            "--cmd", self.CMD, "--timeout", "3",
                            "--accept-timeout", "3", "--run-timeout", "5",
                            "--dry-run-timeout", "3"]
        if dry_run:
            args.append("--dry-run")
        if auth is not None:
            args += ["--auth", auth]
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=60)
        return mock, proc

    def test_accept_runs_command(self):
        mock, proc = self.run_rce("accept")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIsNotNone(mock.terminal_params,
                             "server never received a terminal event")
        self.assertEqual(mock.terminal_params.get("command"), self.CMD,
                         "command altered in transit")
        self.assertIs(mock.terminal_params.get("autoRestart"), False,
                      "autoRestart should be false")
        self.assertIn("uid=1000(tester)", proc.stdout,
                      "command output not printed")
        self.assertTrue(any(p.startswith("41") for p in mock.received),
                        "client never sent a disconnect packet")

    def test_dry_run_stops_at_accept(self):
        mock, proc = self.run_rce("accept", dry_run=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIsNone(mock.terminal_params,
                          "--dry-run sent a terminal event anyway")

    def test_reject_is_auth_enforced(self):
        mock, proc = self.run_rce("reject")
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_non_eio_body_is_no_surface(self):
        mock, proc = self.run_rce("nohandshake")
        self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_malformed_handshake_is_no_surface(self):
        mock, proc = self.run_rce("badjson")
        self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_auth_gate_alone_does_not_prove_enforcement(self):
        """Silence after connect is not proof that credentials are checked.

        An auth handler that accepts anything looks exactly like one that
        checks, until the `auth` event is actually sent. Exit 2 stands, but
        the wording must not claim enforcement it has not observed, and it
        must point at the flag that settles the question.
        """
        mock, proc = self.run_rce("authgate")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIsNone(mock.auth_received,
                          "an `auth` event was sent without --auth")
        self.assertIn("--auth", proc.stdout,
                      "exit 2 did not point at the flag that settles it")
        self.assertNotIn("auth is enforced here", proc.stdout,
                         "claimed enforcement it never tested")

    def test_auth_flag_passes_an_accept_anything_gate(self):
        """A gate is wired but accepts any credentials."""
        mock, proc = self.run_rce("authgate", auth="anything:atall")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(mock.auth_received, ["anything", "atall"],
                         "credentials not sent as two positional arguments")
        self.assertIn("uid=1000(tester)", proc.stdout,
                      "command did not run after the gate accepted")

    def test_auth_flag_sends_the_credentials_given(self):
        mock, proc = self.run_rce("authgate_strict", auth="user:pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(mock.auth_received, ["user", "pass"])

    def test_wrong_credentials_are_still_exit_2(self):
        """A gate that really checks must not be reported as passable."""
        mock, proc = self.run_rce("authgate_strict", auth="wrong:creds")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIsNone(mock.terminal_params,
                          "a command was sent after `reject`")

    def test_auth_without_a_colon_is_the_whole_username(self):
        mock, proc = self.run_rce("authgate", auth="justuser")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(mock.auth_received, ["justuser", ""])

    def test_invalid_namespace_is_no_surface(self):
        """An unregistered namespace is "nothing mounted here", not "auth".

        gritty mounts exactly one namespace: `socket.of(prefix || '/gritty')`.
        A deployment that sets a custom `prefix` leaves nothing at `/gritty`,
        and the connect draws a Socket.IO ERROR packet. Reporting that as 2
        would claim an auth handler the target does not have.
        """
        mock, proc = self.run_rce("badnamespace")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("Invalid namespace", proc.stdout,
                      "the server's reason was not surfaced")
        self.assertNotIn("auth is enforced", proc.stdout,
                         "an absent namespace was reported as auth enforcement")

    def test_invalid_namespace_v4_shape_is_no_surface(self):
        """The verdict must not depend on the ERROR packet's payload shape."""
        mock, proc = self.run_rce("badnamespace_v4")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertNotIn("auth is enforced", proc.stdout,
                         "an absent namespace was reported as auth enforcement")

    def test_invalid_namespace_reason_is_sanitized(self):
        """The reason text is the target's to choose, so it is not printed raw."""
        mock, proc = self.run_rce("badnamespace_hostile")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertNotIn("\x1b", proc.stdout, "ANSI escape reached the terminal")
        self.assertNotIn("\x07", proc.stdout, "BEL reached the terminal")

    def test_nothing_listening_is_no_surface(self):
        """Nothing listening at all: a transport failure, not a live
        surface."""
        proc = subprocess.run(
            rce_cmd() + ["--base", "http://127.0.0.1:1", "--timeout", "1"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 3, proc.stderr)


class Interactive(unittest.TestCase):
    def run_interactive(self, stdin_text, expect_code=0, extra=(),
                        expect_cmd="bash", expect_stdout="OUT: ",
                        expect_err=None):
        mock = mocks.GrittyMock(mode="interactive")
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        self.addCleanup(mocks.stop, srv)
        args = rce_cmd() + ["--base", "http://127.0.0.1:%d" % port,
                            "--timeout", "3", "--accept-timeout", "3",
                            "-i"] + list(extra)
        t0 = time.time()
        proc = subprocess.run(args, input=stdin_text, capture_output=True,
                              text=True, timeout=60)
        elapsed = time.time() - t0
        self.assertEqual(proc.returncode, expect_code, proc.stderr)
        if expect_cmd is not None:
            self.assertIsNotNone(mock.terminal_params,
                                 "no terminal event received")
            self.assertEqual(mock.terminal_params.get("command"), expect_cmd,
                             "wrong command spawned")
            self.assertIs(mock.terminal_params.get("autoRestart"), False,
                          "autoRestart should be false")
            self.assertGreater(mock.terminal_params.get("cols", 0), 0,
                               "no terminal size sent")
        if expect_stdout:
            self.assertIn(expect_stdout, proc.stdout,
                          "remote output not streamed to stdout")
            self.assertTrue(any(p.startswith("41") for p in mock.received),
                            "client never sent a disconnect packet")
            if stdin_text.strip():
                first = stdin_text.splitlines()[0] + "\n"
                self.assertIn(first, mock.data_received,
                              "typed line was not forwarded")
        if expect_err:
            self.assertIn(expect_err, proc.stderr,
                          "expected %r on stderr" % expect_err)
        self.assertNotIn("--- command output ---", proc.stdout,
                         "interactive mode printed the one-shot banner")
        self.assertLess(elapsed, 20,
                        "session took %.1fs; EOF/exit is not prompt"
                        % elapsed)
        return mock, proc

    def test_streams_remote_output(self):
        self.run_interactive("whoami\n")

    def test_last_line_without_newline_runs(self):
        self.run_interactive("whoami")

    def test_eof_closes_session(self):
        self.run_interactive("")

    def test_remote_exit_ends_session(self):
        self.run_interactive("exit\n")

    def test_cmd_names_the_program(self):
        self.run_interactive("", expect_cmd="/bin/sh",
                             extra=["--cmd", "/bin/sh"])

    def test_dry_run_is_usage_error(self):
        self.run_interactive("whoami\n", expect_code=64, expect_cmd=None,
                             expect_stdout=None, extra=["--dry-run"],
                             expect_err="cannot be combined with")


def _read_until(fd, needle, deadline):
    """Read from a pty master until `needle` shows up or the deadline passes."""
    out = b""
    while needle not in out and time.time() < deadline:
        r, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
        if not r:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    return out


def _drain(fd, seconds=1.0):
    """Collect whatever a pty master still has, without blocking."""
    out = b""
    deadline = time.time() + seconds
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if not r:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    return out


def _run_tool_on_pty(port, master, slave):
    return subprocess.Popen(
        rce_cmd() + ["--base", "http://127.0.0.1:%d" % port,
                     "--timeout", "3", "--accept-timeout", "3", "-i"],
        stdin=slave, stdout=slave, stderr=subprocess.DEVNULL)


class Pty(unittest.TestCase):
    def run_password_pty(self, mode="password", secret=True):
        """Type a secret into a real pty: it must reach the target, never the
        screen, and the terminal must come back with echo on."""
        import pty
        mock = mocks.GrittyMock(mode=mode)
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        master, slave = pty.openpty()
        proc = None
        try:
            proc = _run_tool_on_pty(port, master, slave)
            seen = _read_until(master, b"Password: ", time.time() + 20)
            self.assertIn(b"Password: ", seen, "prompt was not printed")
            if secret:
                os.write(master, b"hunter2\n")
            proc.wait(timeout=20)
            seen += _drain(master)
            if secret:
                self.assertNotIn(b"hunter2", seen,
                                 "the typed password was echoed to the "
                                 "terminal")
                self.assertIn("hunter2\n", mock.data_received,
                              "the password never reached the target: %r"
                              % mock.data_received)
            self.assertTrue(mocks.echo_enabled(slave),
                            "terminal left with echo off after the session")
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()
            mocks.stop(srv)
            os.close(master)
            os.close(slave)

    def test_password_is_not_echoed(self):
        self.run_password_pty()

    def test_echo_restored_on_transport_error(self):
        self.run_password_pty(mode="password_then_error", secret=False)

    def test_ordinary_line_is_still_shown(self):
        """An ordinary line typed in a tty session is forwarded once and its
        remote output printed; the mute must not eat it."""
        import pty
        mock = mocks.GrittyMock(mode="interactive")
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        master, slave = pty.openpty()
        proc = None
        try:
            proc = _run_tool_on_pty(port, master, slave)
            time.sleep(1.0)
            os.write(master, b"whoami\n")
            seen = _read_until(master, b"OUT: whoami", time.time() + 20)
            self.assertIn(b"OUT: whoami", seen, "remote output was swallowed")
            self.assertTrue(
                mock.data_received and mock.data_received[0] == "whoami\n",
                "line not forwarded exactly once: %r" % mock.data_received)
            self.assertTrue(mocks.echo_enabled(slave),
                            "terminal left with echo off")
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()
            mocks.stop(srv)
            os.close(master)
            os.close(slave)

    def test_echo_restored_after_sigint(self):
        """Ctrl-C while local echo is muted must hand the terminal back."""
        import pty
        mock = mocks.GrittyMock(mode="password_idle")
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        master, slave = pty.openpty()
        proc = None
        try:
            proc = _run_tool_on_pty(port, master, slave)
            seen = _read_until(master, b"Password: ", time.time() + 20)
            self.assertIn(b"Password: ", seen, "prompt was not printed")
            time.sleep(0.3)
            self.assertFalse(mocks.echo_enabled(slave),
                             "prompt did not mute local echo")
            proc.send_signal(signal.SIGINT)
            deadline = time.time() + 10
            while not mocks.echo_enabled(slave) and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(mocks.echo_enabled(slave),
                            "Ctrl-C left the terminal with echo off")
            self.assertIn("\x03", mock.data_received,
                          "Ctrl-C was not forwarded as \\x03: %r"
                          % mock.data_received)
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()
            mocks.stop(srv)
            os.close(master)
            os.close(slave)


class Keepalive(unittest.TestCase):
    """Engine.IO v3 puts the ping on the client. A tool that only answers
    pings never sends one, and the server reaps the session mid-session."""

    def test_mock_reaps_an_unpinged_session(self):
        """The guard itself has to bite, or the test below proves nothing."""
        mock = mocks.GrittyMock(mode="interactive", ping_interval=200,
                                ping_timeout=100, enforce_ping=True)
        sid = mock.new_session()
        self.assertFalse(mock.expired(sid), "expired inside its budget")
        time.sleep(0.5)
        self.assertTrue(mock.expired(sid), "unpinged session was not reaped")

    def test_session_survives_past_the_ping_budget(self):
        mock = mocks.GrittyMock(mode="interactive", ping_interval=2000,
                                ping_timeout=500, enforce_ping=True,
                                server_pings=False)
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        proc = subprocess.Popen(
            rce_cmd() + ["--base", "http://127.0.0.1:%d" % port,
                         "--timeout", "10", "--accept-timeout", "10", "-i"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            # Idle well past pingInterval + pingTimeout, then speak again.
            time.sleep(4.0)
            proc.stdin.write("whoami\n")
            proc.stdin.flush()
            time.sleep(1.5)             # let the reply land before EOF
            out, _ = proc.communicate("exit\n", timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            mocks.stop(srv)
        self.assertNotIn("Session ID unknown", out,
                         "the session was reaped: the client never pinged")
        self.assertIn("OUT: whoami", out,
                      "no remote output after idling past the budget: %r" % out)
        self.assertGreater(mock.pings, 0, "no client ping was ever sent")
        self.assertEqual(mock.reaped, [], "server reaped the session")


class SigintSurvival(unittest.TestCase):
    def test_sigint_does_not_end_the_session(self):
        """Ctrl-C interrupts the remote command, not the tool: the session has
        to still be usable afterwards."""
        import pty
        mock = mocks.GrittyMock(mode="interactive")
        srv, port = mocks.serve(mocks.gritty_handler(mock))
        master, slave = pty.openpty()
        proc = None
        try:
            proc = _run_tool_on_pty(port, master, slave)
            time.sleep(1.5)
            proc.send_signal(signal.SIGINT)
            deadline = time.time() + 10
            while "\x03" not in mock.data_received and time.time() < deadline:
                time.sleep(0.05)
            self.assertIn("\x03", mock.data_received,
                          "Ctrl-C was not forwarded: %r" % mock.data_received)
            self.assertIsNone(proc.poll(), "the tool exited on Ctrl-C")
            os.write(master, b"whoami\n")
            seen = _read_until(master, b"OUT: whoami", time.time() + 20)
            self.assertIn(b"OUT: whoami", seen,
                          "session unusable after Ctrl-C: %r" % seen[-300:])
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()
            mocks.stop(srv)
            os.close(master)
            os.close(slave)
