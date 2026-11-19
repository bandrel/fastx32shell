"""Unit checks on the terminal tool's echo, prompt and mute helpers."""
import io
import os
import pty
import sys
import unittest

from fastx32shell import term
from tests.mocks import echo_enabled


class Echo(unittest.TestCase):
    """The pty echoes a line the local terminal already showed, and it can
    arrive split across polls."""

    def test_unarmed_stripper_leaves_output_alone(self):
        s = term.EchoStripper()
        self.assertEqual(s.feed("prompt$ "), "prompt$ ")

    def test_split_echo_first_half_removed(self):
        s = term.EchoStripper()
        s.feed("prompt$ ")
        s.arm("id")
        self.assertEqual(s.feed("id\r"), "")

    def test_split_echo_tail_and_output_kept(self):
        s = term.EchoStripper()
        s.feed("prompt$ ")
        s.arm("id")
        s.feed("id\r")
        self.assertEqual(s.feed("\nmain.c\r\n"), "main.c\r\n")

    def test_mismatched_echo_does_not_swallow_output(self):
        s = term.EchoStripper()
        s.arm("ls")
        self.assertEqual(s.feed("uid=0\r\n"), "uid=0\r\n")

    def test_whole_line_echo_removed(self):
        s = term.EchoStripper()
        s.arm("pwd")
        self.assertEqual(s.feed("pwd\r\n/tmp\r\n"), "/tmp\r\n")

    def test_empty_chunk_tolerated(self):
        s = term.EchoStripper()
        self.assertEqual(s.feed(""), "")


class PasswordPrompt(unittest.TestCase):
    def test_recognised_prompts(self):
        for text in ("Password: ",
                     "[sudo] password for lab: ",
                     "Enter passphrase for key '/home/lab/.ssh/id_ed25519': ",
                     "New password: ",
                     "Retype new password: ",
                     "(current) UNIX password: ",
                     "Password:\x1b[0m "):
            with self.subTest(text=text):
                self.assertTrue(term.looks_like_password_prompt(text),
                                "missed prompt: %r" % text)

    def test_non_prompts_are_not_flagged(self):
        for text in ("password policy: 90 days",
                     "Configuration: ",
                     "Password: ok",
                     "lab@host:~$ ",
                     ""):
            with self.subTest(text=text):
                self.assertFalse(term.looks_like_password_prompt(text),
                                 "false positive: %r" % text)


class LocalEchoCase(unittest.TestCase):
    def setUp(self):
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.echo = term.LocalEcho(self.slave)

    def test_pty_starts_with_echo_on(self):
        self.assertTrue(echo_enabled(self.slave),
                        "pty did not start with echo on")

    def test_mute_clears_echo(self):
        self.echo.mute()
        self.assertFalse(echo_enabled(self.slave), "mute did not clear ECHO")

    def test_second_mute_changes_nothing(self):
        self.echo.mute()
        self.echo.mute()
        self.assertFalse(echo_enabled(self.slave),
                         "second mute changed state")

    def test_restore_reinstates_echo(self):
        self.echo.mute()
        self.echo.restore()
        self.assertTrue(echo_enabled(self.slave),
                        "restore did not reinstate ECHO")

    def test_second_restore_changes_nothing(self):
        self.echo.mute()
        self.echo.restore()
        self.echo.restore()
        self.assertTrue(echo_enabled(self.slave),
                        "second restore changed state")

    def test_muting_a_different_pty_leaves_this_one_alone(self):
        # A pty's two fds are one terminal, so "wrong fd" means a second pty.
        other_master, other_slave = pty.openpty()
        try:
            term.LocalEcho(other_slave).mute()
            self.assertTrue(echo_enabled(self.slave),
                            "muting a different pty changed this one")
        finally:
            os.close(other_master)
            os.close(other_slave)

    def test_no_termios_is_tolerated(self):
        """A platform without termios: construct, mute and restore must all
        no-op."""
        saved = term.termios
        try:
            term.termios = None
            quiet = term.LocalEcho(sys.stdin)
            quiet.mute()
            quiet.restore()
        finally:
            term.termios = saved

    def test_default_stream_without_a_tty_is_tolerated(self):
        """No argument means stdin; a non-tty stdin must leave a no-op."""
        saved = sys.stdin
        try:
            sys.stdin = io.StringIO()
            quiet = term.LocalEcho()
            quiet.mute()
            quiet.restore()
        finally:
            sys.stdin = saved
        self.assertIsNone(quiet._fd)


class _SpyEcho:
    def __init__(self):
        self.muted = 0
        self.restored = 0

    def mute(self):
        self.muted += 1

    def restore(self):
        self.restored += 1


class PromptWatcher(unittest.TestCase):
    def test_shell_prompt_does_not_mute(self):
        spy = _SpyEcho()
        w = term.SecretPromptWatcher(spy)
        self.assertIs(w.feed("lab@host:~$ "), False,
                      "muted on a shell prompt")
        self.assertEqual(spy.muted, 0, "muted too early")

    def test_partial_prompt_does_not_mute(self):
        w = term.SecretPromptWatcher(_SpyEcho())
        self.assertIs(w.feed("Password"), False,
                      "muted on a partial prompt")

    def test_prompt_split_across_two_polls_mutes_once(self):
        spy = _SpyEcho()
        w = term.SecretPromptWatcher(spy)
        w.feed("Password")
        self.assertIs(w.feed(": "), True,
                      "missed a prompt split across two polls")
        self.assertEqual(spy.muted, 1, "mute not called once")

    def test_reset_stops_the_match(self):
        spy = _SpyEcho()
        w = term.SecretPromptWatcher(spy)
        w.feed("Password")
        w.feed(": ")
        w.reset()
        self.assertIs(w.feed("\r\n"), False,
                      "re-muted after the watch was reset")
        self.assertEqual(spy.muted, 1, "reset did not stop the match")

    def test_prompt_is_consumed_by_the_match(self):
        # The pty's newline after a secret can reach feed() before the reader
        # thread gets to reset(), and the accumulated tail would otherwise
        # still end in "Password: \r\n".
        spy = _SpyEcho()
        w = term.SecretPromptWatcher(spy)
        self.assertIs(w.feed("Password: "), True, "missed a whole prompt")
        self.assertIs(w.feed("\r\n"), False,
                      "re-muted on the secret's own newline")
        self.assertEqual(spy.muted, 1, "muted twice for one prompt")
