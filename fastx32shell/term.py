"""Terminal handling: keep secrets off the operator's screen, and target bytes
out of the terminal raw.

The pty echoes what is typed, and a remote prompt can ask for a password, so
the interactive session mutes local echo at a secret prompt, strips the pty's
echo of lines the local terminal already showed, and always hands the terminal
back with echo on. `safe_text` bounds and sanitises target-controlled strings
before they are printed.
"""

import re
import sys
import threading

try:
    import termios
except ImportError:      # non-POSIX: nothing to mute, the tool still runs
    termios = None

# How much arriving output the watcher keeps when deciding whether the remote is
# sitting at a secret prompt. A prompt can be split across two polls, so the
# decision is made on the tail, not on one chunk.
SECRET_PROMPT_TAIL = 256

# Colour and title sequences, so a prompt that ends in a reset code still ends
# in its colon as far as the detector is concerned.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")

# A secret prompt: a password/passphrase phrase, at most 80 non-colon
# characters, the colon, then nothing but whitespace. Matching the phrase AND
# the trailing colon keeps `password policy: 90 days` out.
PASSWORD_PROMPT = re.compile(r"(?i)(password|passphrase)[^:\r\n]{0,80}:\s*$")


def looks_like_password_prompt(text):
    """True if `text` ends at a password or passphrase prompt."""
    return bool(PASSWORD_PROMPT.search(_ANSI.sub("", text)))


class LocalEcho:
    """Clear and restore ECHO on a terminal, so a secret is not displayed.

    Display only: nothing here touches the bytes sent to the target. Every
    method is a no-op when the fd is not a tty or `termios` is unavailable, and
    both are idempotent, so an exit path can call restore() unconditionally.
    ISIG is left alone -- Ctrl-C must still reach the pty.

    TCSANOW, never TCSADRAIN: drain waits inside the kernel for the terminal's
    output queue to empty, and a pty whose reader has gone quiet never does.
    That is a hang in the middle of a session, which is worse than the echo it
    was trying to suppress.
    """

    def __init__(self, stream_or_fd=None):
        self._fd = None
        self._saved = None
        self._muted = False
        if termios is None:
            return
        target = sys.stdin if stream_or_fd is None else stream_or_fd
        try:
            fd = target if isinstance(target, int) else target.fileno()
            self._saved = termios.tcgetattr(fd)
        except (AttributeError, OSError, ValueError, termios.error):
            return          # not a tty: there is no local echo to suppress
        self._fd = fd

    def mute(self):
        if self._fd is None or self._muted:
            return
        attrs = list(self._saved)
        attrs[3] &= ~termios.ECHO
        try:
            termios.tcsetattr(self._fd, termios.TCSANOW, attrs)
        except termios.error:
            return
        self._muted = True

    def restore(self):
        if self._fd is None or not self._muted:
            return
        try:
            termios.tcsetattr(self._fd, termios.TCSANOW, self._saved)
        except termios.error:
            return
        self._muted = False


class SecretPromptWatcher:
    """Mute local echo when arriving output ends at a secret prompt.

    Reader and poller threads share one watcher, so the tail and the lock are
    held here rather than in `run_interactive()`.
    """

    def __init__(self, echo, keep=SECRET_PROMPT_TAIL):
        self.echo = echo
        self.keep = keep
        self._tail = ""
        self._lock = threading.Lock()

    def feed(self, chunk):
        """Add remote output; mute and return True if a prompt is now showing.

        A match consumes the tail. Without that, the newline the pty prints
        after the secret completes the line and looks like a prompt again; it
        can reach feed() before the reader thread resets the watcher, and a
        second mute would land with nobody reading the terminal.
        """
        with self._lock:
            self._tail = (self._tail + _ANSI.sub("", chunk))[-self.keep:]
            if not looks_like_password_prompt(self._tail):
                return False
            self._tail = ""
            self.echo.mute()
            return True

    def reset(self):
        """Forget the tail, so the line about to be typed is not judged by it."""
        with self._lock:
            self._tail = ""


class EchoStripper:
    """Drops a pty's echo of a line the local terminal already showed.

    The reader thread arms it with each line it forwards; the polling thread
    feeds it the pty output. The echo can arrive split across polls, so a
    partial match stays armed for the next chunk. A mismatch disarms it and
    that chunk is passed through untouched.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._expect = ""

    def arm(self, line):
        with self._lock:
            self._expect = line + "\r\n"

    def feed(self, chunk):
        with self._lock:
            if not self._expect:
                return chunk
            n = min(len(chunk), len(self._expect))
            if chunk[:n] != self._expect[:n]:
                self._expect = ""
                return chunk
            self._expect = self._expect[n:]
            return chunk[n:]


def safe_text(text, limit=64):
    """Printable, bounded, so a hostile target cannot drive the operator's
    terminal or flood the report with a build string of its own choosing."""
    if text is None:
        return None
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]
