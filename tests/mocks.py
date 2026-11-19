"""Mock servers and shared helpers for the offline suite.

  GrittyMock  a mock Engine.IO v3 / Socket.IO server exposing the /gritty
              namespace, used to drive the terminal tool
  ReadMock    a mock of the /error/assets/:myfile route, including the
              `path.resolve` semantics that make the absolute form work
  ApiMock     a mock of GET /v3/api/, the unauthenticated version endpoint
"""

import json
import posixpath
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

NS = "/gritty"

# Where an affected build keeps its error assets. The depth matters: the client
# sweeps 9-12, and normpath clamps leading ".." at the root, so any depth at or
# above the real one resolves to the same file.
ASSET_DIR = "/opt/fastx/www/error/assets"
VFS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                   "fastx:x:1000:1000::/home/fastx:/bin/sh\n",
    "/etc/hostname": "fastx-host\n",
}

VERBOSE = False


def frame(*packets):
    """Engine.IO v3 polling payload framing: <len>:<packet>."""
    return "".join("%d:%s" % (len(p), p) for p in packets)


def parse(body):
    out, i = [], 0
    while i < len(body):
        j = body.find(":", i)
        if j < 0:
            break
        try:
            n = int(body[i:j])
        except ValueError:
            break
        out.append(body[j + 1:j + 1 + n])
        i = j + 1 + n
    return out


# --------------------------------------------------------------------------
# /gritty mock


class GrittyMock:
    """Per-session state for the Socket.IO mock.

    modes:
      accept       connect -> `accept`, terminal -> `data` + `exit`
      reject       connect -> `reject`
      password     terminal -> `data` "Password: ", and a `data` line is not
                   echoed: the program reading a secret prints only its
                   newline, then `exit`
      password_then_error
                   like `password`, but the long-poll fails on the first
                   request after the prompt has been delivered, so the tool
                   leaves through its transport-error path
      password_idle
                   like `password`, but nothing is ever answered again: the
                   session sits at the prompt, which is where a Ctrl-C test
                   wants it
      authgate     an auth handler is installed, so the connect alone draws
                   nothing; an `auth` event is answered with `accept` whatever
                   the credentials: a gate that is wired but checks nothing.
      authgate_strict
                   the same, but `accept` only for the credentials
                   `user`/`pass`; anything else draws `reject`
      nohandshake  the handshake GET returns 200 with a non-Engine.IO body
      badjson      the handshake looks right but the JSON is malformed
      badnamespace the Engine.IO handshake succeeds but the namespace is not
                   registered, so the connect draws a Socket.IO ERROR packet
                   (`44<ns>,"Invalid namespace"`). This is what a gritty
                   deployment mounted under a custom `prefix` looks like to a
                   client probing the default `/gritty`.
      badnamespace_v4
                   the same, in the Socket.IO v4 payload shape
                   (`44<ns>,{"message":"Invalid namespace"}`). FastX 3 is v2,
                   but the tool must not depend on the payload shape.
    """

    def __init__(self, mode="accept", ping_interval=25000, ping_timeout=5000,
                 enforce_ping=False, server_pings=True):
        self.mode = mode
        self.broken = False
        self.break_after_next = False
        self.sessions = {}
        self.received = []          # every packet posted, in order
        self.terminal_params = None
        self.auth_received = None
        self.data_received = []
        self.lock = threading.Lock()
        # Engine.IO v3 keepalive. `server_pings` False is the shape FastX 3
        # actually has: nothing is sent unprompted, so a client that only
        # answers pings never pings at all, and `enforce_ping` reaps it.
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.enforce_ping = enforce_ping
        self.server_pings = server_pings
        self.pings = 0              # client -> server pings seen
        self.last_ping = {}
        self.reaped = []

    def new_session(self):
        sid = "mock%06d" % int(time.time() * 1000 % 1_000_000)
        with self.lock:
            self.sessions[sid] = []
            self.last_ping[sid] = time.time()
        return sid

    def expired(self, sid):
        """True once the session has gone unpinged past the advertised budget."""
        if not self.enforce_ping:
            return False
        with self.lock:
            last = self.last_ping.get(sid)
            if last is None:
                return False
            budget = (self.ping_interval + self.ping_timeout) / 1000.0
            return time.time() - last > budget

    def on_post(self, sid, body):
        with self.lock:
            q = self.sessions.setdefault(sid, [])
            for p in parse(body):
                self.received.append(p)
                if p == "2":                    # client ping -> pong
                    self.pings += 1
                    self.last_ping[sid] = time.time()
                    q.append("3")
                elif p == "40" + NS + ",":
                    # socket.io 2.5.0 lib/client.js: a connect to a namespace
                    # that was never registered gets
                    # {type: parser.ERROR, nsp: name, data: 'Invalid namespace'}
                    # back on the namespace the client asked for -- never an
                    # `accept` and never a `reject`.
                    if self.mode == "badnamespace":
                        q.append("44" + NS + "," + json.dumps(
                            "Invalid namespace"))
                    elif self.mode == "badnamespace_hostile":
                        q.append("44" + NS + "," + json.dumps(
                            "Invalid\x1b[31mnamespace\x07"))
                    elif self.mode == "badnamespace_v4":
                        q.append("44" + NS + "," + json.dumps(
                            {"message": "Invalid namespace"}))
                    elif self.mode in ("authgate", "authgate_strict"):
                        pass            # an auth handler: nothing until `auth`
                    else:
                        q.append("42" + NS + "," + json.dumps(
                            ["reject"] if self.mode == "reject" else ["accept"]))
                elif p.startswith("42" + NS + ","):
                    payload = json.loads(p[len("42" + NS + ","):])
                    if payload[0] == "auth":
                        # gritty: socket.on('auth', auth(connect, reject)), and
                        # the client emits two positional arguments.
                        self.auth_received = payload[1:]
                        ok = (self.mode == "authgate"
                              or payload[1:] == ["user", "pass"])
                        q.append("42" + NS + "," + json.dumps(
                            ["accept"] if ok else ["reject"]))
                    elif payload[0] == "terminal":
                        self.terminal_params = payload[1]
                        if self.mode in ("accept", "authgate",
                                         "authgate_strict"):
                            q.append("42" + NS + "," + json.dumps(
                                ["data", "uid=1000(tester) gid=1000(tester)\r\n"]))
                            q.append("42" + NS + "," + json.dumps(["exit", 0]))
                        elif self.mode in ("password", "password_then_error",
                                           "password_idle"):
                            q.append("42" + NS + "," + json.dumps(
                                ["data", "Password: "]))
                            if self.mode == "password_then_error":
                                self.break_after_next = True
                    elif payload[0] == "data" and self.mode in (
                            "password", "password_then_error", "password_idle"):
                        text = payload[1]
                        self.data_received.append(text)
                        if self.mode == "password":
                            # A program reading a secret with echo off: no
                            # echo, just the newline it prints afterwards.
                            q.append("42" + NS + "," + json.dumps(
                                ["data", "\r\n"]))
                            q.append("42" + NS + "," + json.dumps(["exit", 0]))
                    elif payload[0] == "data" and self.mode == "interactive":
                        text = payload[1]
                        self.data_received.append(text)
                        q.append("42" + NS + "," + json.dumps(
                            ["data", text.replace("\n", "\r\n")]))
                        q.append("42" + NS + "," + json.dumps(
                            ["data", "OUT: " + text]))
                        if text.strip() == "exit" or text == "\x04":
                            q.append("42" + NS + "," + json.dumps(["exit", 0]))
                elif p.startswith("41"):
                    self.sessions.pop(sid, None)

    def drain(self, sid):
        with self.lock:
            q = self.sessions.get(sid, [])
            out, self.sessions[sid] = list(q), []
            return out


def gritty_handler(mock):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, text):
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain;charset=UTF-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            qs = parse_qs(urlparse(self.path).query)
            sid = qs.get("sid", [None])[0]
            if sid is None:
                # The handshake. These two modes answer 200 but with something
                # that is not a usable Engine.IO handshake, which is what a
                # build with the namespace disabled looks like.
                if mock.mode == "nohandshake":
                    return self._send(200, "<html>not socket.io</html>")
                if mock.mode == "badjson":
                    return self._send(200, frame("0{\"sid\": truncated"))
                new = mock.new_session()
                handshake = json.dumps({
                    "sid": new, "upgrades": [],
                    "pingInterval": mock.ping_interval,
                    "pingTimeout": mock.ping_timeout})
                return self._send(200, frame("0" + handshake, "40"))
            if mock.broken:
                return self._send(500, "boom")
            if mock.expired(sid):
                mock.reaped.append(sid)
                return self._send(400, json.dumps(
                    {"code": 1, "message": "Session ID unknown"}))
            queued = mock.drain(sid)
            if not queued:
                time.sleep(0.05)
                # "2" is a server-sent ping (the v4 shape); "6" is a noop and
                # leaves the keepalive entirely to the client, as FastX does.
                return self._send(200, frame("2" if mock.server_pings else "6"))
            body = frame(*queued)
            if mock.break_after_next:
                mock.break_after_next = False
                mock.broken = True     # prompt is on the wire; now the transport dies
            return self._send(200, body)

        def do_POST(self):
            qs = parse_qs(urlparse(self.path).query)
            sid = qs.get("sid", [""])[0]
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode("utf-8", "replace")
            mock.on_post(sid, body)
            return self._send(200, "ok")

    return H


# --------------------------------------------------------------------------
# /error/assets mock


class ReadMock:
    """Mock of the vulnerable error-asset route.

    modes:
      both           absolute and relative forms both resolve (unpatched)
      relative_only  absolute form is blocked, as if a front end rewrote it
      absolute_only  relative form is 400d, as a normalising proxy would
      patched        every request answers 200 with an empty body (allowlist)
    """

    def __init__(self, mode="both"):
        self.mode = mode
        self.requested = []
        self.lock = threading.Lock()

    def resolve(self, param):
        """Reproduce path.resolve(__dirname, 'assets', param)."""
        decoded = unquote(param)
        if decoded.startswith("/"):
            return decoded, "absolute"
        return posixpath.normpath(posixpath.join(ASSET_DIR, decoded)), "relative"

    def body_for(self, param):
        resolved, form = self.resolve(param)
        with self.lock:
            self.requested.append((form, resolved))
        if self.mode == "patched":
            return ""
        if self.mode == "relative_only" and form == "absolute":
            return ""
        if self.mode == "absolute_only" and form == "relative":
            return None              # signals 400, like a normalising proxy
        return VFS.get(resolved, "")


def read_handler(mock):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            # Deliberately read the raw path: the %2f sequences must survive
            # un-decoded, which is the whole point of the absolute form.
            path = urlparse(self.path).path
            prefix = "/error/assets/"
            if not path.startswith(prefix):
                return self._send(404, "")
            body = mock.body_for(path[len(prefix):])
            if body is None:
                return self._send(400, "bad request")
            return self._send(200, body)

        def _send(self, code, text):
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain;charset=UTF-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


# --------------------------------------------------------------------------
# /v3/api/ mock


class ApiMock:
    """Mock of GET /v3/api/, the unauthenticated version endpoint.

    modes: nested | toplevel | html | absent | auth | missing | redirect |
           bogus | garbage
    """

    def __init__(self, mode="nested"):
        self.mode = mode
        self.hits = 0
        self.lock = threading.Lock()

    def response(self):
        with self.lock:
            self.hits += 1
        if self.mode == "nested":
            return 200, "application/json", '{"result":{"build":"3.3.69"}}'
        if self.mode == "toplevel":
            return 200, "application/json", '{"build":"3.1.27"}'
        if self.mode == "html":
            return 200, "text/html", '<script>var v = {"build":"3.2.60"};</script>'
        if self.mode == "absent":
            return 200, "application/json", '{"result":{"id":"server"}}'
        if self.mode == "auth":
            return 401, "application/json", '{"error":"unauthorized"}'
        if self.mode == "missing":
            return 404, "text/html", "<html>not found</html>"
        if self.mode == "redirect":
            return 302, "text/html", ""
        if self.mode == "bogus":
            return 200, "application/json", '{"result":{"build":"unknown-build"}}'
        if self.mode == "hostile":
            # A build string is attacker-controlled text; a terminal that
            # renders an escape sequence is a terminal the server can drive.
            return 200, "application/json", (
                '{"result":{"build":"3.3.69\\u001b]0;pwned\\u0007"}}')
        if self.mode == "long":
            return 200, "application/json", '{"result":{"build":"%s"}}' % ("3.3.69" + "x" * 400)
        return 200, "text/plain", "hello"


def api_handler(mock):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            if not path.startswith("/v3/api/"):
                return self._send(404, "text/html", "")
            code, ctype, text = mock.response()
            return self._send(code, ctype, text)

        def _send(self, code, ctype, text):
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if code == 302:
                self.send_header("Location", "/login")
            self.end_headers()
            self.wfile.write(data)

    return H


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def echo_enabled(fd):
    import termios
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)


def stop(srv):
    """Shut a `serve` server down and release its listening socket."""
    srv.shutdown()
    srv.server_close()
