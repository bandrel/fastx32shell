"""Hand-rolled Engine.IO v3 long-polling client.

The toolkit takes no dependencies, so the transport is written against the
standard library: `Client` makes the requests, `frame` and `packets` handle the
`<len>:<packet>` payload framing, and `poll_once` and `send_event` speak the
Socket.IO event layer on top.
"""

import json
import threading
import time
import urllib.error
import urllib.request

from fastx32shell import http

# Ping at a fraction of the advertised interval so one dropped ping does not
# cost the session. The server reaps at pingInterval + pingTimeout.
PING_MARGIN = 0.8

# Used when a handshake omits pingInterval; matches the Engine.IO v3 default.
DEFAULT_PING_INTERVAL = 25.0


class Client:
    """Minimal Engine.IO v3 long-polling client."""

    def __init__(self, base, timeout, insecure, proxy, ca, cookie, ua):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cookie = cookie
        self.ua = ua

        self.opener = http.make_opener(insecure=insecure, proxy=proxy, ca=ca)

    def call(self, url, method="GET", body=None):
        data = None if body is None else body.encode()
        req = urllib.request.Request(url, method=method, data=data)
        req.add_header("User-Agent", self.ua)
        req.add_header("Origin", self.base)
        req.add_header("Referer", self.base + "/terminal/")
        if data is not None:
            req.add_header("Content-Type", "text/plain;charset=UTF-8")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return None, "<%s: %s>" % (type(e).__name__, e)


def frame(*packets):
    """Engine.IO v3 polling payload framing: <len>:<packet>."""
    return "".join("%d:%s" % (len(p), p) for p in packets)


def packets(body):
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


def namespace_error(body, ns):
    """The reason text from a Socket.IO ERROR packet, or None.

    A connect to a namespace the server never registered comes back as
    `44<ns>,<payload>` rather than as any event, so `poll_once` -- which
    decodes only `42<ns>,` -- drops it and the caller would otherwise sit
    waiting for an `accept` that is never coming. The payload is a bare string
    in Socket.IO v2 (`"Invalid namespace"`) and an object in v4
    (`{"message": ...}`); both are reported, and an unparseable one still
    counts as an error, because the packet type alone is the verdict.
    """
    for p in packets(body):
        if not p.startswith("44" + ns + ","):
            continue
        raw = p[len("44" + ns + ","):]
        try:
            payload = json.loads(raw)
        except ValueError:
            return raw or "unspecified"
        if isinstance(payload, dict):
            return str(payload.get("message", payload))
        return str(payload)
    return None


def poll_once(cl, poll, ns):
    """One long-poll GET, with pings answered.

    Returns (status, events, body): `events` is a list of (event, args) pairs
    decoded from `42<ns>,` packets; `status` is None on a transport error, in
    which case the caller applies its own retry policy.
    """
    status, body = cl.call(poll + "&t=g%d" % int(time.time() * 1000), "GET")
    if status != 200:
        return status, [], body

    events = []
    for p in packets(body):
        if p.startswith("2"):                           # ping -> pong
            cl.call(poll + "&t=q%d" % int(time.time() * 1000), "POST",
                    frame("3" + p[1:]))
            continue

        if not p.startswith("42" + ns + ","):
            continue

        try:
            payload = json.loads(p[len("42" + ns + ","):])
        except ValueError:
            continue
        if isinstance(payload, list) and payload:
            events.append((payload[0], payload[1:]))

    return status, events, body


def send_event(cl, poll, ns, name, *payload):
    """POST one Socket.IO event; returns the HTTP status (None on error).

    Several arguments are sent as several positional arguments, which is what
    an `auth` handler expects: the client side of this ecosystem emits
    `socket.emit('auth', username, password)`, and gritty's own test suite
    sends `('auth', 'hello', 'world')`. `terminal` and `data` each take one.
    """
    status, _ = cl.call(poll + "&t=e%d" % int(time.time() * 1000), "POST",
                        frame("42" + ns + ","
                              + json.dumps([name] + list(payload))))
    return status


class Pinger:
    """Engine.IO v3 keepalive, on its own thread.

    In v3 the ping is the client's job: the server advertises `pingInterval`
    and then reaps any session that has not pinged within `pingInterval` plus
    `pingTimeout`. Polling does not count, and neither does sending data, so a
    session that is busy the whole time still dies on schedule. Answering a
    server-sent ping, which `poll_once` does, is the v4 shape and never fires
    here.

    The pinger gets its own `Client` because the poll holds a request open for
    as long as the interval itself.
    """

    def __init__(self, client, poll, interval):
        self.client = client
        self.poll = poll
        self.interval = max(1.0, interval * PING_MARGIN)
        self.sent = 0
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        return self

    def _run(self):
        while not self._stop.wait(self.interval):
            status, _ = self.client.call(
                self.poll + "&t=p%d" % int(time.time() * 1000),
                "POST", frame("2"))
            if status == 200:
                self.sent += 1

    def stop(self):
        self._stop.set()
