"""Target HTTP: one SSL context, one opener, one GET.

TLS handling is shared so every tool accepts the same hosts: --ca relaxes
VERIFY_X509_STRICT, which Burp-style CAs need under Python 3.13.

Redirect following is NOT unified. The version scan treats a 302 as a
statement about where the login page is rather than a result, so it passes
follow_redirects=False; the read and RCE tools follow redirects as they
always have.
"""
import ssl
import urllib.error
import urllib.request

DEFAULT_UA = "Mozilla/5.0"
MAX_BODY = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a statement about where the login page is, not a result."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(insecure=False, proxy=None, ca=None, follow_redirects=True):
    ctx = ssl.create_default_context(cafile=ca or None)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca:
        # Burp-style CAs carry a pathlen constraint without keyCertSign;
        # Python 3.13 enables X509_STRICT by default and would reject the
        # chain. Clearing that single flag keeps verification against --ca.
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(NoRedirect())
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def get(opener, url, timeout, ua=DEFAULT_UA, max_body=MAX_BODY, headers=None):
    """Return (status, body, headers). status is None on a transport error."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", ua)
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(max_body), dict(r.headers)
    except urllib.error.HTTPError as e:
        # A stalled or truncated error body must not turn a status into an
        # exception: the code is the result, the body is a bonus.
        try:
            body = e.read(max_body)
        except Exception:  # noqa: BLE001 - network shape varies by target
            body = b""
        return e.code, body, dict(e.headers or {})
    except Exception as e:  # noqa: BLE001 - network shape varies by target
        return None, ("<%s: %s>" % (type(e).__name__, e)).encode(), {}


def transport_error_name(body):
    """Return the exception type name from a transport-error body.

    The inverse of the "<TypeName: message>" formatting in get().
    """
    return body[1:].split(b":", 1)[0].decode()


def normalise_base(line):
    """A bare host or host:port gets https://; a trailing slash is trimmed."""
    base = line.strip()
    if "://" not in base:
        base = "https://" + base
    return base.rstrip("/")


def load_lines(path):
    """Read a list file: blank lines and # comments skipped, whitespace trimmed."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = [line.strip() for line in fh]
    lines = [line for line in lines if line and not line.startswith("#")]
    if not lines:
        raise ValueError("%s: no entries after comments and blank lines" % path)
    return lines
