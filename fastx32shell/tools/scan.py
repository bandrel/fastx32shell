"""FastX version scan.

Which known FastX issues a build carries, decided from the build string alone
rather than by sending an exploiting request. The build string is what the
server reports at `GET /v3/api/` (`result.build`), or a string supplied
offline from another scanner.

    fastx32shell scan --base https://fastx.example.com:3300
    fastx32shell scan --base-file scope.txt
    fastx32shell scan --build 3.1.27
    fastx32shell scan --build-file versions.txt --json

Version scope:

    issue     affected builds              fixed / inert
    read      3.0.32 .. 3.3.69             3.3.71 (filename allowlist)
    rce       3.0.41 .. 3.1.27             3.2.27 onward (namespace never mounts)
    fastx4    CVE-2025-57563, 4.0 .. 4.1.51   not examined

Two properties matter more than the ranges. A verdict always carries the basis
it was reached on: `confirmed` when that exact build was inspected, `inferred`
when it sits inside a range whose ends were, and the basis itself is `unknown`
for a build nobody has looked at. And a gap is reported as a gap: nothing was
sampled between 3.1.28 and 3.2.26, where the command execution stops working,
so a build in there is `unknown`, not a guess.

Read-only. The network mode sends one GET per host and nothing else; the
offline mode sends nothing at all.

Exit codes
    0   a build string was found and nothing is flagged
    1   at least one host carries a vulnerable verdict
    2   no input yielded a build string
    4   every host was a transport error (nothing answered at all)
    64  usage error
"""

import json
import re

from fastx32shell import http
from fastx32shell.term import safe_text
from fastx32shell.versions import classify, parse_build

MAX_BODY = 1024 * 1024
API_PATH = "/v3/api/"


def row(input_text, build_text=None, error=None):
    """One result row. `build_text=None` means the input is the build string.

    `error` forces a failure row: a base URL is not a build string, and
    `127.0.0.1` would otherwise parse as a version triple.
    """
    # A failure row carries no build string: the input is a URL, and showing
    # it in the build column claims the host said that.
    raw = safe_text(input_text if (build_text is None and error is None)
                    else build_text)
    version = None if error else parse_build(raw)
    if error is None and version is None:
        error = "unparsable"
    findings = classify(version) if version else []
    return {"input": input_text, "build": raw, "version": version,
            "findings": findings, "error": error}


def flagged(result):
    """The findings worth printing: anything that is not a clean negative."""
    return [f for f in result["findings"] if f["verdict"] != "not vulnerable"]


def exit_code(rows):
    if not rows:
        return 2
    if all((r["error"] or "").startswith("transport") for r in rows):
        return 4
    if not any(r["version"] for r in rows):
        return 2
    if any(f["verdict"] == "vulnerable" for r in rows for f in r["findings"]):
        return 1
    return 0


def emit_human(rows):
    width = max(len(r["input"]) for r in rows)
    # In offline mode the input *is* the build string; a second identical
    # column is noise, so it appears only when the two differ.
    show_build = any((r["build"] or "-") != r["input"] for r in rows)
    build_width = max(len(r["build"] or "-") for r in rows) if show_build else 0
    for r in rows:
        if r["version"] is None:
            text = "no version (%s)" % (r["error"] or "unknown")
        else:
            text = "   ".join("%s:%s (%s)" % (f["issue"], f["verdict"], f["basis"])
                              for f in flagged(r))
            text = text or "clean (nothing known at this build)"
        if show_build:
            print("%s  %s  %s" % (r["input"].ljust(width),
                                  (r["build"] or "-").ljust(build_width), text))
        else:
            print("%s  %s" % (r["input"].ljust(width), text))

    # Disjoint buckets, so the counts add up to the number of rows.
    hit = clean = unknown = missing = 0
    for r in rows:
        if r["version"] is None:
            missing += 1
        elif any(f["verdict"] == "vulnerable" for f in r["findings"]):
            hit += 1
        elif flagged(r):
            unknown += 1
        else:
            clean += 1
    print("%d %s: %d flagged, %d clean, %d unknown, %d no version"
          % (len(rows), "host" if len(rows) == 1 else "hosts",
             hit, clean, unknown, missing))


def json_doc(rows):
    """Every issue for every parsed row: a consumer must not have to read
    'absent' as 'clean'."""
    return {"tool": "fastx32shell_version_scan",
            "hosts": [{"input": r["input"], "build": r["build"],
                       "error": r["error"], "findings": r["findings"]}
                      for r in rows]}


def extract_build(body):
    """Pull the build string out of whatever /v3/api/ answered.

    result.build is the shape 3.x ships; a top-level build covers a wrapper or
    a proxy; the regex covers an HTML shell that inlines the same JSON.
    """
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        result = doc.get("result")
        if isinstance(result, dict) and isinstance(result.get("build"), str):
            return result["build"]
        if isinstance(doc.get("build"), str):
            return doc["build"]
    match = re.search(r'"build"\s*:\s*"([^"]{3,40})"', text)
    return match.group(1) if match else None


def fetch_build(opener, base, timeout, ua=http.DEFAULT_UA):
    """Return (build, error): one for the version endpoint, nothing else sent."""
    status, body, _ = http.get(opener, base + API_PATH, timeout,
                               ua=ua, max_body=MAX_BODY)
    if status is None:
        return None, "transport: %s" % http.transport_error_name(body)
    if status >= 300:
        return None, "http %d" % status
    build = extract_build(body)
    if build is None:
        return None, "no build key"
    if parse_build(build) is None:
        return build, "unparsable"
    return build, None


def add_arguments(parser):
    parser.add_argument("--build", metavar="STRING",
                        help="classify a build string, e.g. 3.1.27")
    parser.add_argument("--build-file", metavar="PATH",
                        help="classify one build string per line")
    parser.add_argument("--base", metavar="URL",
                        help="target base URL, e.g. https://fastx.example.com:3300")
    parser.add_argument("--base-file", metavar="PATH",
                        help="one target per line; blank lines and # comments skipped")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.set_defaults(_parser=parser)


def run(args):
    given = [name for name, value in
             (("--base", args.base), ("--base-file", args.base_file),
              ("--build", args.build), ("--build-file", args.build_file))
             if value]
    if len(given) != 1:
        args._parser.error("pass exactly one of --base, --base-file, --build, --build-file")

    if args.build:
        rows = [row(args.build)]
    elif args.build_file:
        try:
            lines = http.load_lines(args.build_file)
        except (OSError, ValueError) as exc:
            args._parser.error(str(exc))
        rows = [row(line) for line in lines]
    else:
        if args.base:
            bases = [http.normalise_base(args.base)]
        else:
            try:
                bases = [http.normalise_base(line)
                         for line in http.load_lines(args.base_file)]
            except (OSError, ValueError) as exc:
                args._parser.error(str(exc))
        # One opener for the whole sweep, and no exception can leave the loop:
        # fetch_build turns every failure into a row.
        opener = http.make_opener(insecure=args.insecure, proxy=args.proxy,
                                  ca=args.ca, follow_redirects=False)
        rows = []
        for base in bases:
            build, error = fetch_build(opener, base, args.timeout,
                                       ua=args.ua or http.DEFAULT_UA)
            rows.append(row(base, build_text=build, error=error))

    if args.json:
        print(json.dumps(json_doc(rows), indent=2))
    else:
        emit_human(rows)
    return exit_code(rows)

