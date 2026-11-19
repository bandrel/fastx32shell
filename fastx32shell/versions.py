"""The FastX version matrix and its classifier."""
import re

ISSUES = ("read", "rce", "fastx4")

# (issue, low, high, verdict, basis) — inclusive bounds, first match wins.
# The version matrix verified against real packages; tests/test_versions.py
# pins every build it names.
RANGES = (
    ("read",   (3, 0, 32),  (3, 0, 40),   "vulnerable",     "inferred"),
    ("read",   (3, 0, 41),  (3, 3, 69),   "vulnerable",     "inferred"),
    ("read",   (3, 3, 70),  (3, 3, 70),   "unknown",        "not sampled"),
    ("read",   (3, 3, 71),  (3, 99, 999), "not vulnerable", "inferred"),
    ("read",   (5, 0, 0),   (5, 99, 999), "unknown",        "not examined"),
    ("rce",    (3, 0, 0),   (3, 0, 32),   "not vulnerable", "inferred"),
    ("rce",    (3, 0, 33),  (3, 0, 40),   "unknown",        "not sampled"),
    ("rce",    (3, 0, 41),  (3, 1, 27),   "vulnerable",     "inferred"),
    ("rce",    (3, 1, 28),  (3, 2, 26),   "unknown",        "not sampled"),
    ("rce",    (3, 2, 27),  (3, 3, 71),   "not vulnerable", "inferred"),
    ("rce",    (5, 0, 0),   (5, 99, 999), "not vulnerable", "inferred"),
    ("fastx4", (3, 0, 0),   (3, 99, 999), "not vulnerable", "outside the matrix"),
    ("fastx4", (5, 0, 0),   (5, 99, 999), "not vulnerable", "outside the matrix"),
    ("fastx4", (4, 0, 0),   (4, 1, 51),   "vulnerable",     "unverified"),
    ("fastx4", (4, 1, 52),  (4, 99, 999), "not vulnerable", "unverified"),
)

FALLBACK = {
    "read":   ("unknown", "never sampled"),
    "rce":    ("unknown", "outside the matrix"),
    "fastx4": ("unknown", "unverified"),
}

# Every build actually inspected: an exact hit reports confirmed, whatever
# its range says. From the matrix table.
SAMPLED = frozenset({
    (3, 0, 32), (3, 0, 41), (3, 0, 42), (3, 0, 43), (3, 0, 47),
    (3, 1, 22), (3, 1, 25), (3, 1, 27),
    (3, 2, 27), (3, 2, 36), (3, 2, 60), (3, 2, 72), (3, 2, 77),
    (3, 3, 15), (3, 3, 25), (3, 3, 29), (3, 3, 39), (3, 3, 59),
    (3, 3, 65), (3, 3, 67), (3, 3, 69), (3, 3, 71),
    (5, 1, 7),
})

BUILD_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_build(text):
    """Return the first (major, minor, patch) triple in text, or None.

    A build string may arrive padded ("FastX3 3.0.47-683") or suffixed
    ("3.3.69 (preview)"); the version is the leading triple either way. For
    3.0.x the third component is a build number, not a semver patch, which
    does not change the ordering.
    """
    if not isinstance(text, str):
        return None
    match = BUILD_RE.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def classify(version):
    """Return one {"issue", "verdict", "basis"} dict per issue, in ISSUES order."""
    findings = []
    for issue in ISSUES:
        verdict, basis = FALLBACK[issue]
        for name, low, high, rule_verdict, rule_basis in RANGES:
            if name == issue and low <= version <= high:
                verdict, basis = rule_verdict, rule_basis
                break
        # An inspected build confirms its own row, but never turns an
        # unexamined issue into a confirmed one: 5.1.7 was inspected and its
        # error-asset route still was not.
        if verdict != "unknown" and version in SAMPLED:
            basis = "confirmed"
        findings.append({"issue": issue, "verdict": verdict, "basis": basis})
    return findings
