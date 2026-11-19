"""The version table and classifier, checked directly."""
import unittest

from fastx32shell import versions as scan


def verdicts(build):
    return {f["issue"]: (f["verdict"], f["basis"])
            for f in scan.classify(scan.parse_build(build))}


class ParseBuild(unittest.TestCase):
    def test_plain_version(self):
        self.assertEqual(scan.parse_build("3.3.69"), (3, 3, 69))

    def test_leading_triple_taken_from_a_padded_string(self):
        self.assertEqual(scan.parse_build("FastX3 3.0.47-683"), (3, 0, 47))

    def test_suffix_after_the_triple(self):
        self.assertEqual(scan.parse_build("3.3.69 (preview)"), (3, 3, 69))

    def test_garbage_is_not_a_version(self):
        self.assertIsNone(scan.parse_build("server"))


# Every build in the verified version matrix.
MATRIX = [
    ("3.0.32", "vulnerable", "not vulnerable"),
    ("3.0.41", "vulnerable", "vulnerable"),
    ("3.0.42", "vulnerable", "vulnerable"),
    ("3.0.43", "vulnerable", "vulnerable"),
    ("3.0.47", "vulnerable", "vulnerable"),
    ("3.1.22", "vulnerable", "vulnerable"),
    ("3.1.25", "vulnerable", "vulnerable"),
    ("3.1.27", "vulnerable", "vulnerable"),
    ("3.2.27", "vulnerable", "not vulnerable"),
    ("3.2.36", "vulnerable", "not vulnerable"),
    ("3.2.60", "vulnerable", "not vulnerable"),
    ("3.2.72", "vulnerable", "not vulnerable"),
    ("3.2.77", "vulnerable", "not vulnerable"),
    ("3.3.15", "vulnerable", "not vulnerable"),
    ("3.3.25", "vulnerable", "not vulnerable"),
    ("3.3.29", "vulnerable", "not vulnerable"),
    ("3.3.39", "vulnerable", "not vulnerable"),
    ("3.3.59", "vulnerable", "not vulnerable"),
    ("3.3.65", "vulnerable", "not vulnerable"),
    ("3.3.67", "vulnerable", "not vulnerable"),
    ("3.3.69", "vulnerable", "not vulnerable"),
    ("3.3.71", "not vulnerable", "not vulnerable"),
    ("5.1.7", "unknown", "not vulnerable"),
]


class Matrix(unittest.TestCase):
    """Every inspected build, the gaps, and the boundaries."""

    def test_sampled_build_reports_confirmed(self):
        self.assertEqual(verdicts("3.0.47")["read"],
                         ("vulnerable", "confirmed"),
                         "a sampled build must report confirmed")

    def test_unsampled_build_inside_a_range_reports_inferred(self):
        self.assertEqual(verdicts("3.3.66")["read"],
                         ("vulnerable", "inferred"),
                         "an unsampled build inside a range must report "
                         "inferred")

    def test_3_3_70_does_not_inherit_3_3_69(self):
        self.assertEqual(verdicts("3.3.70")["read"],
                         ("unknown", "not sampled"),
                         "3.3.70 must not inherit 3.3.69's verdict")

    def test_rce_gap_3_0_33_to_3_0_40(self):
        self.assertEqual(verdicts("3.0.35")["rce"],
                         ("unknown", "not sampled"),
                         "3.0.33-3.0.40 rce is a gap")

    def test_rce_gap_3_1_28_to_3_2_26(self):
        self.assertEqual(verdicts("3.2.10")["rce"],
                         ("unknown", "not sampled"),
                         "3.1.28-3.2.26 rce is a gap")

    def test_below_3_0_32_is_unknown_not_clean(self):
        self.assertEqual(verdicts("3.0.20")["read"][0], "unknown",
                         "below 3.0.32 was never sampled, so not "
                         "'not vulnerable'")

    def test_fastx4_range_is_flagged_unverified(self):
        self.assertEqual(verdicts("4.0.45")["fastx4"],
                         ("vulnerable", "unverified"),
                         "CVE-2025-57563 range must be flagged unverified")

    def test_4_1_51_is_top_of_the_cve_range(self):
        self.assertEqual(verdicts("4.1.51")["fastx4"][0], "vulnerable",
                         "4.1.51 is the top of the CVE range")

    def test_4_1_93_is_past_the_cve_range(self):
        self.assertEqual(verdicts("4.1.93")["fastx4"][0], "not vulnerable",
                         "4.1.93 is past the CVE range")


def _matrix_case(build, want_read, want_rce):
    def test(self):
        got = {f["issue"]: f["verdict"]
               for f in scan.classify(scan.parse_build(build))}
        self.assertEqual(got["read"], want_read,
                         "%s read %r != %r" % (build, got["read"], want_read))
        self.assertEqual(got["rce"], want_rce,
                         "%s rce %r != %r" % (build, got["rce"], want_rce))
    return test


for _build, _read, _rce in MATRIX:
    setattr(Matrix, "test_build_%s" % _build.replace(".", "_"),
            _matrix_case(_build, _read, _rce))
