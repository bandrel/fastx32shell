import os
import shutil
import subprocess
import tempfile
import time
import unittest

from tests import keys
from tests.cmd import ROOT, forge_cmd

SERVER_ID = "fastx-host-abc123"
USER = "someuser"


def _read(path):
    with open(path) as fh:
        return fh.read()


class Forge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fastx32shell-forge-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.key, self.pub = keys.write_keypair(self.tmp)
        self.sid = os.path.join(self.tmp, "serverId.txt")
        with open(self.sid, "w") as fh:
            fh.write(SERVER_ID + "\n")
        self.out = os.path.join(self.tmp, "tok.jwt")

    def forge(self, *extra):
        return subprocess.run(
            forge_cmd() + ["-k", self.key, "-s", self.sid, "-u", USER,
                           "-o", self.out, *extra],
            capture_output=True, text=True, timeout=30)

    def forge_to(self, dest):
        return subprocess.run(
            forge_cmd() + ["-k", self.key, "-s", self.sid, "-u", USER,
                           "-o", dest],
            capture_output=True, text=True, timeout=30)

    def token(self):
        return _read(self.out).strip()

    def test_writes_a_three_segment_token(self):
        proc = self.forge()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.token().count("."), 2)

    def test_header_is_rs256(self):
        self.forge()
        header, _, _, _ = keys.decode_jwt(self.token())
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})

    def test_claim_set(self):
        """Every claim but the time fields and the random jti is fixed."""
        self.forge()
        _, payload, _, _ = keys.decode_jwt(self.token())
        fixed = {k: v for k, v in payload.items()
                 if k not in ("iat", "exp", "jti")}
        self.assertEqual(fixed, {
            "iss": SERVER_ID,
            "sub": USER,
            "aud": "api",
            "fastx/auth-method": "web-ssh",
            "fastx/gateway-serverId": SERVER_ID,
            "fastx/gateway-hostname": "fastx-host",
            "fastx/hostname": "fastx-host",
            "fastx/client-ip": "::ffff:127.0.0.1",
            "fastx/terms-accepted": "",
        })

    def test_hostname_derivation_other_serverid_and_no_dash(self):
        """The hostname claim is serverId minus its last dash segment, not a
        hardcoded constant: check a second dashed serverId and one with no
        dash at all (used as-is)."""
        for server_id, expected_host in (
                ("other-box-xyz", "other-box"),
                ("noDashHere", "noDashHere")):
            sid = os.path.join(self.tmp, "serverId2.txt")
            with open(sid, "w") as fh:
                fh.write(server_id + "\n")
            out = os.path.join(self.tmp, "tok2.jwt")
            proc = subprocess.run(
                forge_cmd() + ["-k", self.key, "-s", sid, "-u", USER,
                               "-o", out],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            _, payload, _, _ = keys.decode_jwt(_read(out).strip())
            self.assertEqual(payload["fastx/gateway-hostname"], expected_host)
            self.assertEqual(payload["fastx/hostname"], expected_host)

    def test_iat_and_exp_are_integers_an_hour_apart_by_default(self):
        before = int(time.time())
        self.forge()
        after = int(time.time())
        _, payload, _, _ = keys.decode_jwt(self.token())
        self.assertIsInstance(payload["iat"], int)
        self.assertEqual(payload["exp"] - payload["iat"], 3600)
        self.assertGreaterEqual(payload["iat"], before)
        self.assertLessEqual(payload["iat"], after)

    def test_exp_flag_sets_the_window(self):
        self.forge("-e", "60")
        _, payload, _, _ = keys.decode_jwt(self.token())
        self.assertEqual(payload["exp"] - payload["iat"], 60)

    def test_jti_is_fresh_each_run(self):
        self.forge()
        first = keys.decode_jwt(self.token())[1]["jti"]
        self.forge()
        second = keys.decode_jwt(self.token())[1]["jti"]
        self.assertNotEqual(first, second)

    def test_signature_verifies_against_the_public_key(self):
        self.forge()
        _, _, sig, signing_input = keys.decode_jwt(self.token())
        sig_path = os.path.join(self.tmp, "sig.bin")
        msg_path = os.path.join(self.tmp, "msg.bin")
        with open(sig_path, "wb") as fh:
            fh.write(sig)
        with open(msg_path, "wb") as fh:
            fh.write(signing_input)
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", self.pub,
             "-signature", sig_path, msg_path],
            capture_output=True, text=True)
        self.assertIn("Verified OK", proc.stdout)

    def test_token_file_is_exactly_the_token(self):
        """No trailing newline: the bytes on disk are the token and nothing
        else, and stdout reports that length."""
        proc = self.forge()
        with open(self.out, "rb") as fh:
            raw = fh.read()
        self.assertEqual(raw, raw.strip())
        self.assertEqual(raw.count(b"."), 2)
        self.assertIn("RS256 token, %d bytes" % len(raw), proc.stdout)

    def test_output_directory_component_prefix_only(self):
        """Only a directory component that starts with the word is refused;
        'epoch' merely contains 'poc'."""
        ok = os.path.join(self.tmp, "epoch")
        os.makedirs(ok)
        proc = self.forge_to(os.path.join(ok, "t.jwt"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bad = os.path.join(self.tmp, "evidence-2026")
        os.makedirs(bad)
        proc = self.forge_to(os.path.join(bad, "t.jwt"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing to write a bearer token", proc.stderr)

    def test_a_filename_containing_poc_is_not_refused(self):
        proc = self.forge_to(os.path.join(self.tmp, "poc.jwt"))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_missing_output_directory_is_a_usage_error(self):
        proc = self.forge_to(os.path.join(self.tmp, "nope", "t.jwt"))
        self.assertEqual(proc.returncode, 64)
        self.assertIn("output directory does not exist", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_output_defaults_to_token_jwt_in_the_working_directory(self):
        proc = subprocess.run(
            forge_cmd() + ["-k", self.key, "-s", self.sid, "-u", USER],
            capture_output=True, text=True, timeout=30,
            cwd=self.tmp, env=dict(os.environ, PYTHONPATH=ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "token.jwt")))

    def test_empty_user_is_rejected(self):
        proc = subprocess.run(
            forge_cmd() + ["-k", self.key, "-s", self.sid, "-u", "",
                           "-o", self.out],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 64)
        self.assertFalse(os.path.exists(self.out))

    def test_serverid_loses_only_line_breaks(self):
        with open(self.sid, "w") as fh:
            fh.write("  spaced-id-abc \r\n")
        self.forge()
        _, payload, _, _ = keys.decode_jwt(self.token())
        self.assertEqual(payload["iss"], "  spaced-id-abc ")

    def test_unreadable_key_encoding_is_a_usage_error(self):
        with open(self.key, "wb") as fh:
            fh.write(b"\xff\xfe\x00bad")
        proc = self.forge()
        self.assertEqual(proc.returncode, 64)
        self.assertNotIn("Traceback", proc.stderr)

    def test_token_file_is_0600(self):
        self.forge()
        self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o600)

    def test_token_not_printed_without_p(self):
        proc = self.forge()
        self.assertNotIn(self.token(), proc.stdout)

    def test_token_printed_with_p(self):
        proc = self.forge("-p")
        self.assertIn(self.token(), proc.stdout)

    def test_refuses_an_evidence_path(self):
        dest = os.path.join(self.tmp, "evidence", "tok.jwt")
        os.makedirs(os.path.dirname(dest))
        proc = subprocess.run(
            forge_cmd() + ["-k", self.key, "-s", self.sid, "-u", USER,
                           "-o", dest],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing to write a bearer token", proc.stderr)
        self.assertFalse(os.path.exists(dest))

    def test_missing_serverid_is_a_usage_error(self):
        proc = subprocess.run(
            forge_cmd() + ["-k", self.key, "-u", USER, "-o", self.out],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.returncode, 64)
        self.assertIn("required", proc.stderr)
        self.assertTrue("-s" in proc.stderr or "serverid" in proc.stderr.lower())
