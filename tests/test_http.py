import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request

from fastx32shell import http


class Opener(unittest.TestCase):
    def test_insecure_disables_verification(self):
        opener = http.make_opener(insecure=True)
        ctx = self._context(opener)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_default_verifies(self):
        ctx = self._context(http.make_opener())
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_follow_redirects_false_installs_norredirect(self):
        opener = http.make_opener(follow_redirects=False)
        self.assertTrue(any(isinstance(h, http.NoRedirect)
                            for h in opener.handlers))

    def test_follow_redirects_true_is_the_default(self):
        opener = http.make_opener()
        self.assertFalse(any(isinstance(h, http.NoRedirect)
                             for h in opener.handlers))

    def test_proxy_handler_added_when_asked(self):
        opener = http.make_opener(proxy="http://127.0.0.1:8080")
        self.assertTrue(any(isinstance(h, urllib.request.ProxyHandler)
                            for h in opener.handlers))

    @unittest.skipUnless(hasattr(ssl, "VERIFY_X509_STRICT"),
                         "no VERIFY_X509_STRICT in this ssl")
    def test_ca_clears_strict_but_keeps_verification(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not available to make a CA file")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        pem = os.path.join(tmp, "ca.pem")
        key = os.path.join(tmp, "ca.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", key, "-out", pem, "-days", "1",
                        "-subj", "/CN=test-ca"],
                       check=True, capture_output=True)
        ctx = self._context(http.make_opener(ca=pem))
        self.assertFalse(ctx.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    @staticmethod
    def _context(opener):
        for handler in opener.handlers:
            if isinstance(handler, urllib.request.HTTPSHandler):
                return handler._context
        raise AssertionError("no HTTPSHandler installed")


class Base(unittest.TestCase):
    def test_bare_host_gets_https(self):
        self.assertEqual(http.normalise_base("host:3300"),
                         "https://host:3300")

    def test_scheme_is_left_alone(self):
        self.assertEqual(http.normalise_base("http://host"), "http://host")

    def test_trailing_slash_trimmed(self):
        self.assertEqual(http.normalise_base("https://host/"), "https://host")


class _Boom(urllib.error.HTTPError):
    def read(self, *args):
        raise OSError("stalled")


class _Opener:
    def __init__(self, exc):
        self.exc = exc

    def open(self, req, timeout=None):
        raise self.exc


class Get(unittest.TestCase):
    def test_unreadable_error_body_keeps_the_status(self):
        exc = _Boom("http://x/", 503, "bad", {}, None)
        self.addCleanup(exc.close)
        status, body, headers = http.get(_Opener(exc), "http://x/", 1)
        self.assertEqual((status, body), (503, b""))

    def test_transport_error_name_inverts_the_format(self):
        status, body, _ = http.get(_Opener(TimeoutError("slow")),
                                   "http://x/", 1)
        self.assertIsNone(status)
        self.assertEqual(http.transport_error_name(body), "TimeoutError")
