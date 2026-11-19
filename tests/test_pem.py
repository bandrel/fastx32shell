# tests/test_pem.py
import os
import subprocess
import tempfile
import unittest

from fastx32shell import pem
from tests import keys


def _read(path):
    with open(path) as fh:
        return fh.read()


class Sign(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fastx32shell-pem-")
        self.key, self.pub = keys.write_keypair(self.tmp)

    def test_signature_is_byte_identical_to_openssl(self):
        message = b"header.payload"
        n, d = pem.load_private_key(_read(self.key))
        mine = pem.sign_rs256(message, n, d)

        msg_path = os.path.join(self.tmp, "msg.bin")
        with open(msg_path, "wb") as fh:
            fh.write(message)
        theirs = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.key, msg_path],
            check=True, capture_output=True).stdout
        self.assertEqual(mine, theirs)

    def test_signature_length_matches_the_modulus(self):
        n, d = pem.load_private_key(_read(self.key))
        self.assertEqual(len(pem.sign_rs256(b"x", n, d)), 256)

    def test_reads_pkcs1_layout(self):
        """BEGIN RSA PRIVATE KEY, the traditional layout."""
        pkcs1 = os.path.join(self.tmp, "pkcs1.pem")
        subprocess.run(["openssl", "rsa", "-in", self.key, "-traditional",
                        "-out", pkcs1], check=True, capture_output=True)
        text = _read(pkcs1)
        self.assertIn("BEGIN RSA PRIVATE KEY", text)
        n, d = pem.load_private_key(text)
        self.assertEqual(n.bit_length(), 2048)

    def test_reads_pkcs8_layout(self):
        """BEGIN PRIVATE KEY, what openssl genrsa emits today."""
        text = _read(self.key)
        self.assertIn("BEGIN PRIVATE KEY", text)
        n, d = pem.load_private_key(text)
        self.assertEqual(n.bit_length(), 2048)

    def test_encrypted_key_names_the_remedy(self):
        enc = os.path.join(self.tmp, "enc.pem")
        subprocess.run(["openssl", "rsa", "-in", self.key, "-aes256",
                        "-passout", "pass:hunter2", "-out", enc],
                       check=True, capture_output=True)
        with self.assertRaises(pem.PemError) as caught:
            pem.load_private_key(_read(enc))
        self.assertIn("openssl rsa", str(caught.exception))

    def test_garbage_is_a_pem_error_not_a_traceback(self):
        with self.assertRaises(pem.PemError):
            pem.load_private_key("not a pem at all")

    def test_public_key_is_rejected(self):
        with self.assertRaises(pem.PemError):
            pem.load_private_key(_read(self.pub))


class Base64Url(unittest.TestCase):
    def test_strips_padding_and_uses_url_alphabet(self):
        self.assertEqual(pem.b64url(b"\xff\xff\xfe"), "___-")
        self.assertEqual(pem.b64url(b"a"), "YQ")
