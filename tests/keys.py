"""A throwaway RSA keypair and a JWT decoder, for the forge tests."""
import base64
import json
import os
import subprocess


def write_keypair(tmpdir):
    private = os.path.join(tmpdir, "private.pem")
    public = os.path.join(tmpdir, "public.pem")
    subprocess.run(["openssl", "genrsa", "-out", private, "2048"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", private, "-pubout", "-out", public],
                   check=True, capture_output=True)
    return private, public


def _unpad(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_jwt(token):
    head, payload, sig = token.strip().split(".")
    return (json.loads(_unpad(head)), json.loads(_unpad(payload)),
            _unpad(sig), ("%s.%s" % (head, payload)).encode())
