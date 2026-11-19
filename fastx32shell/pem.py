"""RS256 with nothing but the standard library.

A JWT signature is RSASSA-PKCS1-v1_5 over SHA-256, which is a hash, a fixed
DigestInfo prefix, a padding string, and one modular exponentiation. Python's
integers do the last part natively, so the only real work is pulling n and d
out of the PEM.

Verified against `openssl dgst -sha256 -sign`: for the same key and message
the output is byte-identical, and openssl verifies what this produces. See
tests/test_pem.py.

A passphrase-encrypted key is out of scope. Decrypting PEM needs PBES2 and
AES, which the standard library does not provide, and a signing key lifted
off a FastX host is not encrypted: the service loads it without a prompt.
"""
import base64
import hashlib

# DigestInfo for SHA-256, RFC 8017 section 9.2 notes.
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class PemError(Exception):
    """The key could not be read. Carries the remedy where there is one."""


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _read_der(data, index):
    """Return (tag, contents, next_index) for the TLV at index."""
    if index + 2 > len(data):
        raise PemError("truncated DER")
    tag = data[index]
    length = data[index + 1]
    index += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[index:index + count], "big")
        index += count
    end = index + length
    if end > len(data):
        raise PemError("DER length runs past the end of the key")
    return tag, data[index:end], end


def _sequence_items(body):
    """Flatten one DER SEQUENCE into its integers and nested blobs."""
    items, index = [], 0
    while index < len(body):
        tag, contents, index = _read_der(body, index)
        if tag == 0x02:
            items.append(int.from_bytes(contents, "big"))
        elif tag in (0x30, 0x04):
            items.append(contents)
    return items


def load_private_key(text):
    """Return (modulus, private_exponent) from a PKCS#1 or PKCS#8 PEM."""
    if "ENCRYPTED" in text or "Proc-Type: 4,ENCRYPTED" in text:
        raise PemError(
            "the private key is passphrase-encrypted; decrypt it first:\n"
            "  openssl rsa -in <key> -out plain.pem")
    if "PRIVATE KEY" not in text:
        raise PemError("not an RSA private key in PEM form")

    body = "".join(line for line in text.splitlines()
                   if line and "-----" not in line)
    try:
        der = base64.b64decode(body, validate=True)
    except Exception:
        raise PemError("the PEM body is not valid base64")

    _, outer, _ = _read_der(der, 0)
    items = _sequence_items(outer)

    # PKCS#8 wraps the PKCS#1 key in an OCTET STRING; unwrap it.
    for item in items:
        if isinstance(item, bytes) and item[:1] == b"\x30":
            _, inner, _ = _read_der(item, 0)
            items = _sequence_items(inner)
            break

    numbers = [item for item in items if isinstance(item, int)]
    if len(numbers) < 4:
        raise PemError("the key does not carry an RSA private exponent")
    # PKCS#1 RSAPrivateKey: version, n, e, d, p, q, ...
    return numbers[1], numbers[3]


def sign_rs256(message, n, d):
    """RSASSA-PKCS1-v1_5 over SHA-256. Returns the raw signature."""
    size = (n.bit_length() + 7) // 8
    digest_info = SHA256_PREFIX + hashlib.sha256(message).digest()
    if size < len(digest_info) + 11:
        raise PemError("the key is too small to sign a SHA-256 digest")
    padded = (b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3)
              + b"\x00" + digest_info)
    return pow(int.from_bytes(padded, "big"), d, n).to_bytes(size, "big")
