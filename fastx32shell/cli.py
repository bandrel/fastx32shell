"""fastx32shell: one entry point for the FastX 3 replay tools.

Holds no tool logic. It builds the parser, attaches the shared network
arguments to the subcommands that talk to a target, dispatches to the tool
module's run(), and returns that tool's exit status unchanged. Exit codes
are documented per subcommand, in the module that produces them.
"""
import argparse
import sys

from fastx32shell import VERSION
from fastx32shell.tools import forge, rce, read, scan

EX_USAGE = 64

SUBCOMMANDS = (
    ("read", read, 25.0, "unauthenticated arbitrary file read"),
    ("rce", rce, 20.0, "unauthenticated command execution"),
    ("scan", scan, 10.0, "classify a build from its version string"),
    ("forge", forge, None, "forge an API token from a recovered signing key"),
)


class ArgumentParser(argparse.ArgumentParser):
    """Exits 64 on a usage error, so it never collides with a result code."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, "%s: error: %s\n" % (self.prog, message))


def add_network_args(parser, timeout):
    """The flags every target-facing subcommand shares.

    --timeout keeps each tool's own default: the read tool waits longer for a
    large file than the version scan does for one JSON object.
    """
    parser.add_argument("--timeout", type=float, default=timeout,
                        help="seconds per request (default: %g)" % timeout)
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (self-signed deployments)")
    parser.add_argument("--ca", default=None,
                        help="verify against this CA bundle")
    parser.add_argument("--proxy", default=None,
                        help="route through a proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--ua", default=None,
                        help="override the User-Agent")


def build_parser():
    parser = ArgumentParser(
        prog="fastx32shell", description="FastX 3 replay tooling.")
    parser.add_argument("--version", action="version", version=VERSION)
    subs = parser.add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND", parser_class=ArgumentParser)
    subs.required = True
    for name, module, timeout, summary in SUBCOMMANDS:
        sub = subs.add_parser(
            name, help=summary, description=summary,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=module.__doc__)
        module.add_arguments(sub)
        if timeout is not None:
            add_network_args(sub, timeout)
        sub.set_defaults(_run=module.run)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args._run(args)


if __name__ == "__main__":
    sys.exit(main())
