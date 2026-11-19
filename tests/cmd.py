"""Where the tools live, in one place.

Every CLI-level test runs the real entry point as a child process. When the
scripts become subcommands this file is the only thing that changes.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tool(name):
    return [sys.executable, "-m", "fastx32shell", name]


def read_cmd():
    return _tool("read")


def rce_cmd():
    return _tool("rce")


def scan_cmd():
    return _tool("scan")


def forge_cmd():
    return _tool("forge")
