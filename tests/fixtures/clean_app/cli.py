#!/usr/bin/env python3
"""The same command line, failing cleanly.

Invalid input exits non-zero with a short message and no traceback, which is what
cli.contract checks for.
"""

import sys

COMMANDS = {"status", "report"}


def main() -> int:
    arguments = sys.argv[1:]
    if "--help" in arguments:
        print("usage: cli.py [--help] {status,report}")
        return 0
    if not arguments:
        print("error: a command is required; try --help", file=sys.stderr)
        return 2
    if arguments[0] not in COMMANDS:
        print(f"error: unknown command {arguments[0]!r}; try --help", file=sys.stderr)
        return 2
    if len(arguments) > 1:
        print(f"error: {arguments[0]} takes no arguments", file=sys.stderr)
        return 2
    print(f"{arguments[0]}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
