#!/usr/bin/env python3
"""A command line that fails badly, so cli.contract has something to report.

It exits zero on invalid input and lets an exception reach the terminal, which is
the pair of behaviours a careful operator would be misled by.
"""

import sys


def main() -> int:
    if "--help" in sys.argv:
        print("usage: cli.py [--help] <command>")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "explode":
        raise RuntimeError("this reaches the terminal as a traceback")
    # Exits zero whatever it was given, including nothing at all.
    return 0


if __name__ == "__main__":
    sys.exit(main())
