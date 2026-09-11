#!/usr/bin/env python3
"""The same entry point, treating its input as data.

Untrusted text is quoted and summarised, never executed as instruction, and a model
response is validated against a closed shape before anything is read out of it.
"""

import json
import os
import sys

ALLOWED_FIELDS = {"result"}


def main() -> int:
    supplied = " ".join(sys.argv[1:])
    simulated = os.environ.get("HOWLPROOF_SIMULATED_MODEL_RESPONSE")
    if simulated is not None:
        try:
            parsed = json.loads(simulated)
        except ValueError:
            print("rejected: the model response is not valid JSON", file=sys.stderr)
            return 1
        if not isinstance(parsed, dict) or set(parsed) - ALLOWED_FIELDS:
            print("rejected: the model response does not match the closed schema", file=sys.stderr)
            return 1
        if not isinstance(parsed.get("result"), str):
            print("rejected: result must be a string", file=sys.stderr)
            return 1
        print(f"accepted result: {parsed['result']}")
        return 0
    print(f"received {len(supplied)} characters of untrusted text; treating it as data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
