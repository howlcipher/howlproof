"""The ``howl.interop/v1`` descriptor printed by ``howlproof interop --json``.

``howl doctor`` reads it to check that the commands other components run here
still exist, and that the one command HowlProof runs elsewhere
(``howlplane reconcile``) is still offered by the installed HowlPlane. It is
built from the live argparse tree. Contract:
https://github.com/howlcipher/howl/blob/main/docs/INTEROP.md
"""

from __future__ import annotations

import argparse
from typing import Any

from howlproof import __version__
from howlproof.evidence import HANDOFF_SCHEMA, RESULT_SCHEMA, RUN_SCHEMA
from howlproof.handoff import (
    EVIDENCE_ENTRY_SCHEMA,
    REVIEW_FINDING_SCHEMA,
    VERIFICATION_PLAN_SCHEMA,
)
from howlproof.ledger import LEDGER_SCHEMA
from howlproof.model import EXIT_CODES, EXIT_INTEGRITY, EXIT_INTERNAL, EXIT_USAGE

SCHEMA = "howl.interop/v1"

# Commands that always print JSON on stdout; others do so with --json or
# --format json.
ALWAYS_JSON = {
    "init",
    "calibrate",
    "validate",
    "doctor",
    "plane",
    "attest",
    "verify-attestation",
    "interop",
}

EMITS = {
    "evaluate": [RESULT_SCHEMA, RUN_SCHEMA, LEDGER_SCHEMA],
    "report": [RESULT_SCHEMA],
    "inspect": [RESULT_SCHEMA],
    "handoff": [
        HANDOFF_SCHEMA,
        REVIEW_FINDING_SCHEMA,
        EVIDENCE_ENTRY_SCHEMA,
        VERIFICATION_PLAN_SCHEMA,
    ],
    "plane": ["howlproof.plane_ingestion/v1"],
    "calibrate": ["howlproof.calibration/v1"],
    "interop": [SCHEMA],
}


def _flags(parser: argparse.ArgumentParser) -> list[str]:
    return sorted(
        option
        for action in parser._actions
        for option in action.option_strings
        if option not in ("-h", "--help")
    )


def _json_capable(parser: argparse.ArgumentParser, name: str) -> bool:
    if name in ALWAYS_JSON:
        return True
    for action in parser._actions:
        if "--json" in action.option_strings:
            return True
        if "--format" in action.option_strings and "json" in (action.choices or ()):
            return True
    return False


def describe(parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Return the descriptor for ``parser`` and its subcommands."""
    commands: list[dict[str, Any]] = [{"path": [], "flags": _flags(parser), "json": False}]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                entry: dict[str, Any] = {
                    "path": [name],
                    "flags": _flags(sub),
                    "json": _json_capable(sub, name),
                }
                if name in EMITS:
                    entry["emits"] = EMITS[name]
                commands.append(entry)
    exit_codes = {str(code): f"verdict {verdict.value}" for verdict, code in EXIT_CODES.items()}
    exit_codes[str(EXIT_USAGE)] = "usage or input error (JSON on stderr)"
    exit_codes[str(EXIT_INTERNAL)] = "internal error or interrupted"
    exit_codes[str(EXIT_INTEGRITY)] = "evidence or attestation integrity failure"
    exit_codes["0"] = "ok; for a verdict-producing command, verdict PROVEN"
    return {
        "schema": SCHEMA,
        "component": "howlproof",
        "version": __version__,
        "commands": commands,
        "exit_codes": exit_codes,
        "env": [],
        "consumes": [
            {
                "component": "howlplane",
                "command": ["reconcile"],
                "flags": ["--findings-file", "--output"],
            }
        ],
    }
