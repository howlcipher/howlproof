"""The howl.interop/v1 descriptor matches the real command line."""

import json
import re

from howlproof import __version__
from howlproof.cli import build_parser, main

FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*$")
SCHEMA_ID = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+/v[0-9]+$")


def describe(capsys):
    assert main(["interop", "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def test_descriptor_shape_and_exit_table(capsys):
    d = describe(capsys)
    assert (d["schema"], d["component"], d["version"]) == (
        "howl.interop/v1",
        "howlproof",
        __version__,
    )
    assert set(d["exit_codes"]) == {"0", "2", "3", "4", "10", "20", "30", "40"}
    for command in d["commands"]:
        assert all(FLAG.match(f) for f in command["flags"]), command
        assert all(SCHEMA_ID.match(s) for s in command.get("emits", [])), command


def test_every_subcommand_and_flag_is_described(capsys):
    described = {tuple(c["path"]): set(c["flags"]) for c in describe(capsys)["commands"]}
    subparsers = next(
        a for a in build_parser()._actions if a.__class__.__name__ == "_SubParsersAction"
    )
    for name, sub in subparsers.choices.items():
        flags = {o for a in sub._actions for o in a.option_strings} - {"-h", "--help"}
        assert described[(name,)] == flags, name


def test_declares_the_plane_command_it_runs(capsys):
    (use,) = describe(capsys)["consumes"]
    assert use == {
        "component": "howlplane",
        "command": ["reconcile"],
        "flags": ["--findings-file", "--output"],
    }
