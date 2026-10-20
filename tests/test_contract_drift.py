"""Upstream schema edits must be detected even when the schema version is unchanged."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "drift", Path(__file__).parents[1] / "scripts/check_ecosystem_contracts.py"
)


def test_drift_detects_added_enum_member(tmp_path):
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    upstream = tmp_path / "upstream"
    vendor = tmp_path / "vendor"
    upstream.mkdir()
    vendor.mkdir()
    for name in module.NAMES:
        (upstream / name).write_text('{"enum": ["old"]}')
        (vendor / name).write_text('{ "enum": ["old"] }')
    assert module.differences(upstream, vendor) == []
    (upstream / module.NAMES[0]).write_text('{"enum": ["old", "new"]}')
    assert module.differences(upstream, vendor) == [module.NAMES[0]]
