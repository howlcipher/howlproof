"""The CLI bridge preserves verdicts and fails closed before external ingestion."""

import json
import sys

import pytest

from howlproof.plane import ingest


def test_missing_plane_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="could not start"):
        ingest(
            {
                "verdict": "REJECT",
                "run_id": "hp-test",
                "findings": [],
                "artifact": "test",
                "version": "test",
                "target": {},
            },
            tmp_path / "run",
            executable=str(tmp_path / "absent"),
        )
    record = json.loads((tmp_path / "run" / "plane-ingestion.json").read_text())
    assert record["status"] == "ERROR"
    assert record["authority"] == "ADVISORY"


def test_timeout_is_recorded(tmp_path):
    tool = tmp_path / "slow"
    tool.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    tool.chmod(0o700)
    with pytest.raises(ValueError, match="timed out"):
        ingest(
            {
                "verdict": "REJECT",
                "run_id": "hp-test",
                "findings": [],
                "artifact": "test",
                "version": "test",
                "target": {},
            },
            tmp_path / "run",
            executable=str(tool),
            timeout=0.05,
        )
    assert json.loads((tmp_path / "run" / "plane-ingestion.json").read_text())["status"] == "ERROR"


def test_reject_survives_successful_reconciliation(tmp_path):
    tool = tmp_path / "plane"
    tool.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        "Path('reconciliation.md').write_text('reconciled')\n"
    )
    tool.chmod(0o700)
    result = {
        "verdict": "REJECT",
        "run_id": "hp-test",
        "findings": [],
        "artifact": "test",
        "version": "test",
        "target": {},
    }
    record = ingest(result, tmp_path / "run", executable=str(tool))
    assert record["proof_exit_code"] == 30
    assert record["plane_exit_code"] == 0
    assert record["exit_code"] == 30
    with pytest.raises(FileExistsError):
        ingest(result, tmp_path / "run", executable=str(tool))


def test_real_plane_reject_missing_tool_and_repaired_artifact(tmp_path):
    """Opt-in cross-repository contract test; CI provides an isolated Plane install."""
    import os

    from howlproof.cli import main
    from howlproof.config import ProofConfig, ToolRequired
    from howlproof.engine import evaluate
    from howlproof.evaluators import build_registry

    executable = os.environ.get("HOWLPROOF_PLANE")
    if not executable:
        pytest.skip("set HOWLPROOF_PLANE to run the real Plane CLI contract")
    target = tmp_path / "target"
    target.mkdir()
    source = target / "config.py"
    source.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    config = ProofConfig.model_validate(
        {
            "schema_version": 1,
            "artifact": "plane-contract",
            "profiles": ["secrets.scan"],
            "acceptance": [
                {"id": "AC-1", "requirement": "checks_pass", "checks": ["secrets.scan"]}
            ],
        }
    )
    registry = build_registry()
    rejected = evaluate(target, config, registry, tmp_path / "evidence")
    assert rejected["verdict"] == "REJECT"
    # Resolve the exact generated bundle; there is only one in this fresh test root.
    bundle = next(
        p
        for p in (tmp_path / "evidence").iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )
    assert (
        main(
            [
                "plane",
                str(bundle),
                "--run-dir",
                str(tmp_path / "reject"),
                "--executable",
                executable,
            ]
        )
        == 30
    )
    source.write_text('AWS_KEY = "from-environment"\n')
    repaired = evaluate(target, config, registry, tmp_path / "repaired-evidence")
    assert repaired["verdict"] != "REJECT"
    record = ingest(repaired, tmp_path / "repaired", executable=executable)
    assert record["proof_exit_code"] != 30
    missing = config.model_copy(
        update={
            "acceptance": [
                ToolRequired(
                    id="AC-2",
                    requirement="tool_required",
                    tools=["howlproof-deliberately-absent-tool"],
                )
            ]
        }
    )
    unavailable = evaluate(target, missing, registry, tmp_path / "missing-evidence")
    assert unavailable["verdict"] != "PROVEN"
    record = ingest(unavailable, tmp_path / "missing", executable=executable)
    assert record["exit_code"] != 0
    (bundle / "result.json").write_text("{}")
    assert (
        main(
            [
                "plane",
                str(bundle),
                "--run-dir",
                str(tmp_path / "tampered"),
                "--executable",
                executable,
            ]
        )
        != 0
    )
    assert not (tmp_path / "tampered").exists()


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_deadline_creates_no_run(tmp_path, timeout):
    with pytest.raises(ValueError, match="finite positive"):
        ingest({}, tmp_path / "run", timeout=timeout)
    assert not (tmp_path / "run").exists()


def test_success_without_report_is_not_ingestion(tmp_path):
    tool = tmp_path / "pretend-plane"
    tool.write_text(f"#!{sys.executable}\n")
    tool.chmod(0o700)
    result = {
        "verdict": "PROVEN",
        "run_id": "hp-test",
        "findings": [],
        "artifact": "test",
        "version": "test",
        "target": {},
    }
    with pytest.raises(ValueError, match="without a reconciliation report"):
        ingest(result, tmp_path / "run", executable=str(tool))
    record = json.loads((tmp_path / "run" / "plane-ingestion.json").read_text())
    assert record["status"] == "ERROR"
