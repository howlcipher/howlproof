"""Opt-in distribution smoke test, run after building the wheel in CI."""

import json
import os
import subprocess
import venv
from pathlib import Path

import pytest


def test_installed_wheel_supports_first_project_workflow(tmp_path):
    wheel_name = os.environ.get("HOWLPROOF_WHEEL")
    if not wheel_name:
        pytest.skip("set HOWLPROOF_WHEEL to exercise an isolated built distribution")
    wheel = Path(wheel_name).resolve(strict=True)
    runtime = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=True).create(runtime)
    bindir = runtime / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    launcher = bindir / ("howlproof.exe" if os.name == "nt" else "howlproof")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    imported = subprocess.run(
        [str(python), "-I", "-c", "import howlproof; print(howlproof.__file__)"],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert Path(imported.stdout.strip()).is_relative_to(runtime)

    def cli(*args):
        return subprocess.run(
            [str(launcher), *map(str, args)],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    target = tmp_path / "First project"
    target.mkdir()
    initialized = cli("init", target, "--require-check", "secrets.scan")
    assert initialized.returncode == 0, initialized.stderr
    assert cli("validate", target / "howlproof.yaml").returncode == 0
    evaluated = cli("evaluate", target, "--evidence-root", tmp_path / "evidence", "--json")
    assert evaluated.returncode == 0, evaluated.stderr
    result = json.loads(evaluated.stdout)
    assert result["verdict"] == "PROVEN"
    bundles = list((tmp_path / "evidence").glob("*/manifest.json"))
    assert len(bundles) == 1
    bundle = bundles[0].parent
    assert cli("inspect", bundle).returncode == 0
    assert cli("handoff", bundle, "--for", "plane").returncode == 0
    assert cli("report", bundle).returncode == 0
    # A subsequent defect must change the advisory result, using the same installed CLI.
    (target / "settings.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    rejected = cli("evaluate", target, "--evidence-root", tmp_path / "evidence", "--json")
    assert rejected.returncode == 30, rejected.stderr
    assert json.loads(rejected.stdout)["verdict"] == "REJECT"
