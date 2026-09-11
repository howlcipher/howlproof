"""Provision an isolated interpreter for a Python artifact inside the workspace copy.

Running a project's tests against whatever happens to be on the evaluator's PATH
produces confident nonsense: import errors that belong to the environment get
reported as defects in the artifact. So the artifact is installed into its own
virtual environment, inside the workspace, and a provisioning failure is recorded
as an unavailable surface rather than a failing one.
"""

from __future__ import annotations

from pathlib import Path

from howlproof.registry import Context

VENV_DIR = ".howlproof-venv"
PROVISION_TIMEOUT = 900


class PythonEnv:
    """A provisioned interpreter, or an explanation of why there is not one."""

    def __init__(self, python: str | None, reason: str, log: str = "") -> None:
        self.python = python
        self.reason = reason
        self.log = log

    @property
    def ready(self) -> bool:
        return self.python is not None


def provision(context: Context) -> PythonEnv:
    """Create and populate the environment once per evaluation, then reuse it."""
    if isinstance(context.python_env, PythonEnv):
        return context.python_env
    context.python_env = _provision(context)
    return context.python_env


def _provision(context: Context) -> PythonEnv:
    target = context.target
    if not target.exists("pyproject.toml"):
        return PythonEnv(None, "the artifact has no pyproject.toml to install")

    created = target.run(["python3", "-m", "venv", VENV_DIR], timeout=300)
    if not created.ok:
        return PythonEnv(
            None,
            f"could not create a virtual environment: {(created.stderr or created.stdout)[-400:]}",
        )

    python = str(Path(VENV_DIR) / "bin" / "python")
    if not target.exists(f"{VENV_DIR}/bin/python"):
        return PythonEnv(None, "the created environment has no bin/python")

    upgrade = target.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-q",
            "--upgrade",
            "pip",
            "setuptools",
        ],
        timeout=PROVISION_TIMEOUT,
    )
    log = upgrade.stdout + upgrade.stderr

    for extras in (".[dev]", "."):
        installed = target.run(
            [python, "-m", "pip", "install", "--disable-pip-version-check", "-q", "-e", extras],
            timeout=PROVISION_TIMEOUT,
        )
        log += installed.stdout + installed.stderr
        if installed.ok:
            return PythonEnv(python, "", log[-8000:])

    return PythonEnv(
        None,
        "the artifact could not be installed into a clean environment: "
        + (log.strip()[-400:] or "no output"),
        log[-8000:],
    )
