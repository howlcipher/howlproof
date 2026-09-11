"""The functional adversary's cheapest questions: does the artifact's own gate still hold?

Running a project's test suite is not adversarial by itself. What matters here is the
honesty of the reporting. A missing toolchain is UNAVAILABLE, an absent surface is
NOT_APPLICABLE, an environment that would not build is UNAVAILABLE rather than a
failure of the artifact, and none of them is ever allowed to resemble a pass.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from howlproof.evaluators import pyenv
from howlproof.model import Adversary, Confidence, Severity
from howlproof.registry import Context, Evaluator, Outcome


def transcript(payload: dict[str, object]) -> str:
    return "\n".join(
        [
            f"argv: {payload['argv']}",
            f"exit_code: {payload['exit_code']}",
            "",
            "--- stdout ---",
            str(payload["stdout"]),
            "",
            "--- stderr ---",
            str(payload["stderr"]),
        ]
    )


class _Command(Evaluator):
    """One deterministic command whose exit status is the observation."""

    adversary = Adversary.FUNCTIONAL
    marker_files: tuple[str, ...] = ()
    category = "correctness"
    severity = Severity.HIGH
    limitation = "exit status only; it does not establish that the suite is adequate"
    timeout = 1800

    def argv(self, context: Context) -> Sequence[str]:
        raise NotImplementedError

    def unavailable_reason(self, context: Context) -> str:
        """Non-empty when the check cannot run for environmental reasons."""
        return ""

    def applicable(self, context: Context) -> tuple[bool, str]:
        if any(context.target.exists(name) for name in self.marker_files):
            return True, ""
        markers = ", ".join(self.marker_files) or "a recognised marker"
        return False, f"the artifact contains no {markers}"

    def evaluate(self, context: Context) -> Outcome:
        reason = self.unavailable_reason(context)
        if reason:
            return Outcome(checks=[self.unavailable(reason)])
        argv = list(self.argv(context))
        result = context.target.run(argv, timeout=self.timeout)
        ref = context.save_evidence(self.id, "command.txt", transcript(result.to_dict()))
        printable = " ".join(argv)
        if result.timed_out:
            return Outcome(checks=[self.unavailable(f"`{printable}` exceeded {self.timeout}s")])
        if result.ok:
            return Outcome(
                checks=[
                    self.verified(
                        f"`{printable}` exited 0",
                        self.limitation,
                        evidence_refs=[ref],
                        duration_ms=result.duration_ms,
                    )
                ]
            )
        excerpt = (result.stdout + "\n" + result.stderr).strip()[-3000:]
        return Outcome(
            checks=[
                self.failed(
                    f"`{printable}` exited {result.exit_code}",
                    self.limitation,
                    evidence_refs=[ref],
                    duration_ms=result.duration_ms,
                    detail={"exit_code": result.exit_code},
                )
            ],
            findings=[
                self.finding(
                    title=f"{self.id} fails on the artifact as committed",
                    category=self.category,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"`{printable}` exits {result.exit_code} in a clean, freshly provisioned "
                        "copy of the artifact."
                    ),
                    evidence=excerpt or f"exit code {result.exit_code} with no output",
                    remediation="Repair the failing command in the artifact's own repository.",
                    rule=self.id,
                )
            ],
        )


class _PythonCommand(_Command):
    """A command run through the environment provisioned for the artifact."""

    marker_files = ("pyproject.toml",)
    module = ""
    tail: tuple[str, ...] = ()
    tools: ClassVar[dict[str, list[str]]] = {"python3": ["python3", "--version"]}

    def unavailable_reason(self, context: Context) -> str:
        if not context.tool_available("python3"):
            return context.tool_reason("python3")
        env = pyenv.provision(context)
        if not env.ready:
            return env.reason
        assert env.python is not None
        probe = context.target.run([env.python, "-c", f"import {self.module}"], timeout=120)
        if not probe.ok:
            return (
                f"{self.module} is not installed in the artifact's own environment; "
                "the artifact does not declare it as a development dependency"
            )
        return ""

    def argv(self, context: Context) -> Sequence[str]:
        env = pyenv.provision(context)
        assert env.python is not None
        return [env.python, "-m", self.module, *self.tail]


class PythonTests(_PythonCommand):
    """Run the artifact's own Python test suite in an environment provisioned for it."""

    id = "python.tests"
    module = "pytest"
    tail = ("-q",)
    limitation = (
        "a passing suite shows the tests the artifact chose to write pass; it does not show "
        "that the suite covers the behaviour that matters"
    )


class PythonTypes(_PythonCommand):
    """Run the artifact's own type checker over the code it declares."""

    id = "python.types"
    module = "mypy"
    severity = Severity.MEDIUM
    limitation = "static types only; runtime values and dynamic attribute access are unchecked"


class PythonLint(_PythonCommand):
    """Run the artifact's own linter."""

    id = "python.lint"
    module = "ruff"
    # Excluding the provisioned environment keeps the result about the artifact.
    tail = ("check", ".", "--exclude", pyenv.VENV_DIR)
    category = "simplicity"
    severity = Severity.LOW
    limitation = "style and a narrow set of correctness lints, not program behaviour"


class PythonBuild(_PythonCommand):
    """Build the artifact's distribution, because a package that will not build cannot ship."""

    id = "python.build"
    module = "build"
    tail = ("--outdir", ".howlproof-dist")
    severity = Severity.MEDIUM
    limitation = (
        "the distribution builds; it does not establish that the built wheel installs or runs"
    )


class _GoCommand(_Command):
    marker_files = ("go.mod",)
    tools: ClassVar[dict[str, list[str]]] = {"go": ["go", "version"]}

    def unavailable_reason(self, context: Context) -> str:
        return "" if context.tool_available("go") else context.tool_reason("go")


class GoVet(_GoCommand):
    """Run go vet over the artifact's Go source."""

    id = "go.vet"
    limitation = "vet's fixed catalogue of mistakes, not general correctness"

    def argv(self, context: Context) -> Sequence[str]:
        return ["go", "vet", "./..."]


class GoTest(_GoCommand):
    """Run the artifact's own Go tests."""

    id = "go.test"
    limitation = (
        "runs the artifact's own Go tests; whether those tests are adequate is a separate "
        "question this check does not answer"
    )

    def argv(self, context: Context) -> Sequence[str]:
        return ["go", "test", "./..."]


class GoFmt(Evaluator):
    """gofmt reports by printing names, so exit status alone would be misleading."""

    id = "go.fmt"
    adversary = Adversary.FUNCTIONAL
    tools: ClassVar[dict[str, list[str]]] = {"gofmt": ["gofmt", "-h"]}

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists("go.mod"):
            return True, ""
        return False, "the artifact contains no go.mod"

    def evaluate(self, context: Context) -> Outcome:
        if not context.tool_available("gofmt"):
            return Outcome(checks=[self.unavailable(context.tool_reason("gofmt"))])
        result = context.target.run(["gofmt", "-l", "."], timeout=300)
        unformatted = [
            line for line in result.stdout.splitlines() if line.strip() and ".howlproof" not in line
        ]
        ref = context.save_evidence(self.id, "gofmt.txt", result.stdout + result.stderr)
        limitation = "formatting only; it says nothing about correctness"
        if not unformatted:
            return Outcome(
                checks=[
                    self.verified(
                        "gofmt reports no unformatted files",
                        limitation,
                        evidence_refs=[ref],
                        duration_ms=result.duration_ms,
                    )
                ]
            )
        return Outcome(
            checks=[
                self.failed(
                    f"gofmt lists {len(unformatted)} unformatted files",
                    limitation,
                    evidence_refs=[ref],
                    duration_ms=result.duration_ms,
                    detail={"files": unformatted[:50]},
                )
            ]
        )


EVALUATORS: list[Evaluator] = [
    PythonTests(),
    PythonTypes(),
    PythonLint(),
    PythonBuild(),
    GoVet(),
    GoTest(),
    GoFmt(),
]
