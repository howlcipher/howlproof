"""The human adversary: what would a careful operator hit, and what does the artifact claim?

Documentation is part of the artifact. A README that promises something the code does
not do is a defect, and an absolute claim is the easiest kind to test.
"""

from __future__ import annotations

import json
import re
from typing import Any

from howlproof.evaluators import pyenv
from howlproof.evaluators.code import transcript
from howlproof.model import Adversary, Confidence, Reproduction, ReproductionStep, Severity
from howlproof.registry import Context, Evaluator, Outcome

#: Claims that assert universality. Each one is a promise that a single counterexample breaks.
ABSOLUTE = re.compile(
    r"(?i)\b(?:every|always|never|cannot|can not|all of|none of|no hand-written|"
    r"guarantee[sd]?|impossible|100%|fully verified|completely)\b"
)

#: Sentences that only describe an absence of intent rather than a testable promise.
HEDGES = re.compile(r"(?i)\b(?:not yet|does not yet|planned|roadmap|future|intended to|aims to)\b")

#: Input a careful operator could plausibly type by accident.
MISUSE_ARGUMENTS: tuple[tuple[str, list[str]], ...] = (
    ("no_arguments", []),
    ("unknown_subcommand", ["definitely-not-a-command"]),
    ("unknown_flag", ["--definitely-not-a-flag"]),
    ("empty_string_argument", [""]),
    ("path_that_does_not_exist", ["evaluate", "/nonexistent/path/for/howlproof"]),
)

LEAK_MARKERS = ("Traceback (most recent call last)", "panic: ", "goroutine ")


class DocsClaims(Evaluator):
    """Collect the artifact's absolute claims so each one can be answered with evidence."""

    id = "docs.claims"
    adversary = Adversary.OPERATOR

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.docs and (
            context.config.docs.claim_sources or context.config.docs.synced_pairs
        ):
            return True, ""
        return False, "the artifact declares no documentation to hold to account"

    def evaluate(self, context: Context) -> Outcome:
        docs = context.config.docs
        assert docs is not None
        checks, findings = [], []

        claims = self._claims(context, docs.claim_sources)
        ref = context.save_evidence_json(self.id, "absolute-claims.json", claims)
        limitation = (
            "it locates absolute claims and reports them for adversarial attention; it does not "
            "by itself decide whether each claim is true"
        )
        # An absolute claim is a lead for the other adversaries, not a verdict by itself,
        # so it is raised at INFORMATIONAL: visible in the report, never blocking.
        checks.append(
            self.verified(
                f"{len(claims)} absolute documentation claims collected for challenge"
                if claims
                else "the documentation makes no absolute claims",
                limitation,
                suffix="absolutes",
                evidence_refs=[ref],
                detail={"count": len(claims), "claims": claims[:20]},
            )
        )
        if claims:
            findings.append(
                self.finding(
                    title=f"{len(claims)} absolute documentation claims are unverified",
                    category="other",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CONFIRMED,
                    summary=(
                        "The documentation asserts these without qualification. Each one is a "
                        "promise a single counterexample breaks, and this evaluation did not "
                        "independently establish any of them: "
                        + "; ".join(
                            f"{c['file']}:{c['line']} {c['claim'][:90]}" for c in claims[:6]
                        )
                    ),
                    evidence=json.dumps(claims[:20], indent=2)[:3000],
                    remediation=(
                        "Qualify the claim, or add a check that would fail if it stopped being "
                        "true."
                    ),
                    rule="docs.claims.unverified_absolute",
                    suffix="absolutes",
                    reproduction=Reproduction.by_reevaluation(
                        "docs.claims",
                        "Re-scan the declared documentation for unqualified absolute claims.",
                    ),
                )
            )

        drift = self._drift(context, docs.synced_pairs)
        if docs.synced_pairs:
            drift_ref = context.save_evidence_json(self.id, "synced-pairs.json", drift)
            drift_limitation = (
                "byte comparison of the declared pairs at this commit; it does not detect "
                "semantic drift between files that are supposed to agree but are not copies"
            )
            diverged = [row for row in drift if not row["identical"]]
            if diverged:
                checks.append(
                    self.failed(
                        f"{len(diverged)} of {len(drift)} files documented as kept in sync differ",
                        drift_limitation,
                        suffix="sync",
                        evidence_refs=[drift_ref],
                    )
                )
                findings.append(
                    self.finding(
                        title="Files documented as synchronised have diverged",
                        category="correctness",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(
                            f"{row['left']} differs from {row['right']}" for row in diverged
                        ),
                        evidence=json.dumps(diverged, indent=2)[:2000],
                        remediation="Regenerate the derived copy, or stop documenting the two "
                        "as kept in sync.",
                        rule="docs.claims.sync_drift",
                        suffix="sync",
                        reproduction=Reproduction(
                            summary="Compare the declared pairs again.",
                            steps=[
                                ReproductionStep(
                                    description=f"Compare {row['left']} with {row['right']}",
                                    kind="file_probe",
                                    payload={"path": row["left"], "compare_with": row["right"]},
                                    expect={"identical": False},
                                )
                                for row in diverged
                            ],
                        ),
                    )
                )
            else:
                checks.append(
                    self.verified(
                        f"all {len(drift)} file pairs documented as synchronised are identical",
                        drift_limitation,
                        suffix="sync",
                        evidence_refs=[drift_ref],
                    )
                )
        return Outcome(checks=checks, findings=findings)

    @staticmethod
    def _claims(context: Context, sources: list[str]) -> list[dict[str, Any]]:
        claims: list[dict[str, object]] = []
        for pattern in sources:
            for name in context.target.glob(pattern):
                if not context.target.exists(name):
                    continue
                content = context.target.read_text(name)
                for index, line in enumerate(content.splitlines(), start=1):
                    if ABSOLUTE.search(line) and not HEDGES.search(line):
                        claims.append({"file": name, "line": index, "claim": line.strip()[:300]})
        return claims

    @staticmethod
    def _drift(context: Context, pairs: list[list[str]]) -> list[dict[str, Any]]:
        rows: list[dict[str, object]] = []
        for left, right in pairs:
            left_exists = context.target.exists(left)
            right_exists = context.target.exists(right)
            identical = (
                left_exists
                and right_exists
                and context.target.read_bytes(left) == context.target.read_bytes(right)
            )
            rows.append(
                {
                    "left": left,
                    "right": right,
                    "left_exists": left_exists,
                    "right_exists": right_exists,
                    "identical": identical,
                }
            )
        return rows


class CliContract(Evaluator):
    """Misuse the artifact's command line the way a tired operator would."""

    id = "cli.contract"
    adversary = Adversary.FUNCTIONAL

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.cli and context.config.cli.command:
            return True, ""
        return False, "the artifact declares no command line to exercise"

    def evaluate(self, context: Context) -> Outcome:
        cli = context.config.cli
        assert cli is not None
        if cli.needs_python_env:
            env = pyenv.provision(context)
            if not env.ready:
                return Outcome(checks=[self.unavailable(env.reason)])
        command = list(cli.command)
        transcripts: list[dict[str, object]] = []
        problems: list[str] = []
        for name, arguments in MISUSE_ARGUMENTS:
            try:
                result = context.target.run([*command, *arguments], timeout=120)
            except Exception as error:  # noqa: BLE001 - a missing binary is a real observation
                return Outcome(
                    checks=[self.unavailable(f"the declared command could not run: {error}")]
                )
            combined = result.stdout + result.stderr
            transcripts.append({"case": name, **result.to_dict()})
            if result.timed_out:
                problems.append(f"{name}: the command did not terminate")
                continue
            if result.exit_code == 0:
                problems.append(f"{name}: exited 0 despite invalid input")
            if any(marker in combined for marker in LEAK_MARKERS):
                problems.append(f"{name}: printed an unhandled traceback")
            if not combined.strip():
                problems.append(f"{name}: failed silently with no message")

        help_result = context.target.run([*command, cli.help_flag], timeout=120)
        transcripts.append({"case": "help", **help_result.to_dict()})
        if not help_result.ok:
            problems.append(f"{cli.help_flag} exited {help_result.exit_code}")

        ref = context.save_evidence_json(self.id, "cli-contract.json", transcripts)
        limitation = (
            "a fixed catalogue of misuse cases against the declared entry point; it does not "
            "enumerate every subcommand or flag combination"
        )
        if problems:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(problems)} of {len(MISUSE_ARGUMENTS) + 1} command-line cases "
                        "behaved poorly",
                        limitation,
                        evidence_refs=[ref],
                        detail={"problems": problems},
                    )
                ],
                findings=[
                    self.finding(
                        title="The command line does not fail cleanly on invalid input",
                        category="correctness",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(problems[:8]),
                        evidence=transcript(transcripts[0]),
                        remediation="Exit non-zero with a short, actionable message and no "
                        "traceback for every invalid invocation.",
                        rule="cli.contract.unclean_failure",
                        reproduction=Reproduction(
                            summary="Invoke the declared command with invalid arguments.",
                            steps=[
                                ReproductionStep(
                                    description=f"Run `{' '.join(command + list(arguments))}`",
                                    kind="command",
                                    payload={"argv": command + list(arguments)},
                                    expect={"exit_code": 0},
                                )
                                for name, arguments in MISUSE_ARGUMENTS[:2]
                            ],
                        ),
                    )
                ],
            )
        return Outcome(
            checks=[
                self.verified(
                    f"{len(MISUSE_ARGUMENTS)} invalid invocations failed cleanly and "
                    f"`{cli.help_flag}` succeeded",
                    limitation,
                    evidence_refs=[ref],
                )
            ]
        )


class CliDestructive(Evaluator):
    """Destructive operations should be hard to reach by accident."""

    id = "cli.destructive"
    adversary = Adversary.OPERATOR

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.cli and context.config.cli.destructive_subcommands:
            return True, ""
        return False, "the artifact declares no destructive subcommands to inspect"

    def evaluate(self, context: Context) -> Outcome:
        cli = context.config.cli
        assert cli is not None
        if cli.needs_python_env:
            env = pyenv.provision(context)
            if not env.ready:
                return Outcome(checks=[self.unavailable(env.reason)])
        rows: list[dict[str, object]] = []
        unguarded: list[str] = []
        for subcommand in cli.destructive_subcommands:
            result = context.target.run([*cli.command, subcommand, cli.help_flag], timeout=120)
            text = (result.stdout + result.stderr).lower()
            guarded = any(
                token in text for token in ("--force", "--yes", "--confirm", "--dry-run", "-f,")
            )
            rows.append(
                {"subcommand": subcommand, "guarded": guarded, "exit_code": result.exit_code}
            )
            if not guarded:
                unguarded.append(subcommand)
        ref = context.save_evidence_json(self.id, "destructive.json", rows)
        limitation = (
            "reads each destructive subcommand's own help text for a confirmation or dry-run "
            "flag; it does not execute the destructive operation"
        )
        if unguarded:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(unguarded)} destructive subcommands advertise no confirmation or "
                        "dry-run flag",
                        limitation,
                        evidence_refs=[ref],
                    )
                ],
                findings=[
                    self.finding(
                        title="Destructive subcommands offer no guard",
                        category="other",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        summary="These subcommands are documented as destructive but their help "
                        f"text advertises no confirmation or dry run: {', '.join(unguarded)}",
                        evidence=json.dumps(rows, indent=2),
                        remediation="Add an explicit confirmation or a dry-run mode and mention "
                        "it in the help text.",
                        rule="cli.destructive.unguarded",
                    )
                ],
            )
        return Outcome(
            checks=[
                self.verified(
                    f"all {len(rows)} destructive subcommands advertise a guard",
                    limitation,
                    evidence_refs=[ref],
                )
            ]
        )


EVALUATORS: list[Evaluator] = [DocsClaims(), CliContract(), CliDestructive()]
