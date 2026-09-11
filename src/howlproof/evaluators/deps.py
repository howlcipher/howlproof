"""Third-party security tooling, used when present and reported as absent when not.

These two checks exist to be honest about their own availability. A dependency audit
that quietly does not run is worse than no dependency audit, because the result reads
the same as a clean one.
"""

from __future__ import annotations

import json
from typing import ClassVar

from howlproof.evaluators import pyenv
from howlproof.evaluators.code import transcript
from howlproof.model import Adversary, Confidence, Severity
from howlproof.registry import Context, Evaluator, Outcome


class DependencyAudit(Evaluator):
    """pip-audit against the artifact's own resolved environment."""

    id = "deps.audit"
    adversary = Adversary.SECURITY
    tools: ClassVar[dict[str, list[str]]] = {"python3": ["python3", "--version"]}

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists("pyproject.toml") or context.target.exists("requirements.txt"):
            return True, ""
        return False, "the artifact declares no Python dependencies to audit"

    def evaluate(self, context: Context) -> Outcome:
        if not context.allow_network:
            return Outcome(
                checks=[
                    self.skipped(
                        "a dependency audit queries a remote advisory database and network "
                        "access was not granted with --allow-network; no vulnerability was "
                        "checked for and none is implied to be absent"
                    )
                ]
            )
        env = pyenv.provision(context)
        if not env.ready:
            return Outcome(checks=[self.unavailable(env.reason)])
        assert env.python is not None
        probe = context.target.run([env.python, "-c", "import pip_audit"], timeout=120)
        if not probe.ok:
            return Outcome(
                checks=[
                    self.unavailable(
                        "pip-audit is not installed in the artifact's environment, so its "
                        "dependencies were not audited"
                    )
                ]
            )
        result = context.target.run(
            [env.python, "-m", "pip_audit", "--skip-editable", "--format", "json"], timeout=900
        )
        ref = context.save_evidence(self.id, "pip-audit.txt", transcript(result.to_dict()))
        limitation = (
            "known advisories for resolved Python dependencies at this moment; it says nothing "
            "about undisclosed vulnerabilities or non-Python dependencies"
        )
        if result.timed_out:
            return Outcome(checks=[self.unavailable("pip-audit did not finish within 900s")])
        try:
            report = json.loads(result.stdout or "{}")
        except ValueError:
            report = {}
        vulnerable = [
            dependency
            for dependency in (report.get("dependencies") or [])
            if dependency.get("vulns")
        ]
        if result.ok and not vulnerable:
            return Outcome(
                checks=[
                    self.verified(
                        "no known advisories for the resolved dependencies",
                        limitation,
                        evidence_refs=[ref],
                    )
                ]
            )
        names = ", ".join(sorted({str(d.get("name")) for d in vulnerable})) or "unnamed packages"
        return Outcome(
            checks=[
                self.failed(
                    f"{len(vulnerable)} dependencies carry known advisories",
                    limitation,
                    evidence_refs=[ref],
                )
            ],
            findings=[
                self.finding(
                    title="Dependencies carry known advisories",
                    category="security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    summary=f"pip-audit reports advisories for: {names}",
                    evidence=(result.stdout or result.stderr)[:4000],
                    remediation="Upgrade the affected dependencies or record an explicit, "
                    "time-bounded exclusion with a reason.",
                    rule="deps.audit.known_advisory",
                    aggregate=True,
                )
            ],
        )


class StaticAnalysis(Evaluator):
    """bandit over the artifact's own Python source."""

    id = "sast.bandit"
    adversary = Adversary.SECURITY
    tools: ClassVar[dict[str, list[str]]] = {"python3": ["python3", "--version"]}

    def applicable(self, context: Context) -> tuple[bool, str]:
        if any(True for _ in context.target.iter_files(".py")):
            return True, ""
        return False, "the artifact contains no Python source to analyse"

    def evaluate(self, context: Context) -> Outcome:
        env = pyenv.provision(context)
        if not env.ready:
            return Outcome(checks=[self.unavailable(env.reason)])
        assert env.python is not None
        probe = context.target.run([env.python, "-c", "import bandit"], timeout=120)
        if not probe.ok:
            return Outcome(
                checks=[
                    self.unavailable(
                        "bandit is not installed in the artifact's environment, so its Python "
                        "source was not statically analysed"
                    )
                ]
            )
        source = "src" if context.target.exists("src") else "."
        result = context.target.run(
            [env.python, "-m", "bandit", "-r", source, "-ll", "-f", "json"], timeout=900
        )
        ref = context.save_evidence(self.id, "bandit.txt", transcript(result.to_dict()))
        limitation = (
            "bandit's pattern catalogue at medium severity and above; it finds known shapes of "
            "insecure code, not logic or authority flaws"
        )
        try:
            report = json.loads(result.stdout or "{}")
        except ValueError:
            report = {}
        issues = report.get("results") or []
        if not issues:
            return Outcome(
                checks=[
                    self.verified(
                        f"bandit reports no medium or high findings in {source}",
                        limitation,
                        evidence_refs=[ref],
                    )
                ]
            )
        return Outcome(
            checks=[
                self.failed(
                    f"bandit reports {len(issues)} findings in {source}",
                    limitation,
                    evidence_refs=[ref],
                )
            ],
            findings=[
                self.finding(
                    title=f"{issue.get('test_id')}: {issue.get('issue_text', '')[:120]}",
                    category="security",
                    severity=(
                        Severity.HIGH if issue.get("issue_severity") == "HIGH" else Severity.MEDIUM
                    ),
                    confidence=Confidence.MEDIUM,
                    summary=str(issue.get("issue_text", "")),
                    evidence=str(issue.get("code", ""))[:2000] or json.dumps(issue)[:2000],
                    remediation="Address the pattern or record an explicit suppression with a "
                    "reason in the artifact's own configuration.",
                    location=f"{issue.get('filename')}:{issue.get('line_number')}",
                    rule=f"sast.bandit.{issue.get('test_id')}",
                )
                for issue in issues[:25]
            ],
        )


EVALUATORS: list[Evaluator] = [DependencyAudit(), StaticAnalysis()]
