"""The security adversary reads the artifact's build pipeline as an attack surface.

A workflow is code with credentials attached. These checks are deterministic text
and YAML analysis, so they run everywhere rather than only where a scanner exists.
"""

from __future__ import annotations

import re

import yaml

from howlproof.model import Adversary, Confidence, Reproduction, ReproductionStep, Severity
from howlproof.registry import Context, Evaluator, Outcome

WORKFLOW_DIR = ".github/workflows"
PINNED = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)

#: Expressions whose value an outside contributor can influence.
ATTACKER_CONTROLLED = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
)


class CiSupplyChain(Evaluator):
    """Read the build pipeline as an attack surface: pinning, triggers, permissions, injection."""

    id = "ci.supplychain"
    adversary = Adversary.SECURITY

    def applicable(self, context: Context) -> tuple[bool, str]:
        if self._workflows(context):
            return True, ""
        return False, f"the artifact has no {WORKFLOW_DIR} to analyse"

    def evaluate(self, context: Context) -> Outcome:
        checks = []
        findings = []
        workflows = self._workflows(context)
        issues: list[dict[str, object]] = []
        for name in workflows:
            content = context.target.read_text(name)
            issues.extend(_unpinned(name, content))
            issues.extend(_dangerous_trigger(name, content))
            issues.extend(_missing_permissions(name, content))
            issues.extend(_injectable_run(name, content))

        ref = context.save_evidence_json(self.id, "workflow-issues.json", issues)
        limitation = (
            "static analysis of workflow files in this checkout; it does not evaluate the "
            "repository's branch protection, org policy, or the actions' own contents"
        )
        if not issues:
            checks.append(
                self.verified(
                    f"{len(workflows)} workflows pin their actions, scope permissions and keep "
                    "untrusted expressions out of run blocks",
                    limitation,
                    evidence_refs=[ref],
                    detail={"workflows": workflows},
                )
            )
            return Outcome(checks=checks)

        checks.append(
            self.failed(
                f"{len(issues)} supply-chain weaknesses across {len(workflows)} workflows",
                limitation,
                evidence_refs=[ref],
                detail={"workflows": workflows, "issues": len(issues)},
            )
        )
        for issue in issues:
            findings.append(
                self.finding(
                    title=str(issue["title"]),
                    category="security",
                    severity=Severity[str(issue["severity"])],
                    confidence=Confidence.HIGH,
                    summary=str(issue["summary"]),
                    evidence=str(issue["evidence"]),
                    remediation=str(issue["remediation"]),
                    location=f"{issue['file']}:{issue['line']}",
                    rule=str(issue["rule"]),
                    reproduction=Reproduction(
                        summary="Re-read the workflow and match the same construct.",
                        steps=[
                            ReproductionStep(
                                description=f"Inspect {issue['file']} at line {issue['line']}.",
                                kind="file_probe",
                                payload={
                                    "path": issue["file"],
                                    "pattern": re.escape(str(issue["needle"])),
                                },
                                expect={"matches": True},
                            )
                        ],
                    ),
                )
            )
        return Outcome(checks=checks, findings=findings)

    @staticmethod
    def _workflows(context: Context) -> list[str]:
        return [
            name
            for name in context.target.iter_files(".yml", ".yaml")
            if name.startswith(WORKFLOW_DIR + "/")
        ]


def _line_of(content: str, needle: str) -> int:
    index = content.find(needle)
    return content.count("\n", 0, index) + 1 if index >= 0 else 1


def _unpinned(name: str, content: str) -> list[dict[str, object]]:
    issues = []
    for match in USES.finditer(content):
        reference = match.group(1).strip().strip("\"'")
        if reference.startswith(("./", "docker://")):
            continue
        action, separator, version = reference.partition("@")
        if not separator or PINNED.match(version):
            continue
        issues.append(
            {
                "file": name,
                "line": content.count("\n", 0, match.start()) + 1,
                "rule": "ci.unpinned_action",
                "severity": "MEDIUM",
                "title": f"{action} is pinned to a mutable reference",
                "summary": (
                    f"{name} runs {action} at `{version}`, a tag or branch the action's owner "
                    "can repoint at any time. A compromised or retagged action executes with "
                    "this workflow's token."
                ),
                "evidence": match.group(0).strip(),
                "needle": reference,
                "remediation": (
                    "Pin the action to a full 40-character commit SHA and record the intended "
                    "version in a comment."
                ),
            }
        )
    return issues


def _dangerous_trigger(name: str, content: str) -> list[dict[str, object]]:
    if "pull_request_target" not in content:
        return []
    return [
        {
            "file": name,
            "line": _line_of(content, "pull_request_target"),
            "rule": "ci.pull_request_target",
            "severity": "HIGH",
            "title": f"{name} triggers on pull_request_target",
            "summary": (
                "pull_request_target runs with repository secrets while the pull request's own "
                "code is available to check out. Combining it with a checkout of the head ref "
                "gives an outside contributor code execution with secrets in scope."
            ),
            "evidence": "on: pull_request_target",
            "needle": "pull_request_target",
            "remediation": (
                "Prefer `pull_request`. If `pull_request_target` is genuinely required, never "
                "check out or execute the pull request's code in that job."
            ),
        }
    ]


def _missing_permissions(name: str, content: str) -> list[dict[str, object]]:
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return [
            {
                "file": name,
                "line": 1,
                "rule": "ci.unparsable_workflow",
                "severity": "LOW",
                "title": f"{name} is not parsable YAML",
                "summary": "The workflow could not be parsed, so its permissions were not checked.",
                "evidence": "yaml.safe_load raised",
                "needle": "name:",
                "remediation": "Fix the YAML so the workflow can be analysed.",
            }
        ]
    if not isinstance(document, dict):
        return []
    if "permissions" in document:
        return []
    jobs = document.get("jobs") or {}
    if (
        isinstance(jobs, dict)
        and jobs
        and all(isinstance(job, dict) and "permissions" in job for job in jobs.values())
    ):
        return []
    return [
        {
            "file": name,
            "line": 1,
            "rule": "ci.default_permissions",
            "severity": "MEDIUM",
            "title": f"{name} declares no GITHUB_TOKEN permissions",
            "summary": (
                "Without an explicit `permissions:` block the workflow inherits the repository "
                "default, which may grant write access to contents, packages and more than the "
                "job needs."
            ),
            "evidence": "no top-level or per-job `permissions:` key",
            "needle": "jobs:",
            "remediation": "Add `permissions: {contents: read}` and widen only where required.",
        }
    ]


def _injectable_run(name: str, content: str) -> list[dict[str, object]]:
    issues = []
    for expression in ATTACKER_CONTROLLED:
        pattern = re.compile(r"\$\{\{\s*" + re.escape(expression) + r"\s*\}\}")
        for match in pattern.finditer(content):
            if not _inside_run_block(content, match.start()):
                continue
            issues.append(
                {
                    "file": name,
                    "line": content.count("\n", 0, match.start()) + 1,
                    "rule": "ci.expression_injection",
                    "severity": "HIGH",
                    "title": f"{name} interpolates {expression} into a shell step",
                    "summary": (
                        f"`{expression}` is controlled by whoever opens the pull request or "
                        "issue. Interpolating it directly into a `run:` block substitutes text "
                        "before the shell parses the script, so it becomes command injection."
                    ),
                    "evidence": match.group(0),
                    "needle": match.group(0),
                    "remediation": (
                        "Pass the value through an `env:` entry and reference it as a quoted "
                        "shell variable so the shell never parses attacker text as syntax."
                    ),
                }
            )
    return issues


def _inside_run_block(content: str, position: int) -> bool:
    """Walk back to the nearest `run:` or `uses:` key to decide the expression's context."""
    prefix = content[:position]
    last_run = prefix.rfind("run:")
    last_uses = prefix.rfind("uses:")
    last_with = prefix.rfind("with:")
    return last_run > max(last_uses, last_with)


EVALUATORS: list[Evaluator] = [CiSupplyChain()]
