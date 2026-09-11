"""Release hygiene: does the artifact agree with itself about what version it is?"""

from __future__ import annotations

import json
import re

from howlproof.model import Adversary, Confidence, Reproduction, ReproductionStep, Severity
from howlproof.registry import Context, Evaluator, Outcome

PYPROJECT_VERSION = re.compile(r"^version\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)
DUNDER_VERSION = re.compile(r"^__version__\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)
CHANGELOG_HEADING = re.compile(r"^##\s+v?(\d+\.\d+\.\d+)\s*$", re.MULTILINE)


class ReleaseVersion(Evaluator):
    """Check that the artifact agrees with itself about which version it is."""

    id = "release.version"
    adversary = Adversary.OPERATOR

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists("pyproject.toml"):
            return True, ""
        return False, "the artifact has no pyproject.toml declaring a version"

    def evaluate(self, context: Context) -> Outcome:
        pyproject = context.target.read_text("pyproject.toml")
        declared = PYPROJECT_VERSION.search(pyproject)
        observed: dict[str, object] = {"pyproject": declared.group(1) if declared else None}

        packages = [
            name
            for name in context.target.iter_files("__init__.py")
            if name.startswith("src/") and name.count("/") == 2
        ]
        dunder: dict[str, str] = {}
        for name in packages:
            match = DUNDER_VERSION.search(context.target.read_text(name))
            if match:
                dunder[name] = match.group(1)
        observed["dunder"] = dunder

        changelog = ""
        for candidate in ("change_log.md", "CHANGELOG.md", "changelog.md"):
            if context.target.exists(candidate):
                changelog = context.target.read_text(candidate)
                observed["changelog_file"] = candidate
                break
        headings = CHANGELOG_HEADING.findall(changelog)
        observed["changelog_versions"] = headings[:10]

        problems: list[str] = []
        if declared is None:
            if "dynamic" not in pyproject:
                problems.append("pyproject.toml declares no version and no dynamic version")
        else:
            version = declared.group(1)
            for name, value in dunder.items():
                if value != version:
                    problems.append(f"{name} says {value} but pyproject.toml says {version}")
            if changelog and version not in headings:
                problems.append(f"the changelog has no heading for {version}")
            if not changelog:
                problems.append("the artifact ships no changelog")

        ref = context.save_evidence_json(self.id, "versions.json", observed)
        limitation = (
            "compares the version strings the artifact declares about itself; it does not check "
            "published releases, git tags or what a built wheel actually contains"
        )
        if problems:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(problems)} version inconsistencies",
                        limitation,
                        evidence_refs=[ref],
                        detail={"problems": problems},
                    )
                ],
                findings=[
                    self.finding(
                        title="The artifact disagrees with itself about its version",
                        category="other",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(problems),
                        evidence=json.dumps(observed, indent=2),
                        remediation="Bring the declared version, the package attribute and the "
                        "changelog into agreement, or derive one from the other.",
                        rule="release.version.inconsistent",
                        reproduction=Reproduction(
                            summary="Re-read the declared versions.",
                            steps=[
                                ReproductionStep(
                                    description="Read the version from pyproject.toml",
                                    kind="file_probe",
                                    payload={"path": "pyproject.toml", "pattern": r"^version\s*="},
                                    expect={"matches": True},
                                )
                            ],
                        ),
                    )
                ],
            )
        return Outcome(
            checks=[
                self.verified(
                    "the declared version, package attribute and changelog agree",
                    limitation,
                    evidence_refs=[ref],
                    detail=observed,
                )
            ]
        )


EVALUATORS: list[Evaluator] = [ReleaseVersion()]
