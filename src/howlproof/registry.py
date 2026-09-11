"""Evaluator contract, execution context and registry.

An evaluator is one adversary's attempt on one surface. It must be able to say
"I could not run" as clearly as it says "this failed", which is why every result
helper here forces a reason and a limitation.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import yaml

from howlproof.config import ProofConfig
from howlproof.evidence import Bundle
from howlproof.model import (
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    Mode,
    Reproduction,
    Severity,
)
from howlproof.target import Target

PROFILE_DIR = Path(__file__).parent / "profiles"


@dataclass
class Context:
    """Everything an evaluator is allowed to see, and nothing that lets it repair."""

    target: Target
    config: ProofConfig
    bundle: Bundle
    environment: dict[str, Any] = field(default_factory=dict)
    allow_network: bool = False
    service_base_url: str = ""
    service_running: bool = False
    notes: list[str] = field(default_factory=list)
    #: Set by the engine for evaluators that must stop and start the artifact. Typed as
    #: Any to keep the service module free to import this one.
    service_runner: Any = None
    #: Cached interpreter provisioned for a Python artifact, shared across evaluators.
    python_env: Any = None

    def tool_available(self, name: str) -> bool:
        return bool(self.environment.get("tools", {}).get(name, {}).get("available"))

    def tool_reason(self, name: str) -> str:
        return self.environment.get("tools", {}).get(name, {}).get("reason", "not probed")

    def save_evidence(self, check_id: str, name: str, content: str) -> str:
        ref = self.bundle.evidence_ref(check_id, name)
        self.bundle.write_text(ref, content)
        return ref

    def save_evidence_json(self, check_id: str, name: str, value: Any) -> str:
        ref = self.bundle.evidence_ref(check_id, name)
        self.bundle.write_json(ref, value)
        return ref

    def save_evidence_bytes(self, check_id: str, name: str, content: bytes) -> str:
        ref = self.bundle.evidence_ref(check_id, name)
        self.bundle.write_bytes(ref, content)
        return ref


@dataclass
class Outcome:
    checks: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def extend(self, other: Outcome) -> None:
        self.checks.extend(other.checks)
        self.findings.extend(other.findings)


class Evaluator(ABC):
    """One named, versioned adversarial probe."""

    id: str = ""
    version: str = "1"
    adversary: Adversary = Adversary.FUNCTIONAL
    #: Tool name to probe argv, recorded in environment.json before anything runs.
    tools: ClassVar[dict[str, list[str]]] = {}

    @property
    def checker(self) -> str:
        return f"{self.id}/v{self.version}"

    def applicable(self, context: Context) -> tuple[bool, str]:
        """Return False with a reason when the artifact has no such surface."""
        return True, ""

    @abstractmethod
    def evaluate(self, context: Context) -> Outcome:
        """Attack the surface and report what was actually established."""

    # -- result helpers ---------------------------------------------------

    def verified(
        self,
        summary: str,
        limitation: str,
        *,
        suffix: str = "",
        evidence_refs: Iterable[str] = (),
        detail: dict[str, Any] | None = None,
        duration_ms: int = 0,
        mode: Mode = Mode.REAL,
    ) -> CheckResult:
        return self._result(
            CheckStatus.VERIFIED,
            summary,
            limitation,
            suffix,
            "",
            evidence_refs,
            detail,
            duration_ms,
            mode,
        )

    def failed(
        self,
        summary: str,
        limitation: str,
        *,
        suffix: str = "",
        evidence_refs: Iterable[str] = (),
        detail: dict[str, Any] | None = None,
        duration_ms: int = 0,
        mode: Mode = Mode.REAL,
    ) -> CheckResult:
        return self._result(
            CheckStatus.FAILED,
            summary,
            limitation,
            suffix,
            "",
            evidence_refs,
            detail,
            duration_ms,
            mode,
        )

    def unavailable(self, reason: str, *, suffix: str = "") -> CheckResult:
        return self._result(
            CheckStatus.UNAVAILABLE,
            "the check could not run",
            "nothing about this surface was established",
            suffix,
            reason,
            (),
            None,
            0,
            Mode.REAL,
        )

    def not_applicable(self, reason: str, *, suffix: str = "") -> CheckResult:
        return self._result(
            CheckStatus.NOT_APPLICABLE,
            "the artifact has no such surface",
            "absence of a surface is not evidence about other surfaces",
            suffix,
            reason,
            (),
            None,
            0,
            Mode.REAL,
        )

    def skipped(self, reason: str, *, suffix: str = "") -> CheckResult:
        return self._result(
            CheckStatus.SKIPPED,
            "the check was deliberately not run",
            "nothing about this surface was established",
            suffix,
            reason,
            (),
            None,
            0,
            Mode.REAL,
        )

    def errored(self, reason: str, *, suffix: str = "") -> CheckResult:
        return self._result(
            CheckStatus.ERROR,
            "the check raised before reaching a conclusion",
            "an evaluator fault is not evidence for or against the artifact",
            suffix,
            reason,
            (),
            None,
            0,
            Mode.REAL,
        )

    def _result(
        self,
        status: CheckStatus,
        summary: str,
        limitation: str,
        suffix: str,
        reason: str,
        evidence_refs: Iterable[str],
        detail: dict[str, Any] | None,
        duration_ms: int,
        mode: Mode,
    ) -> CheckResult:
        return CheckResult(
            check_id=f"{self.id}.{suffix}" if suffix else self.id,
            checker=self.checker,
            adversary=self.adversary,
            status=status,
            summary=summary,
            limitation=limitation,
            reason=reason,
            mode=mode,
            duration_ms=duration_ms,
            evidence_refs=list(evidence_refs),
            detail=detail or {},
        )

    def finding(
        self,
        *,
        title: str,
        category: str,
        severity: Severity,
        confidence: Confidence,
        summary: str,
        evidence: str,
        remediation: str,
        location: str | None = None,
        rule: str = "",
        reproduction: Reproduction | None = None,
        suffix: str = "",
        detail: dict[str, Any] | None = None,
        aggregate: bool = False,
    ) -> Finding:
        """Raise a finding.

        Set `aggregate` when the finding summarises a set of observations rather than
        naming one defect. Its identity then comes from the rule alone, so the count
        changing does not mint a new finding every run.
        """
        return Finding(
            check_id=f"{self.id}.{suffix}" if suffix else self.id,
            adversary=self.adversary,
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            recommended_remediation=remediation,
            location=location,
            rule=rule or self.id,
            reproduction=reproduction,
            detail=detail or {},
            fingerprint_basis=[self.id, rule or self.id] if aggregate else None,
        )


class Registry:
    """Named evaluators plus the profiles that select them."""

    def __init__(self) -> None:
        self._evaluators: dict[str, Evaluator] = {}

    def register(self, evaluator: Evaluator) -> None:
        if not evaluator.id:
            raise ValueError("an evaluator needs an id")
        if evaluator.id in self._evaluators:
            raise ValueError(f"duplicate evaluator id: {evaluator.id}")
        self._evaluators[evaluator.id] = evaluator

    def get(self, name: str) -> Evaluator:
        try:
            return self._evaluators[name]
        except KeyError as missing:
            raise KeyError(f"unknown evaluator: {name}") from missing

    def names(self) -> list[str]:
        return sorted(self._evaluators)

    def all(self) -> list[Evaluator]:
        return [self._evaluators[name] for name in self.names()]

    def tools(self, names: Iterable[str]) -> dict[str, list[str]]:
        probes: dict[str, list[str]] = {}
        for name in names:
            probes.update(self._evaluators[name].tools)
        return probes

    def known_probes(self) -> dict[str, list[str]]:
        """Every probe any evaluator declares.

        A `tool_required` criterion can name a tool no selected evaluator uses. Probing
        it with a guessed `--version` produces a false absence: `go --version` exits 2.
        """
        probes: dict[str, list[str]] = {}
        for evaluator in self._evaluators.values():
            probes.update(evaluator.tools)
        return probes


def load_profiles() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(PROFILE_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict) or "evaluators" not in data:
            raise ValueError(f"malformed profile: {path.name}")
        profiles[path.stem] = data
    return profiles


def select(
    registry: Registry, profiles: list[str], adversaries: list[Adversary]
) -> list[Evaluator]:
    """Resolve profile names to a deduplicated, adversary-filtered evaluator list."""
    available = load_profiles()
    known_evaluators = set(registry.names())
    unknown = [name for name in profiles if name not in available and name not in known_evaluators]
    if unknown:
        raise KeyError(
            f"unknown profile(s): {', '.join(unknown)}. Profiles: {', '.join(sorted(available))}."
        )
    chosen: list[str] = []
    for name in profiles:
        # A single evaluator id is accepted where a profile is expected, so one check can
        # be re-run in isolation without inventing a profile for it.
        members = available[name]["evaluators"] if name in available else [name]
        for evaluator_id in members:
            if evaluator_id not in chosen:
                chosen.append(evaluator_id)
    wanted = set(adversaries)
    return [registry.get(name) for name in chosen if registry.get(name).adversary in wanted]


def timed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
