"""Verdicts, findings and checks. A passing verdict must mean more than exit zero."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """What HowlProof is willing to assert about an artifact."""

    PROVEN = "PROVEN"
    CONDITIONALLY_PROVEN = "CONDITIONALLY_PROVEN"
    REQUIRES_HUMAN = "REQUIRES_HUMAN"
    REJECT = "REJECT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


#: Process exit codes. Distinct per verdict so CI can branch without parsing output.
EXIT_CODES: dict[Verdict, int] = {
    Verdict.PROVEN: 0,
    Verdict.CONDITIONALLY_PROVEN: 10,
    Verdict.REQUIRES_HUMAN: 20,
    Verdict.REJECT: 30,
    Verdict.INSUFFICIENT_EVIDENCE: 40,
}

EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_INTEGRITY = 4

#: Best to worst. `--fail-under` accepts everything at or better than its argument.
VERDICT_RANK: dict[Verdict, int] = {
    Verdict.PROVEN: 0,
    Verdict.CONDITIONALLY_PROVEN: 1,
    Verdict.REQUIRES_HUMAN: 2,
    Verdict.INSUFFICIENT_EVIDENCE: 3,
    Verdict.REJECT: 4,
}

VERDICT_DEFINITIONS: dict[Verdict, str] = {
    Verdict.PROVEN: (
        "The artifact satisfied every defined acceptance criterion, the configured adversarial "
        "evaluation produced no unresolved finding above the permitted threshold, and enough "
        "checks actually executed to justify the conclusion."
    ),
    Verdict.CONDITIONALLY_PROVEN: (
        "The artifact passed subject to documented assumptions, exclusions, environment "
        "limitations or unresolved non-blocking findings, each named in the result."
    ),
    Verdict.REQUIRES_HUMAN: (
        "The available evidence cannot safely support an autonomous decision; a human judgment "
        "is materially required before the artifact advances."
    ),
    Verdict.REJECT: (
        "Evidence demonstrates that the artifact violates acceptance criteria, security or "
        "reliability requirements, policy, or another blocking condition."
    ),
    Verdict.INSUFFICIENT_EVIDENCE: (
        "The artifact may or may not be acceptable. The evaluation that ran was inadequate to "
        "make a defensible determination, so no determination is claimed."
    ),
}


class CheckStatus(str, Enum):
    """The outcome of one check. Absence of a result is never success."""

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


#: Statuses that carry no evidence either way, so a criterion resting on one is unevaluable.
INCONCLUSIVE_STATUSES = frozenset({CheckStatus.SKIPPED, CheckStatus.UNAVAILABLE, CheckStatus.ERROR})
#: Statuses that must explain themselves. A silent skip is indistinguishable from a lie.
REASON_REQUIRED_STATUSES = frozenset(
    {CheckStatus.SKIPPED, CheckStatus.UNAVAILABLE, CheckStatus.NOT_APPLICABLE, CheckStatus.ERROR}
)


class Severity(str, Enum):
    """The ecosystem's ai.review_finding/v1 vocabulary, reused rather than reinvented."""

    BLOCKER = "BLOCKER"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.BLOCKER: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class Confidence(str, Enum):
    """CONFIRMED is reserved for findings whose reproduction was actually re-executed."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Adversary(str, Enum):
    FUNCTIONAL = "FUNCTIONAL"
    SECURITY = "SECURITY"
    RELIABILITY = "RELIABILITY"
    AI = "AI"
    OPERATOR = "OPERATOR"
    INTEGRITY = "INTEGRITY"


#: Short codes used in finding identifiers, for example HP-SEC-0041.
ADVERSARY_CODE: dict[Adversary, str] = {
    Adversary.FUNCTIONAL: "FUNC",
    Adversary.SECURITY: "SEC",
    Adversary.RELIABILITY: "REL",
    Adversary.AI: "AI",
    Adversary.OPERATOR: "OPS",
    Adversary.INTEGRITY: "INT",
}


class FindingState(str, Enum):
    """Lifecycle. Only a re-execution can move a finding to VERIFIED_FIXED."""

    FOUND = "FOUND"
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    REMEDIATION_REQUESTED = "REMEDIATION_REQUESTED"
    RETESTED = "RETESTED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    REGRESSED = "REGRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    WONT_FIX = "WONT_FIX"


#: States that record a human decision to live with a finding rather than repair it.
DISMISSED_STATES = frozenset({FindingState.ACCEPTED_RISK, FindingState.WONT_FIX})


class Mode(str, Enum):
    """Whether a check observed the real system or a controlled substitute."""

    REAL = "REAL"
    SIMULATED = "SIMULATED"


#: ai.review_finding/v1 categories.
CATEGORIES = frozenset(
    {"correctness", "regression", "security", "test_gap", "architecture", "simplicity", "other"}
)


class ModelError(ValueError):
    """Raised when a result would misrepresent what the evaluation actually established."""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalise(value: str) -> str:
    """Collapse run-specific noise so a fingerprint survives paths, times and line shifts."""
    text = re.sub(r"\b[0-9a-f]{7,64}\b", "<hex>", value.strip())
    text = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*", "<timestamp>", text)
    # nosec B108 - a pattern that normalises scratch paths out of a fingerprint,
    # not a filesystem location this process ever writes to.
    text = re.sub(r"/tmp/[^\s:]+", "<tmp>", text)  # nosec B108
    text = re.sub(r"\b\d+\b", "<n>", text)
    return re.sub(r"\s+", " ", text).lower()


@dataclass
class CheckResult:
    """One executed (or deliberately not executed) check."""

    check_id: str
    checker: str
    adversary: Adversary
    status: CheckStatus
    summary: str
    limitation: str
    reason: str = ""
    mode: Mode = Mode.REAL
    duration_ms: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status in REASON_REQUIRED_STATUSES and not self.reason.strip():
            raise ModelError(f"{self.check_id}: {self.status.value} requires an explicit reason")
        if not self.limitation.strip():
            raise ModelError(f"{self.check_id}: every check must state what it does not establish")

    @property
    def conclusive(self) -> bool:
        return self.status not in INCONCLUSIVE_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return _enum_safe(asdict(self))


@dataclass
class ReproductionStep:
    """One re-executable step. `expect` describes the defective behaviour, not the fix."""

    description: str
    kind: str
    payload: dict[str, Any]
    expect: dict[str, Any]

    def __post_init__(self) -> None:
        if self.kind not in {"command", "http_request", "file_probe", "reevaluate"}:
            raise ModelError(f"unsupported reproduction step kind: {self.kind}")

    def to_dict(self) -> dict[str, Any]:
        return _enum_safe(asdict(self))


@dataclass
class Reproduction:
    """A recorded way to observe the defect again."""

    summary: str
    steps: list[ReproductionStep]
    requires_service: bool = False
    notes: str = ""

    @classmethod
    def by_reevaluation(cls, evaluator_id: str, observation: str) -> Reproduction:
        """For a defect only the evaluator itself can observe, such as a rendered page.

        `howlproof reproduce` cannot replay this, and says so rather than guessing.
        `howlproof verify-fix` re-runs the evaluator, which is the real re-verification
        path for findings of this kind.
        """
        return cls(
            summary=f"Re-run {evaluator_id} against the artifact.",
            steps=[
                ReproductionStep(
                    description=observation,
                    kind="reevaluate",
                    payload={"evaluator": evaluator_id},
                    expect={"finding_present": True},
                )
            ],
            notes=(
                "This observation is made by the evaluator, not by a replayable command. "
                "Use `howlproof verify-fix` to re-verify it."
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "requires_service": self.requires_service,
            "notes": self.notes,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class Finding:
    """Something HowlProof is prepared to argue against the artifact."""

    check_id: str
    adversary: Adversary
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: str
    recommended_remediation: str
    location: str | None = None
    rule: str = ""
    state: FindingState = FindingState.FOUND
    reproduction: Reproduction | None = None
    resolution_reason: str | None = None
    id: str = ""
    #: Overrides the default fingerprint inputs. An aggregate finding, one that
    #: summarises a set rather than naming a single defect, must not change identity
    #: every time the size of that set changes.
    fingerprint_basis: list[str] | None = None
    fingerprint: str = ""
    first_seen_run: str = ""
    first_seen_commit: str = ""
    last_seen_run: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ModelError(f"unknown finding category: {self.category}")
        if not self.evidence.strip():
            raise ModelError(f"{self.title}: a finding without evidence is an opinion")
        if self.confidence is Confidence.CONFIRMED and self.reproduction is None:
            raise ModelError(f"{self.title}: CONFIRMED requires a recorded reproduction")
        dismissed_without_reason = (
            self.state in DISMISSED_STATES
            and self.severity in (Severity.BLOCKER, Severity.HIGH)
            and not (self.resolution_reason or "").strip()
        )
        if dismissed_without_reason:
            raise ModelError(
                f"{self.title}: dismissing a {self.severity.value} finding requires a reason"
            )
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Stable identity across runs, commits, line shifts and temporary paths.

        The default inputs include the summary, because two defects of the same rule
        in the same file are different findings and only the summary separates them.
        An aggregate finding sets `fingerprint_basis` instead, since its summary
        restates a changing set and would otherwise mint a new identity each run.
        """
        parts = self.fingerprint_basis or [
            self.check_id,
            self.rule or self.title,
            self.location or "",
            self.summary,
        ]
        return digest("|".join(_normalise(part) for part in parts))

    @property
    def blocking(self) -> bool:
        """A finding blocks only when it is both severe and actually reproduced."""
        return (
            self.severity in (Severity.BLOCKER, Severity.HIGH)
            and self.confidence is Confidence.CONFIRMED
            and self.state not in DISMISSED_STATES
        )

    def to_dict(self) -> dict[str, Any]:
        data = _enum_safe(asdict(self))
        data["reproduction"] = self.reproduction.to_dict() if self.reproduction else None
        data["blocking"] = self.blocking
        return data


def _enum_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _enum_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_enum_safe(v) for v in value]
    return value


#: HowlProof severity to the ecosystem's ai.review_finding/v1 lowercase vocabulary.
REVIEW_FINDING_SEVERITY: dict[Severity, str] = {
    Severity.BLOCKER: "blocker",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFORMATIONAL: "informational",
}

#: HowlProof lifecycle state to ai.review_finding/v1 status.
REVIEW_FINDING_STATUS: dict[FindingState, str] = {
    FindingState.FOUND: "open",
    FindingState.REPRODUCED: "confirmed",
    FindingState.NOT_REPRODUCED: "likely",
    FindingState.REMEDIATION_REQUESTED: "confirmed",
    FindingState.RETESTED: "confirmed",
    FindingState.VERIFIED_FIXED: "confirmed",
    FindingState.REGRESSED: "confirmed",
    FindingState.ACCEPTED_RISK: "out_of_scope",
    FindingState.WONT_FIX: "out_of_scope",
}
