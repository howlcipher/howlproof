"""Deterministic verdict derivation.

The rules are ordered and the first match wins. Every step that fired is recorded,
so `howlproof explain` can show the reasoning rather than assert the conclusion.
The bias is deliberate: when the evaluation could not establish something, the
answer is INSUFFICIENT_EVIDENCE, not a pass.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from howlproof.config import (
    ChecksPass,
    CoverageFloor,
    Criterion,
    MaxFindings,
    NoRegressions,
    ProofConfig,
    RequiredEvidence,
    ToolRequired,
)
from howlproof.model import (
    DISMISSED_STATES,
    INCONCLUSIVE_STATUSES,
    SEVERITY_RANK,
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    FindingState,
    Severity,
    Verdict,
)

SATISFIED = "SATISFIED"
VIOLATED = "VIOLATED"
UNEVALUABLE = "UNEVALUABLE"


@dataclass
class CriterionResult:
    id: str
    requirement: str
    outcome: str
    detail: str
    optional: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)  # arbitrary JSON detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "requirement": self.requirement,
            "outcome": self.outcome,
            "detail": self.detail,
            "optional": self.optional,
            "evidence": self.evidence,
        }


@dataclass
class VerdictResult:
    verdict: Verdict
    rule: str
    rationale: list[str]
    criteria: list[CriterionResult]
    unresolved_risks: list[str]
    limitations: list[str]
    counts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "deciding_rule": self.rule,
            "rationale": self.rationale,
            "criteria": [c.to_dict() for c in self.criteria],
            "unresolved_risks": self.unresolved_risks,
            "limitations": self.limitations,
            "counts": self.counts,
        }


def _check_index(checks: Sequence[CheckResult]) -> dict[str, CheckResult]:
    return {check.check_id: check for check in checks}


def _at_or_above(finding: Finding, severity: Severity) -> bool:
    return SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[severity]


def evaluate_criterion(
    criterion: Criterion,
    checks: Sequence[CheckResult],
    findings: Sequence[Finding],
    environment: dict[str, Any],
    evidence_names: set[str],
) -> CriterionResult:
    index = _check_index(checks)
    optional = criterion.optional

    if isinstance(criterion, ChecksPass):
        missing = [name for name in criterion.checks if name not in index]
        if missing:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                f"no result was produced for {', '.join(sorted(missing))}",
                optional,
                {"missing": sorted(missing)},
            )
        failed = [n for n in criterion.checks if index[n].status is CheckStatus.FAILED]
        inconclusive = {
            n: index[n].status.value
            for n in criterion.checks
            if index[n].status in INCONCLUSIVE_STATUSES
        }
        not_applicable = [
            n for n in criterion.checks if index[n].status is CheckStatus.NOT_APPLICABLE
        ]
        if failed:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                VIOLATED,
                f"{', '.join(sorted(failed))} failed",
                optional,
                {"failed": sorted(failed)},
            )
        if inconclusive:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                "required checks did not produce a result: "
                + ", ".join(f"{n} is {s}" for n, s in sorted(inconclusive.items())),
                optional,
                {"inconclusive": inconclusive},
            )
        if not_applicable:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                "the criterion requires checks that do not apply to this artifact: "
                + ", ".join(sorted(not_applicable)),
                optional,
                {"not_applicable": sorted(not_applicable)},
            )
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            SATISFIED,
            f"{len(criterion.checks)} required checks verified",
            optional,
            {"verified": sorted(criterion.checks)},
        )

    if isinstance(criterion, MaxFindings):
        matched = [
            f
            for f in findings
            if _at_or_above(f, criterion.min_severity)
            and f.state not in DISMISSED_STATES
            and (criterion.adversary is None or f.adversary is criterion.adversary)
        ]
        scope = criterion.adversary.value.lower() if criterion.adversary else "any"
        detail = (
            f"{len(matched)} {scope} findings at or above {criterion.min_severity.value}, "
            f"limit {criterion.limit}"
        )
        outcome = VIOLATED if len(matched) > criterion.limit else SATISFIED
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            outcome,
            detail,
            optional,
            {"finding_ids": [f.id for f in matched]},
        )

    if isinstance(criterion, ToolRequired):
        tools = environment.get("tools", {})
        absent = {
            name: tools.get(name, {}).get("reason", "not probed")
            for name in criterion.tools
            if not tools.get(name, {}).get("available")
        }
        if absent:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                VIOLATED,
                "required tooling is unavailable, so the artifact was not fully evaluated: "
                + ", ".join(f"{n} ({r})" for n, r in sorted(absent.items())),
                optional,
                {"absent": absent},
            )
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            SATISFIED,
            f"{len(criterion.tools)} required tools present",
            optional,
            {"tools": criterion.tools},
        )

    if isinstance(criterion, NoRegressions):
        regressed = [f.id for f in findings if f.state is FindingState.REGRESSED]
        if regressed:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                VIOLATED,
                f"previously fixed findings returned: {', '.join(regressed)}",
                optional,
                {"regressed": regressed},
            )
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            SATISFIED,
            "no previously fixed finding reappeared",
            optional,
        )

    if isinstance(criterion, RequiredEvidence):
        missing_evidence = [name for name in criterion.artifacts if name not in evidence_names]
        if missing_evidence:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                f"required evidence was not produced: {', '.join(sorted(missing_evidence))}",
                optional,
                {"absent": sorted(missing_evidence)},
            )
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            SATISFIED,
            f"{len(criterion.artifacts)} evidence artifacts present",
            optional,
        )

    if isinstance(criterion, CoverageFloor):
        applicable = [c for c in checks if c.status is not CheckStatus.NOT_APPLICABLE]
        conclusive = [c for c in applicable if c.conclusive]
        fraction = len(conclusive) / len(applicable) if applicable else 0.0
        detail = (
            f"{len(conclusive)} of {len(applicable)} applicable checks were conclusive "
            f"({fraction:.2f}), floor {criterion.min_conclusive_fraction:.2f}"
        )
        if not applicable:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                "no applicable checks ran, so coverage cannot be measured",
                optional,
            )
        if fraction < criterion.min_conclusive_fraction:
            return CriterionResult(
                criterion.id,
                criterion.requirement,
                UNEVALUABLE,
                detail,
                optional,
                {"fraction": round(fraction, 4)},
            )
        return CriterionResult(
            criterion.id,
            criterion.requirement,
            SATISFIED,
            detail,
            optional,
            {"fraction": round(fraction, 4)},
        )

    raise TypeError(f"unhandled criterion type: {type(criterion).__name__}")


def derive(
    config: ProofConfig,
    checks: Sequence[CheckResult],
    findings: Sequence[Finding],
    environment: dict[str, Any],
    evidence_names: set[str] | None = None,
    integrity_violation: str = "",
    today: date | None = None,
) -> VerdictResult:
    """Apply the ordered rules. The first one that fires decides the verdict."""
    today = today or datetime.now(UTC).date()
    evidence_names = evidence_names or set()
    criteria = [
        evaluate_criterion(c, checks, findings, environment, evidence_names)
        for c in config.acceptance
    ]

    inconclusive = [c for c in checks if c.status in INCONCLUSIVE_STATUSES]
    not_applicable = [c for c in checks if c.status is CheckStatus.NOT_APPLICABLE]
    blocking = [
        f
        for f in findings
        if _at_or_above(f, config.blocking_severity)
        and f.confidence is Confidence.CONFIRMED
        and f.state not in DISMISSED_STATES
    ]
    unproven_severe = [
        f
        for f in findings
        if _at_or_above(f, config.blocking_severity)
        and f.confidence is not Confidence.CONFIRMED
        and f.state not in DISMISSED_STATES
    ]
    human_requested = [c for c in checks if c.detail.get("requires_human")]
    active_exclusions = config.active_exclusions(today)
    expired_exclusions = config.expired_exclusions(today)
    # INFORMATIONAL findings are raised to be read, not to be fixed. Counting them as
    # unresolved would make CONDITIONALLY_PROVEN permanent for any artifact that documents
    # anything, which would drain the verdict of meaning.
    unresolved = [
        f
        for f in findings
        if f.state not in DISMISSED_STATES
        and not _is_closed(f)
        and f.severity is not Severity.INFORMATIONAL
    ]

    counts = {
        "checks": len(checks),
        "verified": sum(1 for c in checks if c.status is CheckStatus.VERIFIED),
        "failed": sum(1 for c in checks if c.status is CheckStatus.FAILED),
        "skipped": sum(1 for c in checks if c.status is CheckStatus.SKIPPED),
        "unavailable": sum(1 for c in checks if c.status is CheckStatus.UNAVAILABLE),
        "not_applicable": len(not_applicable),
        "errored": sum(1 for c in checks if c.status is CheckStatus.ERROR),
        "simulated": sum(1 for c in checks if c.mode.value == "SIMULATED"),
        "findings": len(findings),
        "blocking_findings": len(blocking),
        "criteria_satisfied": sum(1 for c in criteria if c.outcome == SATISFIED),
        "criteria_total": len(criteria),
        "by_severity": {
            severity.value: sum(1 for f in findings if f.severity is severity)
            for severity in Severity
        },
        "by_adversary": {
            adversary.value: sum(1 for f in findings if f.adversary is adversary)
            for adversary in Adversary
        },
    }

    limitations = [
        f"{c.check_id} was {c.status.value}: {c.reason}" for c in inconclusive + not_applicable
    ]
    limitations += [
        f"{c.check_id} observed a simulation, not the real dependency"
        for c in checks
        if c.mode.value == "SIMULATED"
    ]
    limitations += [f"excluded {e.check}: {e.reason}" for e in active_exclusions]
    unresolved_risks = [f"{f.id or f.title} ({f.severity.value}): {f.summary}" for f in unresolved]

    def decide(verdict: Verdict, rule: str, rationale: list[str]) -> VerdictResult:
        return VerdictResult(
            verdict, rule, rationale, criteria, unresolved_risks, limitations, counts
        )

    if integrity_violation:
        return decide(
            Verdict.INSUFFICIENT_EVIDENCE,
            "integrity",
            [
                "The artifact changed during evaluation.",
                integrity_violation,
                "Evidence gathered while the subject was mutating cannot support a verdict.",
            ],
        )

    if not checks:
        return decide(
            Verdict.INSUFFICIENT_EVIDENCE,
            "no_checks",
            ["No check produced a result, so nothing about this artifact was established."],
        )

    if not config.acceptance:
        return decide(
            Verdict.INSUFFICIENT_EVIDENCE,
            "no_acceptance_criteria",
            [
                "The artifact defines no acceptance criteria.",
                "Running checks without criteria shows activity, not conformance.",
            ],
        )

    unevaluable = [c for c in criteria if c.outcome == UNEVALUABLE and not c.optional]
    violated = [c for c in criteria if c.outcome == VIOLATED and not c.optional]
    # An optional criterion cannot reject or block, but its shortfall is still something
    # the contract asked about and the evaluation did not establish.
    optional_shortfalls = [
        c for c in criteria if c.optional and c.outcome in {UNEVALUABLE, VIOLATED}
    ]
    limitations.extend(
        f"optional criterion {c.id} was {c.outcome.lower()}: {c.detail}"
        for c in optional_shortfalls
    )

    if violated or blocking:
        rationale = [f"{c.id} violated: {c.detail}" for c in violated]
        rationale += [
            f"{f.id} ({f.severity.value}, reproduction confirmed): {f.title}" for f in blocking
        ]
        return decide(Verdict.REJECT, "blocking_evidence", rationale)

    if unevaluable:
        return decide(
            Verdict.INSUFFICIENT_EVIDENCE,
            "unevaluable_criteria",
            [f"{c.id} could not be evaluated: {c.detail}" for c in unevaluable],
        )

    if unproven_severe or human_requested or expired_exclusions:
        rationale = [
            f"{f.id} ({f.severity.value}) is severe but its reproduction was not confirmed: "
            f"{f.title}"
            for f in unproven_severe
        ]
        rationale += [
            f"{c.check_id} requested human judgment: {c.summary}" for c in human_requested
        ]
        rationale += [f"exclusion for {e.check} expired on {e.expires}" for e in expired_exclusions]
        return decide(Verdict.REQUIRES_HUMAN, "human_judgment_required", rationale)

    if active_exclusions or inconclusive or unresolved or not_applicable or optional_shortfalls:
        rationale = [f"active exclusion: {e.check} ({e.reason})" for e in active_exclusions]
        rationale += [
            f"optional criterion {c.id} was {c.outcome.lower()}: {c.detail}"
            for c in optional_shortfalls
        ]
        rationale += [f"{c.check_id} was {c.status.value}: {c.reason}" for c in inconclusive]
        rationale += [f"{c.check_id} did not apply: {c.reason}" for c in not_applicable]
        rationale += [
            f"unresolved {f.severity.value} finding {f.id}: {f.title}" for f in unresolved
        ]
        return decide(Verdict.CONDITIONALLY_PROVEN, "conditional", rationale)

    return decide(
        Verdict.PROVEN,
        "all_criteria_satisfied",
        [
            f"{len(criteria)} acceptance criteria satisfied",
            f"{counts['verified']} checks verified with no unresolved findings",
        ],
    )


def _is_closed(finding: Finding) -> bool:
    return finding.state in {FindingState.VERIFIED_FIXED, FindingState.NOT_REPRODUCED}
