"""The verdict table. A pass must mean more than an exit code, and doubt must survive."""

from datetime import date

import pytest

from howlproof.config import ProofConfig
from howlproof.model import (
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    FindingState,
    Mode,
    Reproduction,
    ReproductionStep,
    Severity,
    Verdict,
)
from howlproof.verdict import SATISFIED, UNEVALUABLE, VIOLATED, derive, evaluate_criterion

AVAILABLE = {
    "tools": {
        "python3": {"available": True},
        "go": {"available": False, "reason": "go is not on PATH"},
    }
}


def contract(**updates):
    data = {
        "schema_version": 1,
        "artifact": "fixture",
        "acceptance": [{"id": "AC-01", "requirement": "checks_pass", "checks": ["python.tests"]}],
    }
    data.update(updates)
    return ProofConfig.model_validate(data)


def check(status=CheckStatus.VERIFIED, check_id="python.tests", reason="", **updates):
    data = {
        "check_id": check_id,
        "checker": f"{check_id}/v1",
        "adversary": Adversary.FUNCTIONAL,
        "status": status,
        "summary": "summary",
        "limitation": "this check establishes only what it ran",
        "reason": reason
        or (
            "not run in this environment"
            if status.value in {"SKIPPED", "UNAVAILABLE", "NOT_APPLICABLE", "ERROR"}
            else ""
        ),
    }
    data.update(updates)
    return CheckResult(**data)


def reproduction():
    return Reproduction(
        summary="observe it again",
        steps=[
            ReproductionStep(
                description="probe",
                kind="file_probe",
                payload={"path": "a", "pattern": "b"},
                expect={"matches": True},
            )
        ],
    )


def finding(severity=Severity.HIGH, confidence=Confidence.CONFIRMED, **updates):
    data = {
        "check_id": "secrets.scan",
        "adversary": Adversary.SECURITY,
        "category": "security",
        "title": "A defect",
        "severity": severity,
        "confidence": confidence,
        "summary": "summary",
        "evidence": "evidence",
        "recommended_remediation": "fix it elsewhere",
        "reproduction": reproduction() if confidence is Confidence.CONFIRMED else None,
        "id": "HP-SEC-0001",
    }
    data.update(updates)
    return Finding(**data)


# -- the ordered rules ------------------------------------------------------


def test_an_artifact_mutated_during_evaluation_yields_insufficient_evidence():
    outcome = derive(contract(), [check()], [], AVAILABLE, integrity_violation="it changed")
    assert outcome.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert outcome.rule == "integrity"


def test_running_no_checks_cannot_produce_a_pass():
    assert derive(contract(), [], [], AVAILABLE).verdict is Verdict.INSUFFICIENT_EVIDENCE


def test_an_artifact_with_no_acceptance_criteria_cannot_be_proven():
    outcome = derive(contract(acceptance=[]), [check()], [], AVAILABLE)
    assert outcome.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert outcome.rule == "no_acceptance_criteria"


def test_all_criteria_satisfied_and_nothing_unresolved_is_proven():
    outcome = derive(contract(), [check()], [], AVAILABLE)
    assert outcome.verdict is Verdict.PROVEN


def test_a_failed_required_check_is_a_rejection():
    outcome = derive(contract(), [check(status=CheckStatus.FAILED)], [], AVAILABLE)
    assert outcome.verdict is Verdict.REJECT


def test_a_reproduced_severe_finding_is_a_rejection():
    outcome = derive(contract(), [check()], [finding()], AVAILABLE)
    assert outcome.verdict is Verdict.REJECT
    assert "reproduction confirmed" in " ".join(outcome.rationale)


def test_a_severe_finding_that_was_not_reproduced_requires_a_human():
    outcome = derive(contract(), [check()], [finding(confidence=Confidence.HIGH)], AVAILABLE)
    assert outcome.verdict is Verdict.REQUIRES_HUMAN


def test_an_expired_exclusion_requires_a_human():
    outcome = derive(
        contract(
            exclusions=[
                {
                    "check": "deps.audit",
                    "reason": "no network in this environment",
                    "expires": date(2020, 1, 1),
                }
            ]
        ),
        [check()],
        [],
        AVAILABLE,
    )
    assert outcome.verdict is Verdict.REQUIRES_HUMAN


def test_a_check_requesting_human_judgment_is_honoured():
    outcome = derive(contract(), [check(detail={"requires_human": True})], [], AVAILABLE)
    assert outcome.verdict is Verdict.REQUIRES_HUMAN


@pytest.mark.parametrize(
    "status",
    [CheckStatus.SKIPPED, CheckStatus.UNAVAILABLE, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE],
)
def test_a_required_check_that_did_not_run_is_never_a_pass(status):
    outcome = derive(contract(), [check(status=status)], [], AVAILABLE)
    assert outcome.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert outcome.rule == "unevaluable_criteria"


def test_an_unavailable_check_no_criterion_needs_only_weakens_the_verdict():
    outcome = derive(
        contract(),
        [check(), check(check_id="deps.audit", status=CheckStatus.UNAVAILABLE)],
        [],
        AVAILABLE,
    )
    assert outcome.verdict is Verdict.CONDITIONALLY_PROVEN
    assert any("deps.audit" in item for item in outcome.limitations)


def test_an_active_exclusion_prevents_proven():
    outcome = derive(
        contract(exclusions=[{"check": "deps.audit", "reason": "no network in this environment"}]),
        [check()],
        [],
        AVAILABLE,
    )
    assert outcome.verdict is Verdict.CONDITIONALLY_PROVEN


def test_a_simulated_check_is_reported_as_a_limitation():
    outcome = derive(contract(), [check(mode=Mode.SIMULATED)], [], AVAILABLE)
    assert any("simulation" in item for item in outcome.limitations)


def test_informational_findings_do_not_prevent_proven():
    informational = finding(
        severity=Severity.INFORMATIONAL, confidence=Confidence.CONFIRMED, category="other"
    )
    assert derive(contract(), [check()], [informational], AVAILABLE).verdict is Verdict.PROVEN


def test_a_dismissed_finding_needs_its_reason_to_stop_blocking():
    dismissed = finding(
        state=FindingState.ACCEPTED_RISK, resolution_reason="Accepted by the operator on record."
    )
    assert derive(contract(), [check()], [dismissed], AVAILABLE).verdict is Verdict.PROVEN


def test_a_regression_is_rejected_when_the_contract_forbids_one():
    outcome = derive(
        contract(
            acceptance=[
                {"id": "AC-01", "requirement": "checks_pass", "checks": ["python.tests"]},
                {"id": "AC-02", "requirement": "no_regressions"},
            ]
        ),
        [check()],
        [finding(state=FindingState.REGRESSED)],
        AVAILABLE,
    )
    assert outcome.verdict is Verdict.REJECT


# -- individual criteria ----------------------------------------------------


def test_a_required_tool_that_is_absent_is_a_violation_not_a_skip():
    result = evaluate_criterion(
        contract(
            acceptance=[{"id": "AC", "requirement": "tool_required", "tools": ["go"]}]
        ).acceptance[0],
        [check()],
        [],
        AVAILABLE,
        set(),
    )
    assert result.outcome == VIOLATED
    assert "go is not on PATH" in result.detail


def test_coverage_below_the_floor_is_unevaluable():
    criterion = contract(
        acceptance=[{"id": "AC", "requirement": "coverage_floor", "min_conclusive_fraction": 0.9}]
    ).acceptance[0]
    checks = [check(), check(check_id="a", status=CheckStatus.UNAVAILABLE)]
    assert evaluate_criterion(criterion, checks, [], AVAILABLE, set()).outcome == UNEVALUABLE


def test_coverage_ignores_checks_that_do_not_apply():
    criterion = contract(
        acceptance=[{"id": "AC", "requirement": "coverage_floor", "min_conclusive_fraction": 1.0}]
    ).acceptance[0]
    checks = [check(), check(check_id="a", status=CheckStatus.NOT_APPLICABLE)]
    assert evaluate_criterion(criterion, checks, [], AVAILABLE, set()).outcome == SATISFIED


def test_missing_required_evidence_is_unevaluable_rather_than_a_pass():
    criterion = contract(
        acceptance=[
            {"id": "AC", "requirement": "required_evidence", "artifacts": ["web.responsive/375"]}
        ]
    ).acceptance[0]
    assert evaluate_criterion(criterion, [check()], [], AVAILABLE, set()).outcome == UNEVALUABLE
    present = evaluate_criterion(criterion, [check()], [], AVAILABLE, {"web.responsive/375"})
    assert present.outcome == SATISFIED


def test_findings_can_be_capped_per_adversary():
    criterion = contract(
        acceptance=[
            {
                "id": "AC",
                "requirement": "max_findings",
                "adversary": "SECURITY",
                "min_severity": "HIGH",
                "limit": 0,
            }
        ]
    ).acceptance[0]
    operator_finding = finding(
        adversary=Adversary.OPERATOR, category="other", check_id="web.links", id="HP-OPS-0001"
    )
    assert evaluate_criterion(
        criterion, [check()], [operator_finding], AVAILABLE, set()
    ).outcome == (SATISFIED)
    assert (
        evaluate_criterion(criterion, [check()], [finding()], AVAILABLE, set()).outcome == VIOLATED
    )


def test_an_optional_criterion_does_not_decide_the_verdict():
    outcome = derive(
        contract(
            acceptance=[
                {"id": "AC-01", "requirement": "checks_pass", "checks": ["python.tests"]},
                {
                    "id": "AC-02",
                    "requirement": "checks_pass",
                    "checks": ["absent"],
                    "optional": True,
                },
            ]
        ),
        [check()],
        [],
        AVAILABLE,
    )
    assert outcome.verdict is Verdict.CONDITIONALLY_PROVEN
