"""Evaluation orchestration.

Prepare a read-only view of the artifact, probe what tooling actually exists, run
the selected adversaries, prove the artifact was not modified, then derive a
verdict from the evidence rather than from the exit status of any one command.
"""

from __future__ import annotations

import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from howlproof import __version__
from howlproof.config import ProofConfig
from howlproof.evidence import AUTHORITY, HANDOFF_SCHEMA, RESULT_SCHEMA, Bundle, environment_probe
from howlproof.ledger import Ledger
from howlproof.model import (
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    FindingState,
    Mode,
    ModelError,
    Severity,
    Verdict,
)
from howlproof.registry import Context, Evaluator, Registry, select
from howlproof.report import render_report
from howlproof.service import ServiceRunner
from howlproof.target import Target, TargetError, TargetMutatedError
from howlproof.verdict import VerdictResult, derive


class EvaluationError(RuntimeError):
    """The evaluation could not be set up. This is distinct from a failing artifact."""


def evaluate(
    target_root: Path,
    config: ProofConfig,
    registry: Registry,
    evidence_root: Path,
    allow_network: bool = False,
    allow_evidence_in_target: bool = False,
    config_source: str = "",
) -> dict[str, Any]:
    """Run one evaluation and return the sealed bundle's result document."""
    started = time.monotonic()
    bundle = Bundle.create(evidence_root, target_root, allow_evidence_in_target)
    evaluators = select(registry, config.profiles, config.adversaries)
    if not evaluators:
        raise EvaluationError(
            "the selected profiles and adversaries resolve to no evaluators; "
            "an evaluation that runs nothing cannot support a verdict"
        )

    # Probe the tooling the evaluators need and every tool an acceptance criterion
    # names, so a `tool_required` criterion fails on real absence rather than on the
    # fact that nothing happened to ask.
    probes = registry.tools(e.id for e in evaluators)
    known = registry.known_probes()
    for criterion in config.acceptance:
        for tool in getattr(criterion, "tools", []):
            probes.setdefault(tool, known.get(tool, [tool, "--version"]))
    environment = environment_probe(probes)
    bundle.write_json("environment.json", environment)
    bundle.write_json("config.json", {"source": config_source, **config.model_dump(mode="json")})

    checks: list[CheckResult] = []
    findings: list[Finding] = []
    integrity_violation = ""

    with tempfile.TemporaryDirectory(prefix="howlproof-") as scratch:
        workspace = Path(scratch) / "workspace"
        try:
            target = Target.prepare(target_root, workspace, config.include_ignored)
        except TargetError as error:
            raise EvaluationError(str(error)) from error

        context = Context(
            target=target,
            config=config,
            bundle=bundle,
            environment=environment,
            allow_network=allow_network,
        )

        with ServiceRunner(context) as service:
            context.service_base_url = service.base_url
            context.service_running = service.running
            # Evaluators that stop and start the artifact need the handle, and must run
            # last in a profile so they cannot disturb the checks that came before.
            context.service_runner = service
            if service.note:
                context.notes.append(service.note)
            for evaluator in evaluators:
                checks_before = len(checks)
                context.service_running = service.running
                _run_one(evaluator, context, checks, findings)
                if len(checks) == checks_before:
                    checks.append(evaluator.errored("the evaluator returned no result at all"))

        try:
            target.verify_unchanged()
        except TargetMutatedError as mutated:
            integrity_violation = str(mutated)
            changed = target.changed_paths()
            checks.append(_integrity_check(changed))
            findings.append(_integrity_finding(changed, str(mutated)))

        target_document = target.describe()

    ledger = Ledger.open(evidence_root)
    previously_fixed = ledger.fixed_fingerprints(config.artifact)
    for finding in findings:
        ledger.assign(
            config.artifact,
            finding,
            bundle.run_id,
            target_document.get("commit", ""),
            target_document.get("tree_digest_before", ""),
        )
        if finding.fingerprint in previously_fixed and finding.state is not FindingState.REGRESSED:
            finding.state = FindingState.REGRESSED
    ledger.save()

    evidence_names = {ref for check in checks for ref in check.evidence_refs} | {
        ref.removeprefix("evidence/") for check in checks for ref in check.evidence_refs
    }

    outcome = derive(
        config=config,
        checks=checks,
        findings=findings,
        environment=environment,
        evidence_names=evidence_names,
        integrity_violation=integrity_violation,
    )

    for finding in findings:
        bundle.write_json(f"findings/{finding.id}.json", finding.to_dict())
        if finding.reproduction is not None:
            bundle.write_json(
                f"reproductions/{finding.id}/steps.json", finding.reproduction.to_dict()
            )

    bundle.write_json("target.json", target_document)
    bundle.write_jsonl("checks.jsonl", [check.to_dict() for check in checks])

    result = _result_document(
        bundle.run_id, config, target_document, outcome, checks, findings, context.notes, started
    )
    bundle.write_json("result.json", result)
    bundle.write_text("result.md", render_report(result))
    bundle.write_json("handoff.json", _handoff(result))
    manifest = bundle.seal(
        {
            "artifact": config.artifact,
            "profiles": config.profiles,
            "started_at": result["started_at"],
            "completed_at": result["completed_at"],
            "verdict": outcome.verdict.value,
            "evaluators": [e.checker for e in evaluators],
        }
    )
    result["manifest"] = manifest
    result["path"] = str(bundle.path)
    return result


def _run_one(
    evaluator: Evaluator, context: Context, checks: list[CheckResult], findings: list[Finding]
) -> None:
    """One evaluator's fault must never become the artifact's fault, or a silent pass."""
    try:
        applicable, reason = evaluator.applicable(context)
        if not applicable:
            checks.append(evaluator.not_applicable(reason or "no such surface was declared"))
            return
        outcome = evaluator.evaluate(context)
    except ModelError as invalid:
        checks.append(evaluator.errored(f"evaluator produced an invalid result: {invalid}"))
        return
    except Exception as error:  # noqa: BLE001 - an evaluator fault is evidence about the evaluator
        checks.append(evaluator.errored(f"{type(error).__name__}: {error}"))
        return
    checks.extend(outcome.checks)
    findings.extend(outcome.findings)


def _integrity_check(changed: list[str]) -> CheckResult:
    return CheckResult(
        check_id="integrity.target_unchanged",
        checker="target_unchanged/v1",
        adversary=Adversary.INTEGRITY,
        status=CheckStatus.FAILED,
        summary="the artifact under evaluation changed while it was being evaluated",
        limitation="this check proves mutation occurred, not which component caused it",
        detail={"changed_paths": changed},
    )


def _integrity_finding(changed: list[str], message: str) -> Finding:
    return Finding(
        check_id="integrity.target_unchanged",
        adversary=Adversary.INTEGRITY,
        category="correctness",
        title="Artifact mutated during its own evaluation",
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        summary=message,
        evidence="changed paths: " + ", ".join(changed) if changed else message,
        recommended_remediation=(
            "Identify the evaluator or process writing to the target and confine it to the "
            "workspace copy. HowlProof must not modify the artifact it judges."
        ),
        rule="integrity.target_unchanged",
        detail={"changed_paths": changed},
    )


def _result_document(
    run_id: str,
    config: ProofConfig,
    target_document: dict[str, Any],
    outcome: VerdictResult,
    checks: list[CheckResult],
    findings: list[Finding],
    notes: list[str],
    started: float,
) -> dict[str, Any]:
    completed = datetime.now(UTC)
    return {
        "schema": RESULT_SCHEMA,
        "run_id": run_id,
        "authority": AUTHORITY,
        "version": __version__,
        "artifact": config.artifact,
        "profiles": config.profiles,
        "adversaries": [a.value for a in config.adversaries],
        "target": target_document,
        "started_at": datetime.fromtimestamp(
            completed.timestamp() - (time.monotonic() - started), UTC
        ).isoformat(),
        "completed_at": completed.isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "verdict": outcome.verdict.value,
        "verdict_definition": _definition(outcome.verdict),
        "deciding_rule": outcome.rule,
        "rationale": outcome.rationale,
        "criteria": [criterion.to_dict() for criterion in outcome.criteria],
        "counts": outcome.counts,
        "checks": [check.to_dict() for check in checks],
        "findings": [finding.to_dict() for finding in findings],
        "unresolved_risks": outcome.unresolved_risks,
        "limitations": outcome.limitations,
        "notes": notes,
        "validation_modes": _validation_modes(checks),
    }


def _validation_modes(checks: list[CheckResult]) -> dict[str, list[str]]:
    """Keep REAL, SIMULATED, SKIPPED and UNAVAILABLE separable in the final record."""
    modes: dict[str, list[str]] = {
        "REAL": [],
        "SIMULATED": [],
        "SKIPPED": [],
        "UNAVAILABLE": [],
        "NOT_APPLICABLE": [],
        "ERROR": [],
    }
    for check in checks:
        if check.status is CheckStatus.SKIPPED:
            modes["SKIPPED"].append(check.check_id)
        elif check.status is CheckStatus.UNAVAILABLE:
            modes["UNAVAILABLE"].append(check.check_id)
        elif check.status is CheckStatus.NOT_APPLICABLE:
            modes["NOT_APPLICABLE"].append(check.check_id)
        elif check.status is CheckStatus.ERROR:
            modes["ERROR"].append(check.check_id)
        elif check.mode is Mode.SIMULATED:
            modes["SIMULATED"].append(check.check_id)
        else:
            modes["REAL"].append(check.check_id)
    return modes


def _definition(verdict: Verdict) -> str:
    from howlproof.model import VERDICT_DEFINITIONS

    return VERDICT_DEFINITIONS[verdict]


def _handoff(result: dict[str, Any]) -> dict[str, Any]:
    """The advisory record siblings consume. HowlProof judges; it never promotes."""
    blocking = [f for f in result["findings"] if f.get("blocking")]
    return {
        "schema": HANDOFF_SCHEMA,
        "authority": AUTHORITY,
        "run_id": result["run_id"],
        "artifact": result["artifact"],
        "commit": result["target"].get("commit", ""),
        "branch": result["target"].get("branch", ""),
        "tree_digest": result["target"].get("tree_digest_before", ""),
        "verdict": result["verdict"],
        "deciding_rule": result["deciding_rule"],
        "criteria_satisfied": result["counts"]["criteria_satisfied"],
        "criteria_total": result["counts"]["criteria_total"],
        "blocking_finding_ids": [f["id"] for f in blocking],
        "finding_ids": [f["id"] for f in result["findings"]],
        "unresolved_risks": result["unresolved_risks"],
        "limitations": result["limitations"],
        "validation_modes": result["validation_modes"],
        "note": (
            "Advisory only. HowlProof does not promote, merge, deploy or approve. "
            "Promotion decisions belong to HowlPlane and HowlChangeOps."
        ),
    }
