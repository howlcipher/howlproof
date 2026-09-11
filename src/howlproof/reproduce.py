"""Replaying a recorded reproduction, and independently re-verifying a claimed fix.

Two separate mechanisms, deliberately.

`replay` re-executes the steps stored with a finding. It answers "is the defect still
observable the way it was observed before?"

`verify_fix` re-runs the evaluator that produced the finding against a changed artifact.
It answers "is the defect gone?" and it refuses to answer at all when the artifact has
not changed, because an unchanged artifact cannot have been fixed. Nothing here accepts
an assertion that a defect was repaired: only a re-execution moves a finding forward.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from howlproof.config import ProofConfig
from howlproof.evidence import Bundle
from howlproof.model import FindingState
from howlproof.registry import Context, Registry
from howlproof.service import ServiceRunner, request
from howlproof.target import Target

SUPPORTED_KINDS = frozenset({"file_probe", "command", "http_request"})

CONFIRMED = "CONFIRMED"
NOT_REPRODUCED = "NOT_REPRODUCED"
NOT_SUPPORTED = "NOT_SUPPORTED"


@dataclass
class StepOutcome:
    description: str
    kind: str
    matched: bool | None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "kind": self.kind,
            "matched": self.matched,
            "detail": self.detail,
        }


@dataclass
class ReplayResult:
    outcome: str
    reason: str
    steps: list[StepOutcome]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "steps": [step.to_dict() for step in self.steps],
        }


def replay(finding: dict[str, Any], target_root: Path, config: ProofConfig) -> ReplayResult:
    """Re-execute a stored reproduction against the artifact as it is now."""
    reproduction = finding.get("reproduction")
    if not reproduction:
        return ReplayResult(
            NOT_SUPPORTED,
            "this finding carries no recorded reproduction; re-verify it with verify-fix",
            [],
        )
    steps = reproduction.get("steps") or []
    unsupported = sorted({s["kind"] for s in steps if s["kind"] not in SUPPORTED_KINDS})
    if unsupported:
        return ReplayResult(
            NOT_SUPPORTED,
            f"the reproduction uses step kinds replay cannot execute ({', '.join(unsupported)}); "
            "re-verify it with verify-fix, which re-runs the evaluator itself",
            [],
        )

    outcomes: list[StepOutcome] = []
    with tempfile.TemporaryDirectory(prefix="howlproof-replay-") as scratch:
        target = Target.prepare(target_root, Path(scratch) / "workspace", config.include_ignored)
        needs_service = bool(reproduction.get("requires_service"))
        # Replay writes no bundle; the discard target satisfies the evaluator contract.
        bundle = cast(Bundle, _NoBundle())
        context = Context(target=target, config=config, bundle=bundle)
        if needs_service:
            with ServiceRunner(context) as service:
                if not service.running:
                    return ReplayResult(
                        NOT_SUPPORTED,
                        "the reproduction needs the artifact's service and it did not start: "
                        + (service.note or "no reason recorded"),
                        [],
                    )
                base_url = service.base_url
                for step in steps:
                    outcomes.append(_run_step(step, target, base_url))
        else:
            for step in steps:
                outcomes.append(_run_step(step, target, ""))

    asserted = [step for step in outcomes if step.matched is not None]
    if not asserted:
        return ReplayResult(
            NOT_SUPPORTED,
            "the reproduction records only setup steps and asserts nothing",
            outcomes,
        )
    if all(step.matched for step in asserted):
        return ReplayResult(
            CONFIRMED,
            f"all {len(asserted)} asserted steps still observe the defect",
            outcomes,
        )
    return ReplayResult(
        NOT_REPRODUCED,
        "at least one asserted step no longer observes the defect; this is not by itself proof "
        "of a fix, because the reproduction may have become inapplicable",
        outcomes,
    )


def _run_step(step: dict[str, Any], target: Target, base_url: str) -> StepOutcome:
    kind = step["kind"]
    payload = step.get("payload") or {}
    expect = step.get("expect") or {}
    description = step.get("description", kind)

    if kind == "file_probe":
        return _file_probe(description, payload, expect, target)
    if kind == "command":
        argv = payload.get("argv")
        if not argv:
            return StepOutcome(description, kind, None, {"note": "no argv recorded"})
        result = target.run(list(argv), timeout=300)
        detail = result.to_dict()
        if not expect:
            return StepOutcome(description, kind, None, detail)
        matched = True
        if "exit_code" in expect:
            matched = matched and result.exit_code == expect["exit_code"]
        if "stdout_contains" in expect:
            matched = matched and expect["stdout_contains"] in (result.stdout + result.stderr)
        if "stdout_not_contains" in expect:
            matched = matched and expect["stdout_not_contains"] not in (
                result.stdout + result.stderr
            )
        return StepOutcome(description, kind, matched, detail)
    if kind == "http_request":
        if not base_url:
            return StepOutcome(
                description, kind, None, {"note": "no service was running for this step"}
            )
        response = request(
            base_url,
            str(payload.get("method", "POST")),
            str(payload.get("path", "/")),
            body=payload.get("body"),
            raw_body=(payload["raw_body"].encode() if "raw_body" in payload else None),
        )
        detail = response.to_dict()
        if not expect:
            return StepOutcome(description, kind, None, detail)
        matched = True
        if "status" in expect:
            matched = matched and response.status == expect["status"]
        if "status_not" in expect:
            matched = matched and response.status != expect["status_not"]
        if "status_gte" in expect:
            matched = matched and response.status >= expect["status_gte"]
        if "body_contains" in expect:
            matched = matched and expect["body_contains"] in response.body
        return StepOutcome(description, kind, matched, detail)
    return StepOutcome(description, kind, None, {"note": "unsupported step kind"})


def _file_probe(
    description: str, payload: dict[str, Any], expect: dict[str, Any], target: Target
) -> StepOutcome:
    path = str(payload.get("path", ""))
    if "compare_with" in payload:
        other = str(payload["compare_with"])
        if not (target.exists(path) and target.exists(other)):
            return StepOutcome(
                description,
                "file_probe",
                expect.get("identical") is False,
                {"note": "one of the compared files is absent"},
            )
        identical = target.read_bytes(path) == target.read_bytes(other)
        if "identical" in expect:
            return StepOutcome(
                description,
                "file_probe",
                identical == expect["identical"],
                {"identical": identical},
            )
        return StepOutcome(description, "file_probe", None, {"identical": identical})
    if not target.exists(path):
        matched = expect.get("matches") is False if "matches" in expect else None
        return StepOutcome(description, "file_probe", matched, {"note": f"{path} is absent"})
    content = target.read_text(path)
    pattern = str(payload.get("pattern", ""))
    if pattern:
        found = re.search(pattern, content) is not None
    elif "value" in payload:
        found = str(payload["value"]) in content
    else:
        return StepOutcome(description, "file_probe", None, {"note": "no pattern recorded"})
    if "matches" in expect:
        return StepOutcome(description, "file_probe", found == expect["matches"], {"found": found})
    return StepOutcome(description, "file_probe", None, {"found": found})


@dataclass
class FixResult:
    outcome: str
    reason: str
    still_present: bool
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "still_present": self.still_present,
            "detail": self.detail,
        }


class FixRefused(RuntimeError):
    """The claim of a fix cannot be tested, so no fix is recorded."""


def verify_fix(
    finding: dict[str, Any],
    recorded_tree_digest: str,
    target_root: Path,
    config: ProofConfig,
    registry: Registry,
    evidence_root: Path,
    allow_network: bool = False,
) -> FixResult:
    """Re-run the evaluator that raised the finding, against a genuinely changed artifact."""
    from howlproof.engine import evaluate  # imported here to avoid a module cycle

    with tempfile.TemporaryDirectory(prefix="howlproof-fixcheck-") as scratch:
        probe = Target.prepare(target_root, Path(scratch) / "probe", config.include_ignored)
        current = probe.digest_before
    if recorded_tree_digest and current == recorded_tree_digest:
        raise FixRefused(
            "the artifact is byte-for-byte identical to the state the finding was raised "
            f"against (tree digest {current[:16]}), so there is nothing to re-verify. "
            "A statement that a defect was fixed is not evidence that it was."
        )

    evaluator_id = str(finding.get("check_id", "")).split(".")[0:2]
    scoped = _scoped_config(config, finding)
    result = evaluate(
        target_root=target_root,
        config=scoped,
        registry=registry,
        evidence_root=evidence_root,
        allow_network=allow_network,
        config_source=f"verify-fix for {finding.get('id')}",
    )
    fingerprint = finding.get("fingerprint")
    still = [f for f in result["findings"] if f.get("fingerprint") == fingerprint]
    detail = {
        "run_id": result["run_id"],
        "path": result["path"],
        "previous_tree_digest": recorded_tree_digest,
        "current_tree_digest": current,
        "evaluator": ".".join(evaluator_id),
        "checks": [
            c["check_id"]
            for c in result["checks"]
            if c["check_id"].startswith(".".join(evaluator_id))
        ],
    }
    inconclusive = [
        c
        for c in result["checks"]
        if c["check_id"].startswith(".".join(evaluator_id))
        and c["status"] in {"UNAVAILABLE", "SKIPPED", "ERROR", "NOT_APPLICABLE"}
    ]
    if still:
        return FixResult(
            FindingState.RETESTED.value,
            "the finding is still present after the change; it is not fixed",
            True,
            detail,
        )
    if inconclusive:
        return FixResult(
            FindingState.RETESTED.value,
            "the evaluator that raised this finding could not run against the changed artifact ("
            + "; ".join(f"{c['check_id']} is {c['status']}: {c['reason']}" for c in inconclusive)
            + "), so its absence is not evidence of a fix",
            False,
            detail,
        )
    return FixResult(
        FindingState.VERIFIED_FIXED.value,
        "the evaluator ran against the changed artifact and no longer raises this finding",
        False,
        detail,
    )


def _scoped_config(config: ProofConfig, finding: dict[str, Any]) -> ProofConfig:
    """Re-run only the evaluator that raised the finding, with acceptance criteria removed."""
    data = config.model_dump()
    data["acceptance"] = []
    data["profiles"] = ["default"]
    data["adversaries"] = [finding.get("adversary", "FUNCTIONAL")]
    return ProofConfig.model_validate(data)


class _NoBundle:
    """Replay writes no evidence bundle; it reports its outcome to the caller instead."""

    def evidence_ref(self, check_id: str, name: str) -> str:
        return f"evidence/{check_id}/{name}"

    def write_text(self, *_: Any, **__: Any) -> None:
        return None

    def write_json(self, *_: Any, **__: Any) -> None:
        return None

    def write_bytes(self, *_: Any, **__: Any) -> None:
        return None
