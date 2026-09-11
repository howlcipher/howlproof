"""Documented file contracts for the rest of the ecosystem.

These are files, not API calls. Each one is written in a schema a sibling already
reads, so integrating HowlProof requires no change to a sibling component, which
matters because HowlPlane's control-plane architecture is deliberately frozen.

Where a mapping loses information it says so in the output rather than pretending
the vocabularies line up.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import yaml

from howlproof.evidence import AUTHORITY
from howlproof.model import (
    REVIEW_FINDING_SEVERITY,
    REVIEW_FINDING_STATUS,
    FindingState,
    Severity,
)

REVIEW_FINDING_SCHEMA = "ai.review_finding/v1"
EVIDENCE_ENTRY_SCHEMA = "ai.evidence_entry/v1"
VERIFICATION_PLAN_SCHEMA = "ai.verification_plan/v1"

#: HowlProof check status to the verification plan's closed status enum. Lossy on purpose:
#: the plan vocabulary has no word for "the tool was not installed", so the distinction is
#: preserved in the step name and note instead of being silently dropped.
STEP_STATUS = {
    "VERIFIED": "verified",
    "FAILED": "failed",
    "SKIPPED": "skipped",
    "UNAVAILABLE": "skipped",
    "NOT_APPLICABLE": "skipped",
    "ERROR": "skipped",
}

STEP_CATEGORY = {
    "python.tests": "unit_test",
    "python.types": "lint",
    "python.lint": "lint",
    "python.build": "build",
    "go.test": "unit_test",
    "go.vet": "lint",
    "go.fmt": "lint",
    "secrets.scan": "security_check",
    "ci.supplychain": "security_check",
    "sast.bandit": "security_check",
    "deps.audit": "security_check",
    "markup.escaping": "security_check",
    "http.authz": "security_check",
    "web.dom_injection": "security_check",
    "http.abuse": "integration_test",
    "api.idempotency": "integration_test",
    "service.restart": "integration_test",
    "reliability.partial_request": "integration_test",
    "reliability.corrupt_store": "integration_test",
    "release.version": "repository_hygiene",
    "docs.claims": "repository_hygiene",
    "web.links": "repository_hygiene",
    "web.metadata": "repository_hygiene",
    "web.responsive": "integration_test",
    "cli.contract": "integration_test",
    "cli.destructive": "policy_check",
    "ai.promptinjection": "security_check",
    "ai.schema": "integration_test",
    "integrity.target_unchanged": "policy_check",
}

TARGETS = ("plane", "board", "relay", "changeops")


def render(result: dict[str, Any], target: str) -> tuple[str, str]:
    """Return (suggested filename, content) for one sibling contract."""
    if target == "plane":
        return "howlproof-findings.yaml", _plane_findings(result)
    if target == "board":
        return "howlproof-evidence.jsonl", _evidence_entries(result)
    if target == "relay":
        return "howlproof-handoff.md", _relay_markdown(result)
    if target == "changeops":
        return "howlproof-changeops.md", _changeops_note(result)
    raise KeyError(f"unknown handoff target: {target}; expected one of {', '.join(TARGETS)}")


def verification_plan(result: dict[str, Any]) -> dict[str, Any]:
    """An ai.verification_plan/v1 document describing what actually ran.

    The schema is closed and its step shape is fixed, so nothing is invented here.
    Where a HowlProof concept has no field of its own, it goes into one the schema
    already defines rather than into a new key the consumer would reject.
    """
    required_checks = _required_checks(result)
    steps = []
    for index, check in enumerate(result["checks"], start=1):
        status = STEP_STATUS.get(check["status"], "skipped")
        note = check["reason"] or check["summary"]
        if check["status"] in {"UNAVAILABLE", "NOT_APPLICABLE", "ERROR"}:
            # This vocabulary has no word for "the tool was not installed". The
            # distinction is preserved in a field the schema does define.
            note = f"[howlproof status {check['status']}] {note}"
        steps.append(
            {
                "step_id": f"hp-{index:03d}",
                "name": check["check_id"],
                "command": check["checker"],
                "category": STEP_CATEGORY.get(
                    check["check_id"],
                    STEP_CATEGORY.get(check["check_id"].split(".")[0], "custom"),
                ),
                "status": status,
                "stderr": note,
                "duration_seconds": round(check.get("duration_ms", 0) / 1000, 3),
                "required": check["check_id"] in required_checks,
            }
        )
    statuses = {step["status"] for step in steps}
    if not steps:
        overall = "unverified"
    elif "failed" in statuses:
        overall = "failed"
    elif statuses == {"verified"}:
        overall = "passed"
    else:
        overall = "partial"
    return {
        "schema": VERIFICATION_PLAN_SCHEMA,
        "task_id": result["run_id"],
        "overall_status": overall,
        "steps": steps,
    }


def _required_checks(result: dict[str, Any]) -> set[str]:
    """Checks a non-optional acceptance criterion depends on."""
    required: set[str] = set()
    for criterion in result.get("criteria", []):
        if criterion.get("requirement") != "checks_pass" or criterion.get("optional"):
            continue
        evidence = criterion.get("evidence") or {}
        required.update(evidence.get("verified") or [])
        required.update(evidence.get("failed") or [])
        required.update(evidence.get("inconclusive") or {})
        required.update(evidence.get("not_applicable") or [])
        required.update(evidence.get("missing") or [])
    return required


def _plane_findings(result: dict[str, Any]) -> str:
    findings = []
    for finding in result["findings"]:
        state = FindingState(finding["state"])
        record = {
            "schema": REVIEW_FINDING_SCHEMA,
            "id": finding["id"],
            "reviewer_role": f"howlproof-{finding['adversary'].lower()}",
            "title": finding["title"],
            "severity": REVIEW_FINDING_SEVERITY[Severity(finding["severity"])],
            "category": finding["category"],
            "description": finding["summary"],
            "status": REVIEW_FINDING_STATUS[state],
            "component": result["artifact"],
            "location": finding["location"] or "",
            "evidence": finding["evidence"][:2000],
            "suggested_fix": finding["recommended_remediation"],
            "redundancy_status": "independent",
        }
        if finding.get("resolution_reason"):
            record["resolution_reason"] = finding["resolution_reason"]
        findings.append(record)
    document = {
        "produced_by": f"howlproof {result['version']}",
        "run_id": result["run_id"],
        "artifact": result["artifact"],
        "commit": result["target"].get("commit", ""),
        "howlproof_verdict": result["verdict"],
        "note": (
            "Advisory findings for `python -m src.control_plane reconcile --findings-file`. "
            "HowlProof does not remediate what it reports; routing the repair is HowlPlane's "
            "decision. Dismissing a blocker or high finding requires a resolution_reason."
        ),
        "findings": findings,
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def _evidence_entries(result: dict[str, Any]) -> str:
    """ai.evidence_entry/v1 lines.

    That schema is closed, so HowlProof's own vocabulary travels inside the object
    fields it already provides rather than as new keys. An entry carrying an unknown
    field is rejected by its reader, which would make the integration a claim rather
    than a contract.
    """
    blocking = [f for f in result["findings"] if f.get("blocking")]
    timestamp = result["completed_at"]
    entries = [
        {
            "schema": EVIDENCE_ENTRY_SCHEMA,
            "entry_id": f"ev-{result['run_id'].split('-')[-1]}",
            "task_id": result["run_id"],
            "agent_id": "howlproof",
            "action": "verification_executed",
            "timestamp": timestamp,
            "result": (
                "failed"
                if result["verdict"] == "REJECT"
                else "passed"
                if result["verdict"] == "PROVEN"
                else "partial"
            ),
            "defect_type": "verification_caught_defect" if blocking else None,
            "risk_level": "HIGH" if blocking else "LOW",
            "repository": result["artifact"],
            "artifact": result.get("path", ""),
            "control_plane_caught_defect": bool(blocking),
            # This schema types findings_summary as integers and verification_summary
            # as strings. Structured detail goes in metadata, which is open.
            "verification_summary": {
                "verdict": result["verdict"],
                "deciding_rule": result["deciding_rule"],
                "criteria": (
                    f"{result['counts']['criteria_satisfied']}/"
                    f"{result['counts']['criteria_total']} satisfied"
                ),
                "checks": (
                    f"{result['counts']['verified']} verified, "
                    f"{result['counts']['failed']} failed, "
                    f"{result['counts']['skipped']} skipped, "
                    f"{result['counts']['unavailable']} unavailable, "
                    f"{result['counts']['not_applicable']} not applicable, "
                    f"{result['counts']['errored']} errored"
                ),
                "validation_modes": "; ".join(
                    f"{mode}: {len(names)}" for mode, names in result["validation_modes"].items()
                ),
                "limitations": " | ".join(result["limitations"]) or "none recorded",
            },
            "findings_summary": {
                "total": len(result["findings"]),
                "blocking": len(blocking),
                **{
                    f"severity_{key.lower()}": value
                    for key, value in result["counts"]["by_severity"].items()
                },
                **{
                    f"adversary_{key.lower()}": value
                    for key, value in result["counts"]["by_adversary"].items()
                },
            },
            "metadata": {
                "commit": result["target"].get("commit", ""),
                "run_id": result["run_id"],
                "howlproof_version": result["version"],
                "authority": AUTHORITY,
                "counts": result["counts"],
                "validation_modes": result["validation_modes"],
                "limitations": result["limitations"],
            },
        }
    ]
    for finding in result["findings"]:
        entries.append(
            {
                "schema": EVIDENCE_ENTRY_SCHEMA,
                "entry_id": f"ev-{finding['id'].lower().replace('-', '')}",
                "task_id": result["run_id"],
                "agent_id": "howlproof",
                "action": "review_submitted",
                "timestamp": timestamp,
                "result": "failed" if finding.get("blocking") else "partial",
                "defect_type": "review_caught_defect",
                "risk_level": finding["severity"],
                "repository": result["artifact"],
                "artifact": finding["location"] or result.get("path", ""),
                "findings_summary": {"total": 1, "blocking": int(bool(finding.get("blocking")))},
                "metadata": {
                    "run_id": result["run_id"],
                    "finding_id": finding["id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "state": finding["state"],
                    "adversary": finding["adversary"],
                    "blocking": bool(finding.get("blocking")),
                    "fingerprint": finding["fingerprint"],
                    "authority": AUTHORITY,
                },
            }
        )
    return "".join(json.dumps(entry) + "\n" for entry in entries)


def _relay_markdown(result: dict[str, Any]) -> str:
    blocking = [f for f in result["findings"] if f.get("blocking")]
    unresolved = result["unresolved_risks"]
    lines = [
        f"# HowlProof evaluation of {result['artifact']}",
        "",
        "## Objective",
        "",
        (
            f"Independently challenge {result['artifact']} and produce evidence for or against "
            "trusting it."
        ),
        "",
        "## Current State",
        "",
        (
            f"Verdict {result['verdict']} at run {result['run_id']} "
            f"({result['completed_at']}). "
            f"{result['counts']['criteria_satisfied']} of {result['counts']['criteria_total']} "
            "acceptance criteria satisfied."
        ),
        "",
        "## Known Failures",
        "",
    ]
    lines += [f"- {f['id']} ({f['severity']}): {f['title']}" for f in result["findings"]] or [
        "- None recorded by the checks that ran."
    ]
    lines += ["", "## Blockers", ""]
    lines += [f"- {f['id']}: {f['summary']}" for f in blocking] or ["- No blocking findings."]
    lines += ["", "## Next Recommended Action", ""]
    if blocking:
        lines.append(
            "- Route remediation of the blocking findings to the artifact's builder, then run "
            "`howlproof verify-fix` for each one. HowlProof does not repair what it judges."
        )
    else:
        lines.append(
            "- No remediation is required by this evaluation. Re-evaluate on the next change."
        )
    lines += [
        "",
        "## Commands to Resume Work",
        "",
        "```bash",
        f"howlproof inspect {result.get('path', '<bundle>')}",
        f"howlproof explain {result.get('path', '<bundle>')}",
        "```",
        "",
    ]
    if unresolved:
        lines += ["## Known Limitations", ""]
        lines += [f"- {risk}" for risk in unresolved]
        lines.append("")
    lines += [
        "## Context the Next Agent Must Not Lose",
        "",
        "- HowlProof evidence is advisory. It grants no authority to promote, merge or deploy.",
        (
            "- A finding is only VERIFIED_FIXED after HowlProof re-ran the evaluator against a "
            "changed artifact. A statement that something was fixed is not evidence."
        ),
        "",
    ]
    return "\n".join(lines)


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] or ["- None recorded."]


def _changeops_note(result: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# HowlProof advisory for {result['artifact']}",
            "",
            f"Run: {result['run_id']}",
            f"Commit: {result['target'].get('commit', 'unknown')}",
            f"Verdict: {result['verdict']}",
            "",
            "## There is no HowlChangeOps ingest path for this document",
            "",
            "As of this release HowlChangeOps gathers its own evidence and projects only its",
            "`test` and `build` check results into its policy. It exposes no parameter through",
            "which an external verdict can reach a gate, so this file is written for a human",
            "reader and for the record, not for machine consumption.",
            "",
            "The supported way to make a HowlProof verdict affect promotion is to raise it in",
            "HowlPlane, which already owns the boundary that gates package publishing. Use the",
            "`plane` handoff for that.",
            "",
            "## What this evaluation established",
            "",
            (
                f"- Acceptance criteria satisfied: {result['counts']['criteria_satisfied']} of "
                f"{result['counts']['criteria_total']}"
            ),
            f"- Blocking findings: {len([f for f in result['findings'] if f.get('blocking')])}",
            (
                f"- Checks verified: {result['counts']['verified']}, failed: "
                f"{result['counts']['failed']}, unavailable: {result['counts']['unavailable']}, "
                f"skipped: {result['counts']['skipped']}"
            ),
            "",
            "## Limitations recorded by this run",
            "",
            *(_bullets(result["limitations"])),
            "",
            f"Generated {datetime.now(UTC).isoformat()} by howlproof {result['version']}.",
            "",
        ]
    )
