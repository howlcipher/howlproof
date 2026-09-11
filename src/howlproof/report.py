"""Human-readable rendering of a result document.

The report is written so a reader can disagree with it: every verdict shows the
rule that produced it, every check shows what it did not establish, and REAL,
SIMULATED, SKIPPED and UNAVAILABLE validation are never blended together.
"""

from __future__ import annotations

from typing import Any

BAR = "-" * 68


def render_report(result: dict[str, Any]) -> str:
    counts = result["counts"]
    lines = [
        "# HowlProof result",
        "",
        "HowlProof judges. It does not repair the artifact it is judging.",
        "",
        f"Artifact: {result['artifact']}",
        f"Commit: {result['target'].get('commit') or 'not a git checkout'}",
        f"Branch: {result['target'].get('branch') or 'unknown'}"
        + (" (working tree dirty)" if result["target"].get("dirty") else ""),
        f"Run: {result['run_id']}",
        f"Profiles: {', '.join(result['profiles'])}",
        f"Completed: {result['completed_at']}",
        "",
        f"## Verdict: {result['verdict']}",
        "",
        result["verdict_definition"],
        "",
        f"Deciding rule: `{result['deciding_rule']}`",
        "",
    ]
    for reason in result["rationale"]:
        lines.append(f"- {reason}")
    lines += [
        "",
        "## Acceptance criteria",
        "",
        f"{counts['criteria_satisfied']} of {counts['criteria_total']} satisfied.",
        "",
        "| Criterion | Requirement | Outcome | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for criterion in result["criteria"]:
        optional = " (optional)" if criterion["optional"] else ""
        lines.append(
            f"| {criterion['id']}{optional} | {criterion['requirement']} | "
            f"{criterion['outcome']} | {_cell(criterion['detail'])} |"
        )

    lines += [
        "",
        "## Checks",
        "",
        (
            f"{counts['verified']} verified, {counts['failed']} failed, "
            f"{counts['skipped']} skipped, {counts['unavailable']} unavailable, "
            f"{counts['not_applicable']} not applicable, {counts['errored']} errored."
        ),
        "",
        "| Check | Checker | Status | Mode | Note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in result["checks"]:
        note = check["reason"] or check["summary"]
        lines.append(
            f"| {check['check_id']} | {check['checker']} | {check['status']} | "
            f"{check['mode']} | {_cell(note)} |"
        )

    lines += ["", "## Validation modes", ""]
    for mode, names in result["validation_modes"].items():
        lines.append(f"- **{mode}**: {', '.join(names) if names else 'none'}")

    lines += ["", "## Findings", ""]
    if not result["findings"]:
        lines.append("No findings were raised by the checks that ran.")
    for finding in result["findings"]:
        lines += [
            f"### {finding['id']} — {finding['title']}",
            "",
            f"- Adversary: {finding['adversary']}",
            f"- Category: {finding['category']}",
            f"- Severity: {finding['severity']}",
            f"- Confidence: {finding['confidence']}",
            f"- State: {finding['state']}",
            f"- Blocking: {'yes' if finding['blocking'] else 'no'}",
            f"- Location: {finding['location'] or 'not localised'}",
            "",
            finding["summary"],
            "",
            "Evidence:",
            "",
            "```",
            finding["evidence"][:4000],
            "```",
            "",
            (
                f"Recommended remediation (for the artifact's owner, not for HowlProof): "
                f"{finding['recommended_remediation']}"
            ),
            "",
        ]
        if finding.get("reproduction"):
            lines += [
                f"Reproduction: {finding['reproduction']['summary']}",
                "",
            ]
            for index, step in enumerate(finding["reproduction"]["steps"], start=1):
                lines.append(f"{index}. {step['description']}")
            lines.append("")

    lines += ["", "## Unresolved risks", ""]
    lines += [f"- {risk}" for risk in result["unresolved_risks"]] or ["None recorded."]
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in result["limitations"]] or [
        "No skipped, unavailable or simulated checks in this run."
    ]
    if result.get("notes"):
        lines += ["", "## Notes", ""]
        lines += [f"- {note}" for note in result["notes"]]
    lines += [
        "",
        BAR,
        "",
        (
            "This report is advisory evidence. HowlProof does not promote, merge, deploy or "
            "approve anything. Remediation belongs to the artifact's builder and promotion to "
            "HowlPlane and HowlChangeOps."
        ),
        "",
    ]
    return "\n".join(lines)


def render_terminal(result: dict[str, Any]) -> str:
    """A compact console summary."""
    counts = result["counts"]
    findings = result["findings"]
    blocking = [f for f in findings if f.get("blocking")]
    lines = [
        "HOWLPROOF RESULT",
        "",
        f"Artifact: {result['artifact']}",
        f"Commit:   {result['target'].get('commit') or '(not a git checkout)'}",
        f"Run:      {result['run_id']}",
        "",
        f"Verdict:  {result['verdict']}  [{result['deciding_rule']}]",
        "",
        (
            f"Acceptance criteria: {counts['criteria_satisfied']} / "
            f"{counts['criteria_total']} satisfied"
        ),
        (
            f"Checks: {counts['verified']} verified, {counts['failed']} failed, "
            f"{counts['skipped']} skipped, {counts['unavailable']} unavailable, "
            f"{counts['not_applicable']} n/a, {counts['errored']} errored"
        ),
        "",
    ]
    for adversary, total in result["counts"]["by_adversary"].items():
        if total:
            lines.append(f"  {adversary.lower():<12} {total} finding(s)")
    if blocking:
        lines += ["", "Blocking findings:"]
        for finding in blocking:
            lines.append(f"  {finding['id']}  {finding['severity']:<13} {finding['title']}")
    if result["rationale"]:
        lines += ["", "Why:"]
        lines += [f"  - {reason}" for reason in result["rationale"][:6]]
    lines += ["", f"Evidence: {result.get('path', '(unsealed)')}", ""]
    return "\n".join(lines)


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")[:200]
