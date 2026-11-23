"""Independently adjudicate pinned Writer heading regression evidence."""

from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

HEADING_CHECKS = frozenset({"heading", "adjacent_paragraph", "reference"})
CHECKS = HEADING_CHECKS | {"page_number"}
REGRESSIONS = {
    (
        "tests.rendering.test_pdf_heading_content",
        "test_heading_does_not_discard_adjacent_paragraph",
    ),
    ("tests.rendering.test_pdf_heading_content", "test_stacked_headings_preserve_depth"),
    ("tests.rendering.test_pdf_heading_content", "test_following_section_ends_reference_styling"),
    ("tests.rendering.test_pdf_heading_content", "test_fallback_keep_paragraph_following_heading"),
    ("tests.rendering.test_pdf_fallback", "test_fallback_preserves_long_paragraphs_and_structure"),
    ("tests.rendering.test_rendering", "test_pdf_renderer"),
}


@dataclass(frozen=True)
class VerificationProfile:
    operation: str
    producer: str
    checks: frozenset[str]
    regressions: frozenset[tuple[str, str]]


PDF_PROFILE = VerificationProfile("pdf", "Skia/PDF", CHECKS, frozenset(REGRESSIONS))
DOCX_PROFILE = VerificationProfile(
    "docx",
    "python-docx",
    HEADING_CHECKS,
    frozenset(
        {
            (
                "tests.rendering.test_docx_heading_content",
                "test_docx_retains_prose_immediately_after_heading",
            ),
            (
                "tests.rendering.test_docx_heading_content",
                "test_docx_preserves_heading_depth_and_reference_scope",
            ),
            (
                "tests.rendering.test_docx_heading_content",
                "test_docx_adjacent_fenced_code_preserves_heading_like_lines",
            ),
            (
                "tests.rendering.test_docx_heading_content",
                "test_docx_indented_fence_keeps_info_bearing_lines_literal",
            ),
            (
                "tests.rendering.test_docx_heading_content",
                "test_docx_long_fence_preserves_shorter_fence_as_code",
            ),
            ("tests.rendering.test_pdf_fallback", "test_fallback_keeps_code_inside_a_longer_fence"),
        }
    ),
)
PROFILES = {profile.operation: profile for profile in (PDF_PROFILE, DOCX_PROFILE)}


def validate_sample(sample: Any, profile: VerificationProfile, *, fixed: bool) -> None:
    if not isinstance(sample, dict) or set(sample) != {"event", "checks", "producer"}:
        raise ValueError("invalid sample fields")
    expected = dict.fromkeys(profile.checks, True)
    expected["adjacent_paragraph"] = fixed
    checks = sample["checks"]
    if (
        not isinstance(checks, dict)
        or any(type(value) is not bool for value in checks.values())
        or checks != expected
        or sample["producer"] != profile.producer
    ):
        raise ValueError(f"{profile.operation.upper()} result disagrees with the scenario")


def verify_improvement_evidence(
    candidate_path: Path,
    baseline_path: Path,
    current_path: Path,
    regression_path: Path,
    expected_hashes: list[str],
    store_path: Path | None = None,
) -> dict[str, Any]:
    try:
        contracts = import_module("howlloop.contracts")
        analysis = import_module("howlloop.analysis")
        lifecycle = import_module("howlloop.lifecycle")
    except ImportError as exc:
        raise ValueError("Install HowlLoop in the HowlProof environment") from exc

    if len(expected_hashes) != 4 or not all(contracts.hex_text(value) for value in expected_hashes):
        raise ValueError("four SHA-256 pins are required")

    def read_pinned(path: Path, expected: str) -> bytes:
        from hashlib import sha256

        with path.open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536 or sha256(data).hexdigest() != expected:
            raise ValueError("evidence exceeds the limit or does not match its pinned digest")
        return data

    candidate, baseline, current = (
        contracts.decode(read_pinned(path, expected))
        for path, expected in zip(
            (candidate_path, baseline_path, current_path), expected_hashes[:3], strict=True
        )
    )
    candidate = analysis.validate_candidate(candidate)
    profile = PROFILES.get(candidate["operation"])
    if profile is None or (candidate["project"], candidate["problem"], candidate["detail"]) != (
        "writer",
        "failed",
        "validation",
    ):
        raise ValueError("candidate does not describe a supported Writer validation scenario")

    def parse_samples(samples: Any, fixed: bool) -> tuple[list[Any], str]:
        if not isinstance(samples, list) or not 2 <= len(samples) <= 10:
            raise ValueError(f"expected two to ten {profile.operation.upper()} samples")
        events = []
        for sample in samples:
            validate_sample(sample, profile, fixed=fixed)
            event = contracts.Event.parse(sample["event"])
            if (
                event.project != "writer"
                or event.operation != profile.operation
                or event.source != "observed"
                or event.result != ("ok" if fixed else "failed")
                or event.validation != ("passed" if fixed else "failed")
                or event.environment != "linux"
                or not event.commit
                or not event.duration_ns
            ):
                raise ValueError(f"unmatched {profile.operation.upper()} observation")
            events.append(event)
        commits = {event.commit for event in events}
        if len(commits) != 1 or len({event.run_id for event in events}) != len(events):
            raise ValueError("mixed revisions or duplicate runs")
        return events, commits.pop()

    old_events, old_commit = parse_samples(baseline, False)
    new_events, new_commit = parse_samples(current, True)
    lifecycle.validate_evidence(candidate, old_events)
    if old_commit == new_commit or {e.run_id for e in old_events} & {e.run_id for e in new_events}:
        raise ValueError("verification requires a distinct candidate revision and new observations")

    validate_regression_report(
        read_pinned(regression_path, expected_hashes[3]), profile.regressions
    )
    result = {
        "schema": "howlproof.improvement_verification/v1",
        "candidate_id": candidate["candidate_id"],
        "authority": "none",
        "verdict": "supported",
        "scenario": f"writer_{profile.operation}_heading",
        "baseline_commit": old_commit,
        "candidate_commit": new_commit,
        "baseline_samples": len(old_events),
        "candidate_samples": len(new_events),
        "artifact_hashes": expected_hashes,
        "regression_checks": sorted(profile.regressions),
        "performance": "inconclusive; sequential runs do not establish a speed change",
        "scope": "Adjudicates pinned observations and test results supplied by the verifier.",
    }
    if store_path is not None:
        store_api = import_module("howlloop.store")
        store = store_api.Store(store_path)
        receipt = contracts.digest(result)

        def confirm(data: Any, state: str, digest: str) -> bool:
            return data == candidate and state == "verified" and digest == receipt

        try:
            lifecycle.transition(store, candidate, "verified", receipt=receipt, verify=confirm)
        except store_api.StorageError as exc:
            raise ValueError("HowlLoop evidence store is unavailable") from exc
    return result


def validate_regression_report(
    xml: bytes, required: AbstractSet[tuple[str, str]] = PDF_PROFILE.regressions
) -> None:
    if len(xml) > 65536:
        raise ValueError("regression report exceeds size limit")
    try:
        root = fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("invalid or unsupported regression report") from exc
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    groups = [(suite, suite.findall("testcase")) for suite in suites]
    cases = [case for _, group in groups for case in group]
    if root.tag == "testsuites":
        groups.append((root, cases))
    if (
        root.tag not in {"testsuite", "testsuites"}
        or not suites
        or len(suites) != len(list(root.iter("testsuite")))
        or len(cases) != len(list(root.iter("testcase")))
        or any(
            node.get("tests", str(len(group))) != str(len(group))
            or any(node.get(key, "0") != "0" for key in ("errors", "failures", "skipped"))
            for node, group in groups
        )
        or any(list(root.iter(tag)) for tag in ("failure", "error", "skipped"))
    ):
        raise ValueError("regression report must record executed and passing checks")
    names = [(test.get("classname"), test.get("name")) for test in cases]
    if any(names.count(name) != 1 for name in required):
        raise ValueError("required regression check missing or duplicated")
