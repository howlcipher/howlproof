"""Independently adjudicate the Writer PDF heading regression evidence."""

from importlib import import_module
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

CHECKS = {"heading", "adjacent_paragraph", "reference", "page_number"}
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


def verify_pdf_evidence(
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
    if (
        candidate["project"],
        candidate["operation"],
        candidate["problem"],
        candidate["detail"],
    ) != ("writer", "pdf", "failed", "validation"):
        raise ValueError("candidate does not describe the Writer PDF validation scenario")

    def parse_samples(samples: Any, fixed: bool) -> tuple[list[Any], str]:
        if not isinstance(samples, list) or not 2 <= len(samples) <= 10:
            raise ValueError("expected two to ten PDF samples")
        events = []
        for sample in samples:
            if not isinstance(sample, dict) or set(sample) != {"event", "checks", "producer"}:
                raise ValueError("invalid sample fields")
            expected_checks = dict.fromkeys(CHECKS, True)
            expected_checks["adjacent_paragraph"] = fixed
            checks = sample["checks"]
            if (
                not isinstance(checks, dict)
                or checks.keys() != CHECKS
                or any(type(value) is not bool for value in checks.values())
                or checks != expected_checks
                or sample["producer"] != "Skia/PDF"
            ):
                raise ValueError("PDF result disagrees with the scenario")
            event = contracts.Event.parse(sample["event"])
            if (
                event.project != "writer"
                or event.operation != "pdf"
                or event.source != "observed"
                or event.result != ("ok" if fixed else "failed")
                or event.validation != ("passed" if fixed else "failed")
                or event.environment != "linux"
                or not event.commit
                or not event.duration_ns
            ):
                raise ValueError("unmatched PDF observation")
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

    validate_regression_report(read_pinned(regression_path, expected_hashes[3]))
    result = {
        "schema": "howlproof.improvement_verification/v1",
        "candidate_id": candidate["candidate_id"],
        "authority": "none",
        "verdict": "supported",
        "scenario": "writer_pdf_heading",
        "baseline_commit": old_commit,
        "candidate_commit": new_commit,
        "baseline_samples": len(old_events),
        "candidate_samples": len(new_events),
        "artifact_hashes": expected_hashes,
        "regression_checks": sorted(REGRESSIONS),
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


def validate_regression_report(xml: bytes) -> None:
    if len(xml) > 65536:
        raise ValueError("regression report exceeds size limit")
    try:
        root = fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError("invalid or unsupported regression report") from exc
    suites = list(root.iter("testsuite"))
    if (
        not suites
        or any(
            suite.get(key, "0") != "0"
            for suite in suites
            for key in ("errors", "failures", "skipped")
        )
        or any(list(root.iter(tag)) for tag in ("failure", "error", "skipped"))
    ):
        raise ValueError("regression report must record executed and passing checks")
    names = [(test.get("classname"), test.get("name")) for test in root.iter("testcase")]
    if any(names.count(name) != 1 for name in REGRESSIONS):
        raise ValueError("required PDF regression check missing or duplicated")
