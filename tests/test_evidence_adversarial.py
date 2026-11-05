"""Final adversarial audit of the evidence trust model.

Two kinds of test live here. Attacks that must fail are asserted to fail. Attacks that still
succeed are asserted *to succeed* and named `test_known_limit_*`: they document exactly what
HowlProof cannot establish, so a future change that closes one has to update the record.
"""

from __future__ import annotations

import time

import pytest
from test_acquire import Fake, R, ok
from test_evidence_trust import (
    DECLARED,
    REAL,
    SOURCE,
    ev,
    evaluate,
    lat_claim,
    presence_claim,
    write_bundle,
)
from test_research_claims import claim, fact_check

from howlproof.acquire import AcquisitionStore, acquire_url
from howlproof.evaluators import research
from howlproof.trust import locate_phrase, source_text


@pytest.fixture
def store(tmp_path):
    return AcquisitionStore(tmp_path / "store")


# -- hostile content cannot stall the evaluator ---------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    ["<" * 200_000, "<a " * 100_000, "<script>" + "a" * 200_000, "<!--" * 50_000],
    ids=["lt-flood", "open-tags", "unterminated-script", "comment-flood"],
)
def test_pathological_markup_is_processed_in_linear_time(payload):
    started = time.monotonic()
    source_text(payload.encode(), "text/html")
    assert time.monotonic() - started < 2.0


def test_markup_is_reduced_to_visible_text_and_scripts_are_dropped():
    html = "<html><script>var secret='Rubydex 99 ms'</script><p>Rubydex &amp; 42&nbsp;ms</p></html>"
    text = source_text(html.encode(), "text/html")
    assert "Rubydex & 42" in text and "secret" not in text


def test_plain_text_is_not_treated_as_markup():
    assert source_text(b"if a < b and c > d then", "text/plain") == "if a < b and c > d then"


def test_a_bundle_cannot_cite_an_unbounded_number_of_evidence_records(tmp_path):
    root = tmp_path / "bundle"
    many = [ev(root, f"e{i}", facts={}) for i in range(research.MAX_EVIDENCE + 1)]
    write_bundle(root, [], many, authorship=REAL)
    from test_research_claims import run

    outcome = run(tmp_path, root)
    assert outcome.checks[0].status.value == "ERROR"
    assert "at most" in outcome.checks[0].reason


def test_total_source_text_is_budgeted_and_overflow_is_unverifiable(tmp_path, store, monkeypatch):
    monkeypatch.setattr(research, "MAX_TOTAL_SOURCE_CHARS", 120)
    root = tmp_path / "bundle"
    first = ev(root, "e1", facts={"latency_ms": "42 ms"}, store=store, raw=SOURCE + "Rubydex 42 ms")
    second = ev(
        root, "e2", facts={"latency_ms": "42 ms"}, store=store,
        raw=SOURCE + "Rubydex 42 ms again", url="https://b.example.com/x",
    )  # fmt: skip
    cl = lat_claim()
    cl["evidence_refs"] = ["e1", "e2"]
    write_bundle(root, [cl], [first, second], authorship=REAL)
    rows = {r["id"]: r for r in evaluate(tmp_path, root, store.root)["c1"]["evidence_considered"]}
    assert rows["e1"]["trust"]["acquisition"] == "OBSERVED"
    assert rows["e2"]["trust"]["acquisition"] == "SOURCE_BUDGET_EXCEEDED"
    assert rows["e2"]["eligible"] is False


def test_an_oversize_stored_artifact_is_refused_not_loaded(tmp_path, store):
    record, raw = acquire_url("https://a.example.com/x", transport=Fake(ok()), resolve=R)
    sealed = store.add(record, raw)
    (store.root / "raw" / sealed["content_sha256"]).write_bytes(b"x" * (5 * 1024 * 1024))
    assert store.verify(sealed["id"], sealed["content_sha256"]).status == "TOO_LARGE"


# -- attacks that must fail ----------------------------------------------------------------------------


def test_a_generic_phrase_is_not_a_methodology(tmp_path, store):
    root = tmp_path / "bundle"
    e = ev(
        root, "e1", facts={"latency_ms": "42 ms"}, store=store, raw=SOURCE + "Rubydex 42 ms",
        extra={"methodology_quote": "Rubydex"},
    )  # fmt: skip
    cl = lat_claim()
    cl["check"] = fact_check("latency_ms", "50 ms", "le")
    write_bundle(root, [cl], [e], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "INCONCLUSIVE"
    assert c["assurance"]["methodology"] == "NOT_RECORDED"


def test_text_presence_reports_the_proposition_actually_checked_not_the_broad_claim(
    tmp_path, store
):
    """Attack: a broad claim, a one-file check, and no `checked_proposition` supplied."""
    root = tmp_path / "bundle"
    readme = ev(
        root,
        "readme",
        facts={},
        store=store,
        raw="Mutant is a mutation tool.",
        url="https://github.com/mbj/mutant",
    )
    broad = presence_claim()
    broad["text"] = "Mutant has no AI agent integration"
    del broad["checked_proposition"]
    del broad["scope"]
    broad["check"] = {"type": "text_presence", "term": "agent", "expect": "absent"}
    write_bundle(root, [broad], [readme], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "SUPPORTED" and c["scope_limited"] is True
    assert c["checked_proposition"] != broad["text"]
    assert "readme" in c["checked_proposition"] and "'agent'" in c["checked_proposition"]
    assert c["broader_question"] == "NOT_EVALUATED"


def test_declaring_a_full_question_scope_cannot_widen_a_text_presence_result(tmp_path, store):
    root = tmp_path / "bundle"
    readme = ev(
        root,
        "readme",
        facts={},
        store=store,
        raw="Mutant is a tool.",
        url="https://github.com/mbj/mutant",
    )
    c = presence_claim(scope={"artifact": "everything", "extent": "FULL_QUESTION"})
    write_bundle(root, [c], [readme], authorship=REAL)
    assert evaluate(tmp_path, root, store.root)["c1"]["scope_limited"] is True


def test_two_acquisitions_of_the_same_bytes_cannot_manufacture_corroboration(tmp_path, store):
    root = tmp_path / "bundle"
    raw = SOURCE + "Rubydex 42 ms"
    entries = [
        ev(
            root,
            f"e{i}",
            facts={"latency_ms": "42 ms"},
            store=store,
            raw=raw,
            url=f"https://a.example.com/r?utm_x={i}",
        )
        for i in range(3)
    ]
    cl = lat_claim()
    cl["evidence_refs"] = ["e0", "e1", "e2"]
    write_bundle(root, [cl], entries, authorship=REAL)
    a = evaluate(tmp_path, root, store.root)["c1"]["assurance"]
    assert a["corroboration"] == "DUPLICATES_ONLY" and a["corroborated"] is False


def test_two_versions_of_one_url_with_different_numbers_are_a_preserved_conflict(tmp_path, store):
    root = tmp_path / "bundle"
    v1 = ev(root, "v1", facts={"latency_ms": "42 ms"}, store=store, raw=SOURCE + "Rubydex 42 ms")
    v2 = ev(root, "v2", facts={"latency_ms": "180 ms"}, store=store, raw=SOURCE + "Rubydex 180 ms")
    cl = lat_claim()
    cl["evidence_refs"] = ["v1", "v2"]
    write_bundle(root, [cl], [v1, v2], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "INCONCLUSIVE" and c["conflicts"]


def test_fabricated_contradicting_evidence_cannot_silently_cancel_a_real_refutation(
    tmp_path, store
):
    root = tmp_path / "bundle"
    real = ev(
        root, "real", facts={"latency_ms": "180 ms"}, store=store, raw=SOURCE + "Rubydex 180 ms"
    )
    fake = ev(root, "fake", facts={"latency_ms": "42 ms"}, url="https://railsatscale.com/x")
    cl = lat_claim()
    cl["evidence_refs"] = ["real", "fake"]
    write_bundle(root, [cl], [real, fake], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "INCONCLUSIVE" and c["conflicts"]  # conservative, and visible


# -- KNOWN LIMITS: attacks that still succeed, recorded so they are never forgotten ------------------------


def test_known_limit_a_real_number_with_the_wrong_meaning_passes(tmp_path, store):
    """The source says 42 ms is a *build* time; the agent labels it request latency. Location
    finds the number, not its meaning. Only a reviewer reading the source catches this."""
    root = tmp_path / "bundle"
    raw = SOURCE + "Rubydex full index build took 42 ms on the sample app."
    e = ev(root, "e1", facts={"latency_ms": "42 ms"}, store=store, raw=raw)
    write_bundle(root, [lat_claim()], [e], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "SUPPORTED"  # KNOWN LIMIT
    assert c["assurance"]["claim_relevance"] == "STRUCTURAL_MATCH"  # never "substantive"
    assert c["assurance"]["real_world_truth"] == "UNRESOLVED"
    assert c["assurance"]["corroborated"] is False


def test_known_limit_author_chosen_subject_terms_can_be_too_generic(tmp_path, store):
    root = tmp_path / "bundle"
    e = ev(
        root,
        "e1",
        facts={"latency_ms": "42 ms"},
        store=store,
        raw="Ruby news. Latency 42 ms for the website.",
    )
    cl = lat_claim(subject_terms=["Ruby"])  # the claim is about Rubydex; the page is not
    write_bundle(root, [cl], [e], authorship=REAL)
    assert evaluate(tmp_path, root, store.root)["c1"]["claim_status"] == "SUPPORTED"  # KNOWN LIMIT


def test_known_limit_a_vendors_own_page_passes_as_a_single_uncorroborated_source(tmp_path, store):
    root = tmp_path / "bundle"
    e = ev(
        root, "e1", facts={"latency_ms": "42 ms"}, store=store, raw=SOURCE + "Rubydex 42 ms (our own numbers)",
        declared={**DECLARED, "produced_by": "the-vendor"},
    )  # fmt: skip
    write_bundle(root, [lat_claim()], [e], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "SUPPORTED"  # KNOWN LIMIT: vendor claims look like any source
    assert c["assurance"]["corroboration"] == "SINGLE_SOURCE"


def test_known_limit_whoever_can_write_the_acquisition_store_can_forge_a_record(tmp_path, store):
    """No signing key or execution boundary exists, so none is claimed."""
    root = tmp_path / "bundle"
    forged = "Rubydex benchmark. Rubydex p95 was 42 ms."
    e = ev(root, "e1", facts={"latency_ms": "42 ms"}, store=store, raw=forged)  # attacker-written
    write_bundle(root, [lat_claim()], [e], authorship=REAL)
    c = evaluate(tmp_path, root, store.root)["c1"]
    assert c["claim_status"] == "SUPPORTED"  # KNOWN LIMIT: provenance is only as good as the store
    assert c["evidence_considered"][0]["trust"]["acquisition_method"] == "https_get"


def test_phrase_location_is_the_same_helper_the_attacks_rely_on():
    assert locate_phrase("Rubydex", "RUBYDEX  rocks")


def test_the_claim_helper_is_still_importable():
    assert claim("c", "t", "EMPIRICAL")["claim_id"] == "c"
