"""Ecosystem handoffs, validated against the schemas the ecosystem actually publishes.

"HowlProof emits documents HowlPlane and HowlBoard already read" is a claim, and a
claim of that shape is exactly what this project exists to be sceptical about. So it
is tested: every emitted document is validated against a vendored copy of HowlPlane's
own JSON Schema, which is closed and rejects unknown fields.

Two of the three emitters failed this test when it was first written. Both were fixed.
"""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from howlproof.config import read_config
from howlproof.engine import evaluate
from howlproof.evaluators import build_registry
from howlproof.handoff import TARGETS, render, verification_plan

SCHEMAS = Path(__file__).parent / "ecosystem_schemas"
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    target = FIXTURES / "vulnerable_app"
    return evaluate(
        target_root=target,
        config=read_config(target / "howlproof.yaml"),
        registry=build_registry(),
        evidence_root=tmp_path_factory.mktemp("handoff") / "proof",
    )


def validate(name: str, documents: list[dict]) -> None:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    problems = [
        f"{'.'.join(map(str, error.path))}: {error.message}"
        for document in documents
        for error in validator.iter_errors(document)
    ]
    assert not problems, f"{name} rejects the emitted documents:\n" + "\n".join(problems[:10])
    assert documents, f"{name}: nothing was emitted to validate"


def test_plane_findings_match_the_review_finding_schema(result):
    _, content = render(result, "plane")
    document = yaml.safe_load(content)
    validate("review-finding", document["findings"])
    assert document["howlproof_verdict"] == result["verdict"]
    assert all(f["reviewer_role"].startswith("howlproof-") for f in document["findings"])


def test_board_evidence_matches_the_evidence_entry_schema(result):
    _, content = render(result, "board")
    entries = [json.loads(line) for line in content.splitlines() if line.strip()]
    validate("evidence-entry", entries)
    assert entries[0]["action"] == "verification_executed"
    assert all(entry["agent_id"] == "howlproof" for entry in entries)


def test_the_verification_plan_matches_its_schema(result):
    validate("verification-plan", [verification_plan(result)])


def test_the_verification_plan_keeps_the_original_status_visible(result):
    plan = verification_plan(result)
    inconclusive = [step for step in plan["steps"] if step["status"] == "skipped"]
    assert inconclusive, "the fixture should produce at least one inconclusive check"
    assert all("[howlproof status" in step["stderr"] for step in inconclusive), (
        "mapping UNAVAILABLE onto `skipped` must not lose the original status"
    )


def test_every_handoff_declares_advisory_authority(result):
    for target in TARGETS:
        _, content = render(result, target)
        assert content.strip(), f"{target} emitted nothing"
    assert result["findings"], "the fixture should produce findings to hand off"
    handoff = json.loads((Path(result["path"]) / "handoff.json").read_text())
    assert handoff["authority"] == "ADVISORY"
    assert "does not promote" in handoff["note"]


def test_the_changeops_handoff_does_not_imply_an_ingest_path(result):
    _, content = render(result, "changeops")
    assert "no HowlChangeOps ingest path" in content
    assert "HowlPlane" in content


def test_the_relay_handoff_uses_headings_relay_parses(result):
    _, content = render(result, "relay")
    for heading in (
        "## Objective",
        "## Current State",
        "## Known Failures",
        "## Blockers",
        "## Next Recommended Action",
        "## Commands to Resume Work",
    ):
        assert heading in content, f"HowlRelay's collector looks for {heading!r}"


def test_an_unknown_handoff_target_is_refused(result):
    with pytest.raises(KeyError, match="unknown handoff target"):
        render(result, "telepathy")
