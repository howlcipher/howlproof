"""Tests for the howl.claim_bundle/v1 JSON Schema contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from howlproof.evaluators import research

SCHEMAS_DIR = Path(__file__).resolve().parent / "ecosystem_schemas"
SCHEMA_PATH = SCHEMAS_DIR / "howl.claim_bundle.v1.schema.json"
REPO_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "schemas" / "howl.claim_bundle.v1.schema.json"
)


@pytest.fixture
def claim_bundle_schema() -> dict[str, Any]:
    assert SCHEMA_PATH.exists(), f"Missing vendored schema at {SCHEMA_PATH}"
    return json.loads(SCHEMA_PATH.read_text())


def test_root_and_vendored_schemas_are_identical():
    assert REPO_SCHEMA_PATH.exists(), f"Missing repo schema at {REPO_SCHEMA_PATH}"
    assert SCHEMA_PATH.exists(), f"Missing vendored schema at {SCHEMA_PATH}"
    assert REPO_SCHEMA_PATH.read_text() == SCHEMA_PATH.read_text()


def canonical_bundle() -> dict[str, Any]:
    return {
        "schema": "howl.claim_bundle/v1",
        "candidate": {
            "candidate_id": "cand-001",
            "source_run_id": "run-001",
            "parent_request_id": "req-001",
            "objective": "Verify claims",
            "text": "Idea proposal",
            "status": "GENERATED",
            "trust": "UNVERIFIED",
        },
        "authorship": {
            "kind": "EXTERNAL_AUTHORED",
            "component": "test-agent",
            "provider": None,
            "model": None,
        },
        "claims": [
            {
                "claim_id": "c001",
                "text": "Latency is under 50 ms",
                "category": "EMPIRICAL",
                "evidence_refs": ["e001"],
                "assumption": False,
                "check": {
                    "type": "fact_compare",
                    "fact": "latency_ms",
                    "op": "le",
                    "expected": "50 ms",
                    "tolerance": "0",
                },
                "subject_terms": ["Latency"],
                "checked_proposition": "Latency does not exceed 50 ms",
                "scope": {"artifact": "benchmark.md", "extent": "SINGLE_FILE"},
                "verification_plan": {
                    "status": "PROPOSED",
                    "grounded": True,
                    "methods": ["compare against independent primary-source data"],
                    "note": "a proposed plan is not an acceptance test",
                },
            }
        ],
        "evidence": [
            {
                "id": "e001",
                "path": "evidence/001-latency.json",
                "sha256": "0" * 64,
                "source_type": "EXTERNAL_OBSERVATION",
                "produced_by": "bench-tool",
                "source_ref": "https://example.com/bench",
                "independent": True,
                "represents_observed_reality": True,
                "published_at": "2026-03-01T00:00:00Z",
                "acquisition": {
                    "id": "acq-1234567890abcdef",
                    "content_sha256": "1" * 64,
                },
                "methodology_quote": (
                    "We measured the end-to-end response latency across 100 trials"
                ),
            }
        ],
        "lineage": {
            "exported_by": "howldream",
            "exporter_version": "0.4.5",
            "candidate_created_at": "2026-03-01T00:00:00Z",
            "candidate_sha256": "2" * 64,
        },
    }


def test_schema_validates_canonical_claim_bundle(claim_bundle_schema):
    bundle = canonical_bundle()
    jsonschema.validate(bundle, claim_bundle_schema)
    # HowlProof evaluator's internal validator also accepts it
    research.validate_bundle(bundle)


def test_schema_rejects_missing_required_top_level_fields(claim_bundle_schema):
    bundle = canonical_bundle()
    for required in ("schema", "candidate", "authorship"):
        broken = {k: v for k, v in bundle.items() if k != required}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(broken, claim_bundle_schema)


def test_schema_rejects_unsupported_schema_version(claim_bundle_schema):
    bundle = canonical_bundle()
    bundle["schema"] = "howl.claim_bundle/v2"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)

    bundle["schema"] = "howl.candidate/v1"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)


@pytest.mark.parametrize(
    "category",
    ["EMPIRICAL", "TECHNICAL", "HYPOTHESIS", "VALUE_JUDGMENT"],
)
def test_all_valid_categories_accepted(claim_bundle_schema, category):
    bundle = canonical_bundle()
    bundle["claims"][0]["category"] = category
    jsonschema.validate(bundle, claim_bundle_schema)


@pytest.mark.parametrize(
    "bad_category",
    ["OPINION", "FACT", "CONJECTURE", "PROVEN", ""],
)
def test_invalid_category_rejected(claim_bundle_schema, bad_category):
    bundle = canonical_bundle()
    bundle["claims"][0]["category"] = bad_category
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)


def test_injected_authority_rejected_by_schema(claim_bundle_schema):
    """Claim bundles carry claims, not execution authority. Injected authority is rejected."""
    bundle = canonical_bundle()
    bundle["authority"] = {"type": "EXECUTIVE", "executable": True}
    with pytest.raises(jsonschema.ValidationError) as exc:
        jsonschema.validate(bundle, claim_bundle_schema)
    assert "additionalProperties" in str(exc.value) or "authority" in str(exc.value)


def test_injected_executable_flag_rejected_by_schema(claim_bundle_schema):
    bundle = canonical_bundle()
    bundle["executable"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)


def test_bad_evidence_digest_rejected_by_schema(claim_bundle_schema):
    bundle = canonical_bundle()
    bundle["evidence"][0]["sha256"] = "not-a-64-char-digest"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)


def test_bad_acquisition_pointer_rejected_by_schema(claim_bundle_schema):
    bundle = canonical_bundle()
    bundle["evidence"][0]["acquisition"] = {"id": "bad-prefix", "content_sha256": "1" * 64}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bundle, claim_bundle_schema)
