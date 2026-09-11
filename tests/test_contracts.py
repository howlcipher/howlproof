"""Contracts that keep a verdict honest: strict input, sealed evidence, stable identity."""

import json

import pytest
from pydantic import ValidationError

import howlproof
from howlproof.config import ProofConfig, read_config
from howlproof.evidence import Bundle, BundleError, new_run_id, redact, scrub
from howlproof.ledger import Ledger, LedgerError
from howlproof.model import (
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    FindingState,
    ModelError,
    Reproduction,
    ReproductionStep,
    Severity,
)


def contract(**updates):
    data = {
        "schema_version": 1,
        "artifact": "fixture",
        "acceptance": [{"id": "AC-01", "requirement": "max_findings", "limit": 0}],
    }
    data.update(updates)
    return ProofConfig.model_validate(data)


def finding(**updates):
    data = {
        "check_id": "secrets.scan",
        "adversary": Adversary.SECURITY,
        "category": "security",
        "title": "A credential is committed",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "summary": "A credential-shaped string is present in the tree.",
        "evidence": "config.py:3 ghp_...[40 chars redacted]",
        "recommended_remediation": "Rotate and remove it.",
    }
    data.update(updates)
    return Finding(**data)


def reproduction():
    return Reproduction(
        summary="Read the file again.",
        steps=[
            ReproductionStep(
                description="Search config.py",
                kind="file_probe",
                payload={"path": "config.py", "pattern": "ghp_"},
                expect={"matches": True},
            )
        ],
    )


# -- configuration ----------------------------------------------------------


@pytest.mark.parametrize(
    "update",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"schema_version": 1.0},
        {"unexpected_key": True},
        {"artifact": "has spaces"},
        {"profiles": []},
        {"adversaries": ["NOT_AN_ADVERSARY"]},
        {"blocking_severity": "CRITICAL"},
        {"acceptance": [{"id": "AC-01", "requirement": "no_such_requirement"}]},
        {
            "acceptance": [
                {"id": "AC-01", "requirement": "coverage_floor", "min_conclusive_fraction": 1.5}
            ]
        },
        {"acceptance": [{"id": "AC-01", "requirement": "checks_pass", "checks": []}]},
        {"exclusions": [{"check": "x", "reason": "short"}]},
        {"include_ignored": ["../escape"]},
        {"service": {"base_url": "http://evil.example.com"}},
        {"web": {"root": "../outside"}},
    ],
)
def test_contract_rejects_invalid(update):
    with pytest.raises(ValidationError):
        contract(**update)


def test_duplicate_criterion_ids_are_rejected():
    with pytest.raises(ValidationError):
        contract(
            acceptance=[
                {"id": "AC-01", "requirement": "no_regressions"},
                {"id": "AC-01", "requirement": "no_regressions"},
            ]
        )


def test_enum_names_are_accepted_but_unknown_values_are_not():
    assert contract(adversaries=["SECURITY"]).adversaries == [Adversary.SECURITY]
    with pytest.raises(ValidationError, match="expected one of"):
        contract(adversaries=["SECURITY", "HACKING"])


def test_config_larger_than_the_cap_is_refused(tmp_path):
    path = tmp_path / "howlproof.yaml"
    path.write_text("schema_version: 1\nartifact: big\ndescription: " + "x" * 300_000)
    with pytest.raises(ValueError, match="exceeds"):
        read_config(path)


def test_config_must_be_a_mapping(tmp_path):
    path = tmp_path / "howlproof.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="mapping"):
        read_config(path)


# -- results that cannot misrepresent themselves ----------------------------


def test_a_check_that_did_not_run_must_say_why():
    with pytest.raises(ModelError, match="requires an explicit reason"):
        CheckResult(
            check_id="python.tests",
            checker="python.tests/v1",
            adversary=Adversary.FUNCTIONAL,
            status=CheckStatus.UNAVAILABLE,
            summary="could not run",
            limitation="nothing was established",
        )


def test_every_check_must_state_what_it_does_not_establish():
    with pytest.raises(ModelError, match="does not establish"):
        CheckResult(
            check_id="python.tests",
            checker="python.tests/v1",
            adversary=Adversary.FUNCTIONAL,
            status=CheckStatus.VERIFIED,
            summary="passed",
            limitation="   ",
        )


def test_confirmed_confidence_requires_a_recorded_reproduction():
    with pytest.raises(ModelError, match="CONFIRMED requires a recorded reproduction"):
        finding(confidence=Confidence.CONFIRMED)
    assert finding(confidence=Confidence.CONFIRMED, reproduction=reproduction()).blocking


def test_a_finding_without_evidence_is_refused():
    with pytest.raises(ModelError, match="opinion"):
        finding(evidence="   ")


def test_dismissing_a_high_finding_without_a_reason_is_refused():
    with pytest.raises(ModelError, match="requires a reason"):
        finding(state=FindingState.ACCEPTED_RISK)
    accepted = finding(
        state=FindingState.ACCEPTED_RISK, resolution_reason="Rotated; fixture value only."
    )
    assert not accepted.blocking


def test_an_unreproduced_finding_does_not_block():
    assert not finding(severity=Severity.BLOCKER, confidence=Confidence.HIGH).blocking


def test_unknown_categories_are_refused():
    with pytest.raises(ModelError, match="unknown finding category"):
        finding(category="vibes")


def test_unsupported_reproduction_step_kinds_are_refused():
    with pytest.raises(ModelError, match="unsupported reproduction step kind"):
        ReproductionStep(description="x", kind="telepathy", payload={}, expect={})


# -- fingerprints -----------------------------------------------------------


def test_fingerprint_survives_line_numbers_paths_and_timestamps():
    first = finding(location="src/config.py:3", summary="found at 2026-09-11T10:00:00Z in /tmp/a")
    second = finding(location="src/config.py:41", summary="found at 2026-01-02T03:04:05Z in /tmp/b")
    assert first.fingerprint == second.fingerprint


def test_fingerprint_distinguishes_different_defects():
    assert finding().fingerprint != finding(title="A different defect", rule="other").fingerprint


# -- evidence bundles -------------------------------------------------------


def test_run_ids_follow_the_ecosystem_shape():
    run_id = new_run_id()
    assert run_id.startswith("hp-")
    stamp, suffix = run_id[3:].rsplit("-", 1)
    assert len(stamp) == 15 and len(suffix) == 12


def test_evidence_is_refused_inside_the_artifact(tmp_path):
    target = tmp_path / "artifact"
    target.mkdir()
    with pytest.raises(BundleError, match="refusing to write evidence inside"):
        Bundle.create(target / "proof", target)
    assert Bundle.create(tmp_path / "proof", target).path.exists()


def test_binary_evidence_is_hashed_by_bytes_not_decoded_text(tmp_path):
    """Two different images must not hash alike because both decode to the same text."""
    bundle = Bundle.create(tmp_path / "proof", tmp_path / "artifact")
    for name in ("target", "environment", "result", "handoff", "config"):
        bundle.write_json(f"{name}.json", {"name": name})
    bundle.write_jsonl("checks.jsonl", [{"check_id": "x"}])
    bundle.write_text("result.md", "# report")
    bundle.write_bytes("evidence/web/shot.png", b"\x89PNG\r\n\x1a\n\xff\xfe one")
    manifest = bundle.seal({"artifact": "fixture"})
    (bundle.path / "evidence" / "web" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe two")
    assert "evidence/web/shot.png" in manifest["file_hashes"]
    with pytest.raises(BundleError, match="integrity mismatch"):
        Bundle.load(bundle.path)


def test_a_sealed_bundle_detects_tampering(tmp_path):
    bundle = _seal(tmp_path)
    (bundle.path / "result.md").write_text("a different report")
    with pytest.raises(BundleError, match="integrity mismatch"):
        Bundle.load(bundle.path)


def test_a_bundle_missing_a_required_file_is_refused(tmp_path):
    bundle = _seal(tmp_path)
    manifest = json.loads((bundle.path / "manifest.json").read_text())
    del manifest["file_hashes"]["result.json"]
    (bundle.path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(BundleError, match="incomplete"):
        Bundle.load(bundle.path)


def test_a_bundle_claiming_authority_is_refused(tmp_path):
    bundle = _seal(tmp_path)
    manifest = json.loads((bundle.path / "manifest.json").read_text())
    manifest["authority"] = "APPROVED"
    (bundle.path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(BundleError, match="ADVISORY"):
        Bundle.load(bundle.path)


def test_evidence_paths_cannot_escape_the_bundle(tmp_path):
    bundle = Bundle.create(tmp_path / "proof", tmp_path / "artifact")
    with pytest.raises(BundleError, match="escapes the bundle"):
        bundle.write_text("../escaped.txt", "nope")


def _seal(tmp_path):
    bundle = Bundle.create(tmp_path / "proof", tmp_path / "artifact")
    for name in ("target", "environment", "result", "handoff", "config"):
        bundle.write_json(f"{name}.json", {"name": name})
    bundle.write_jsonl("checks.jsonl", [{"check_id": "x"}])
    bundle.write_text("result.md", "# report")
    bundle.seal({"artifact": "fixture"})
    return bundle


# -- redaction --------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "sk-" + "a" * 25,
        "ghp_" + "b" * 36,
        "Authorization: Bearer abcdefghijkl",
        'password="fixture-secret-value"',
    ],
)
def test_secrets_are_redacted_from_evidence(secret):
    assert secret not in redact(secret)


def test_secret_keys_are_redacted_even_with_unrecognised_values():
    assert "unrecognised" not in json.dumps(scrub({"api_key": "unrecognised"}))


# -- ledger -----------------------------------------------------------------


def test_a_finding_keeps_its_identifier_across_runs(tmp_path):
    ledger = Ledger.open(tmp_path)
    first = ledger.assign("fixture", finding(), "hp-run-one", "aaa", "digest-one")
    ledger.save()
    reopened = Ledger.open(tmp_path)
    second = reopened.assign("fixture", finding(), "hp-run-two", "bbb", "digest-two")
    assert first.id == second.id == "HP-SEC-0001"
    assert second.first_seen_run == "hp-run-one"


def test_identifiers_are_allocated_per_adversary(tmp_path):
    ledger = Ledger.open(tmp_path)
    security = ledger.assign("fixture", finding(), "run", "sha")
    operator = ledger.assign(
        "fixture",
        finding(
            adversary=Adversary.OPERATOR,
            category="other",
            title="Broken link",
            check_id="web.links",
        ),
        "run",
        "sha",
    )
    assert security.id == "HP-SEC-0001"
    assert operator.id == "HP-OPS-0001"


def test_a_fixed_finding_that_returns_is_recorded_as_a_regression(tmp_path):
    ledger = Ledger.open(tmp_path)
    raised = ledger.assign("fixture", finding(), "run-one", "sha")
    ledger.record_state("fixture", raised.id, FindingState.VERIFIED_FIXED, "run-two", "re-ran")
    returning = ledger.assign("fixture", finding(), "run-three", "sha")
    assert returning.state is FindingState.REGRESSED


def test_an_unknown_finding_cannot_be_moved(tmp_path):
    with pytest.raises(LedgerError, match="unknown finding"):
        Ledger.open(tmp_path).record_state(
            "fixture", "HP-SEC-9999", FindingState.RETESTED, "r", "n"
        )


def test_a_ledger_from_an_incompatible_version_is_refused(tmp_path):
    (tmp_path / "ledger.json").write_text(json.dumps({"schema": "howlproof.ledger/v99"}))
    with pytest.raises(LedgerError, match="unsupported ledger schema"):
        Ledger.open(tmp_path)


# -- versioning -------------------------------------------------------------


def test_the_declared_version_matches_the_package():
    assert howlproof.__version__ == "0.1.0"
