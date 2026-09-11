"""Evaluators, tested against artifacts with known defects and against clean ones.

A check that only ever passes is worthless, and so is one that fires on everything.
Each evaluator is therefore run twice: once against a fixture carrying the exact defect
it looks for, and once against the same shape built correctly.
"""

import json
import shutil
from pathlib import Path

import pytest

from howlproof.config import read_config
from howlproof.engine import evaluate
from howlproof.evaluators import build_registry
from howlproof.model import Adversary, CheckStatus, Severity, Verdict
from howlproof.registry import Context, Evaluator, Outcome
from howlproof.target import Target, TargetError, TargetMutatedError

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_app"
CLEAN = FIXTURES / "clean_app"


def run(target: Path, tmp_path: Path, registry=None, profiles=None):
    config = read_config(target / "howlproof.yaml")
    if profiles:
        config = config.model_copy(update={"profiles": profiles})
    return evaluate(
        target_root=target,
        config=config,
        registry=registry or build_registry(),
        evidence_root=tmp_path / "proof",
    )


@pytest.fixture(scope="module")
def vulnerable(tmp_path_factory):
    return run(VULNERABLE, tmp_path_factory.mktemp("vulnerable"))


@pytest.fixture(scope="module")
def clean(tmp_path_factory):
    return run(CLEAN, tmp_path_factory.mktemp("clean"))


def rules(result):
    return {f["rule"] for f in result["findings"]}


def status_of(result, check_id):
    for check in result["checks"]:
        if check["check_id"] == check_id:
            return check["status"]
    raise AssertionError(
        f"{check_id} produced no result; got {[c['check_id'] for c in result['checks']]}"
    )


# -- the defects each evaluator exists to find ------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        "secrets.github_token",
        "ci.unpinned_action",
        "ci.pull_request_target",
        "ci.default_permissions",
        "ci.expression_injection",
        "markup.escaper_context_mismatch",
        "markup.sink_without_escaping",
        "docs.claims.sync_drift",
        "web.links.broken",
        "web.metadata.incomplete",
    ],
)
def test_each_planted_defect_is_found(vulnerable, rule):
    assert rule in rules(vulnerable)


def test_the_clean_fixture_raises_no_severe_findings(clean):
    severe = [
        f
        for f in clean["findings"]
        if f["severity"] in {Severity.BLOCKER.value, Severity.HIGH.value}
    ]
    assert severe == [], severe


def test_the_clean_fixture_raises_none_of_the_planted_rules(clean):
    planted = {
        "secrets.github_token",
        "ci.unpinned_action",
        "ci.pull_request_target",
        "ci.default_permissions",
        "ci.expression_injection",
        "markup.escaper_context_mismatch",
        "markup.sink_without_escaping",
        "docs.claims.sync_drift",
        "web.links.broken",
        "web.metadata.incomplete",
    }
    assert planted & rules(clean) == set()


def test_the_escaper_analysis_reads_the_artifact_own_escape_function(vulnerable):
    finding = next(
        f for f in vulnerable["findings"] if f["rule"] == "markup.escaper_context_mismatch"
    )
    assert "does not escape the single quote" in finding["title"]
    assert finding["severity"] == Severity.HIGH.value
    assert "src/render.js" in (finding["location"] or "")


def test_a_credential_is_reported_without_reprinting_it(vulnerable):
    finding = next(f for f in vulnerable["findings"] if f["rule"] == "secrets.github_token")
    assert "redacted" in finding["evidence"]
    assert "ZmFrZUZpeHR1cmVUb2tlbkZvclRlc3Rz" not in json.dumps(vulnerable)


def test_the_vulnerable_fixture_is_rejected(vulnerable):
    assert vulnerable["verdict"] == Verdict.REJECT.value


def test_the_clean_fixture_is_not_rejected(clean):
    assert clean["verdict"] in {Verdict.PROVEN.value, Verdict.CONDITIONALLY_PROVEN.value}


# -- honesty about what did not run -----------------------------------------


def test_an_absent_surface_is_not_applicable_rather_than_verified(clean):
    assert status_of(clean, "http.authz") == CheckStatus.NOT_APPLICABLE.value
    assert status_of(clean, "web.dom_injection") == CheckStatus.NOT_APPLICABLE.value


def test_every_inconclusive_check_records_a_reason(vulnerable, clean):
    for result in (vulnerable, clean):
        for check in result["checks"]:
            if check["status"] != CheckStatus.VERIFIED.value and check["status"] != (
                CheckStatus.FAILED.value
            ):
                assert check["reason"].strip(), check


def test_every_check_records_what_it_does_not_establish(vulnerable):
    for check in vulnerable["checks"]:
        assert check["limitation"].strip()


def test_validation_modes_stay_separable(clean):
    modes = clean["validation_modes"]
    assert set(modes) == {"REAL", "SIMULATED", "SKIPPED", "UNAVAILABLE", "NOT_APPLICABLE", "ERROR"}
    assert modes["REAL"]
    everything = sum(len(names) for names in modes.values())
    assert everything == len(clean["checks"])


def test_no_evaluator_errored_on_either_fixture(vulnerable, clean):
    for result in (vulnerable, clean):
        errored = [c for c in result["checks"] if c["status"] == CheckStatus.ERROR.value]
        assert errored == [], errored


# -- the separation of duties, enforced ------------------------------------


class _MutatingEvaluator(Evaluator):
    """An evaluator that repairs the artifact it is judging. This must not go unnoticed."""

    id = "test.mutates_target"
    adversary = Adversary.FUNCTIONAL

    def evaluate(self, context: Context) -> Outcome:
        (context.target.root / "REPAIRED_BY_THE_EVALUATOR.txt").write_text("fixed it\n")
        return Outcome(
            checks=[self.verified("everything is fine now", "this check proves nothing")]
        )


def test_an_evaluator_that_modifies_the_artifact_invalidates_the_evaluation(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    registry = build_registry()
    registry.register(_MutatingEvaluator())
    result = run(target, tmp_path, registry=registry, profiles=["test.mutates_target"])

    assert result["verdict"] == Verdict.INSUFFICIENT_EVIDENCE.value
    assert result["deciding_rule"] == "integrity"
    integrity = next(f for f in result["findings"] if f["adversary"] == Adversary.INTEGRITY.value)
    assert integrity["severity"] == Severity.BLOCKER.value
    assert "REPAIRED_BY_THE_EVALUATOR.txt" in json.dumps(integrity)


def test_the_target_is_read_through_a_copy_not_the_original(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    workspace = tmp_path / "workspace"
    handle = Target.prepare(target, workspace)
    (workspace / "README.md").write_text("rewritten inside the workspace")
    assert (target / "README.md").read_text() != "rewritten inside the workspace"
    handle.verify_unchanged()


def test_a_modified_original_is_detected(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    handle = Target.prepare(target, tmp_path / "workspace")
    (target / "README.md").write_text("changed behind the evaluator's back")
    with pytest.raises(TargetMutatedError, match="not trustworthy"):
        handle.verify_unchanged()
    assert "README.md (modified)" in handle.changed_paths()


def test_reads_cannot_escape_the_workspace(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    handle = Target.prepare(target, tmp_path / "workspace")
    with pytest.raises(TargetError, match="escapes the workspace"):
        handle.read_text("../../etc/passwd")


def test_a_workspace_inside_the_target_is_refused(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    with pytest.raises(TargetError, match="must not live inside the target"):
        Target.prepare(target, target / "workspace")


def test_an_evaluation_writes_nothing_into_the_artifact(tmp_path):
    target = tmp_path / "artifact"
    shutil.copytree(CLEAN, target)
    before = sorted(p.relative_to(target).as_posix() for p in target.rglob("*"))
    run(target, tmp_path)
    assert sorted(p.relative_to(target).as_posix() for p in target.rglob("*")) == before


# -- bundles ----------------------------------------------------------------


def test_the_bundle_can_be_re_read_and_verified(vulnerable):
    from howlproof.evidence import Bundle

    loaded = Bundle.load(Path(vulnerable["path"]))
    assert loaded["result"]["run_id"] == vulnerable["run_id"]
    assert loaded["manifest"]["authority"] == "ADVISORY"
    assert len(loaded["findings"]) == len(vulnerable["findings"])


def test_findings_carry_identifiers_severity_evidence_and_lifecycle(vulnerable):
    for finding in vulnerable["findings"]:
        assert finding["id"].startswith("HP-")
        assert finding["severity"] in {s.value for s in Severity}
        assert finding["evidence"].strip()
        assert finding["state"] == "FOUND"
        assert finding["fingerprint"]
