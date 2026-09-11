"""The command line as a pipeline would use it: real processes, real exit codes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_app"
CLEAN = FIXTURES / "clean_app"

EXIT_PROVEN = 0
EXIT_CONDITIONAL = 10
EXIT_REQUIRES_HUMAN = 20
EXIT_REJECT = 30
EXIT_INSUFFICIENT = 40
EXIT_USAGE = 2


def howlproof(*arguments, expect=None):
    result = subprocess.run(
        [sys.executable, "-m", "howlproof.cli", *arguments],
        capture_output=True,
        check=False,
        text=True,
    )
    if expect is not None:
        assert result.returncode == expect, (
            f"expected exit {expect}, got {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result


@pytest.fixture(scope="module")
def rejected(tmp_path_factory):
    root = tmp_path_factory.mktemp("reject")
    result = howlproof(
        "evaluate", str(VULNERABLE), "--evidence-root", str(root), "--json", expect=EXIT_REJECT
    )
    return json.loads(result.stdout), root


@pytest.fixture(scope="module")
def accepted(tmp_path_factory):
    root = tmp_path_factory.mktemp("accept")
    result = howlproof(
        "evaluate", str(CLEAN), "--evidence-root", str(root), "--json", expect=EXIT_CONDITIONAL
    )
    return json.loads(result.stdout), root


# -- basics -----------------------------------------------------------------


def test_version_is_reported():
    assert howlproof("--version", expect=0).stdout.strip() == "0.1.0"


def test_help_succeeds():
    assert "red-team" in howlproof("--help", expect=0).stdout


def test_no_command_is_a_usage_error():
    assert howlproof().returncode == EXIT_USAGE


def test_an_unknown_command_is_a_usage_error():
    assert howlproof("definitely-not-a-command").returncode == EXIT_USAGE


def test_a_missing_target_fails_without_a_traceback():
    result = howlproof("evaluate", "/nonexistent/path/for/howlproof")
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["error"]


# -- verdicts carry into exit codes ----------------------------------------


def test_a_rejected_artifact_exits_thirty(rejected):
    result, _ = rejected
    assert result["verdict"] == "REJECT"


def test_an_artifact_with_no_contract_cannot_reach_zero(tmp_path):
    artifact = tmp_path / "bare"
    artifact.mkdir()
    (artifact / "README.md").write_text("# Nothing declared here\n")
    result = howlproof(
        "evaluate",
        str(artifact),
        "--profile",
        "documentation",
        "--evidence-root",
        str(tmp_path / "proof"),
        "--json",
        expect=EXIT_INSUFFICIENT,
    )
    assert json.loads(result.stdout)["deciding_rule"] == "no_acceptance_criteria"


def test_fail_under_collapses_the_verdict_for_simple_pipelines(tmp_path):
    howlproof(
        "evaluate",
        str(CLEAN),
        "--evidence-root",
        str(tmp_path / "proof"),
        "--fail-under",
        "CONDITIONALLY_PROVEN",
        expect=EXIT_PROVEN,
    )


def test_fail_under_still_fails_a_worse_verdict(tmp_path):
    howlproof(
        "evaluate",
        str(VULNERABLE),
        "--evidence-root",
        str(tmp_path / "proof"),
        "--fail-under",
        "CONDITIONALLY_PROVEN",
        expect=EXIT_REJECT,
    )


def test_evidence_inside_the_artifact_is_refused(tmp_path):
    result = howlproof(
        "evaluate", str(CLEAN), "--evidence-root", str(CLEAN / "proof"), expect=EXIT_USAGE
    )
    assert "refusing to write evidence inside" in json.loads(result.stderr)["error"]


def test_an_artifact_that_mutates_itself_exits_four(tmp_path):
    """Exit 4 is a documented behaviour, so it is exercised through the real CLI.

    The artifact's own declared command writes into the artifact while the evaluation
    is running. Nothing HowlProof does causes this, which is the point: the guard is
    on the subject, not on the evaluator's good intentions.
    """
    artifact = tmp_path / "self-mutating"
    artifact.mkdir()
    (artifact / "README.md").write_text("# An artifact that edits itself mid-evaluation\n")
    marker = artifact / "WRITTEN_DURING_EVALUATION.txt"
    (artifact / "howlproof.yaml").write_text(
        "schema_version: 1\n"
        "artifact: self-mutating\n"
        "profiles: [cli.contract]\n"
        "acceptance:\n"
        "  - {id: AC-01, requirement: max_findings, limit: 0}\n"
        "cli:\n"
        "  command:\n"
        "    - python3\n"
        "    - -c\n"
        f"    - \"open({str(marker)!r}, 'a').write('x')\"\n"
    )
    result = howlproof(
        "evaluate",
        str(artifact),
        "--evidence-root",
        str(tmp_path / "proof"),
        "--json",
        expect=4,
    )
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert payload["deciding_rule"] == "integrity"
    integrity = next(f for f in payload["findings"] if f["adversary"] == "INTEGRITY")
    assert integrity["severity"] == "BLOCKER"
    assert "WRITTEN_DURING_EVALUATION.txt" in json.dumps(integrity)


# -- configuration ----------------------------------------------------------


def test_a_valid_contract_validates():
    payload = json.loads(howlproof("validate", str(CLEAN / "howlproof.yaml"), expect=0).stdout)
    assert payload == {
        "valid": True,
        "artifact": "clean-fixture",
        "profiles": ["security", "documentation", "web"],
        "criteria": 2,
    }


def test_a_malformed_contract_is_rejected_with_field_detail(tmp_path):
    path = tmp_path / "howlproof.yaml"
    path.write_text("schema_version: 1\nartifact: fixture\nsurprise: true\n")
    result = howlproof("validate", str(path), expect=EXIT_USAGE)
    payload = json.loads(result.stderr)
    assert payload["error"] == "invalid configuration"
    assert payload["details"][0]["field"] == "surprise"


def test_an_unknown_profile_is_reported_with_the_known_ones(tmp_path):
    result = howlproof(
        "evaluate",
        str(CLEAN),
        "--profile",
        "telepathy",
        "--evidence-root",
        str(tmp_path / "proof"),
        expect=EXIT_USAGE,
    )
    assert "unknown profile" in json.loads(result.stderr)["error"]


# -- reading what was produced ---------------------------------------------


def test_profiles_can_be_listed_and_shown():
    listed = json.loads(howlproof("profiles", expect=0).stdout)
    assert "security" in listed and listed["security"]["evaluators"] > 0
    shown = json.loads(howlproof("profiles", "security", expect=0).stdout)
    assert "secrets.scan" in shown["evaluators"]
    assert "SECURITY" in shown["adversaries"]


def test_doctor_never_claims_a_tool_it_did_not_find():
    payload = json.loads(howlproof("doctor").stdout)
    for name, row in payload["tools"].items():
        assert row["available"] or row["reason"], name


def test_inspect_reverifies_the_bundle(rejected):
    result, root = rejected
    payload = json.loads(howlproof("inspect", str(root), expect=EXIT_REJECT).stdout)
    assert payload["integrity"] == "VERIFIED"
    assert payload["run_id"] == result["run_id"]


def test_inspect_refuses_a_tampered_bundle(rejected, tmp_path):
    _, root = rejected
    import shutil

    copy = tmp_path / "copy"
    shutil.copytree(root, copy)
    bundle = next(copy.glob("hp-*"))
    (bundle / "result.md").write_text("a different report")
    result = howlproof("inspect", str(bundle), expect=EXIT_USAGE)
    assert "integrity mismatch" in json.loads(result.stderr)["error"]


def test_explain_shows_the_deciding_rule_and_its_definition(rejected):
    result, root = rejected
    payload = json.loads(howlproof("explain", str(root), expect=0).stdout)
    assert payload["deciding_rule"] == result["deciding_rule"]
    assert payload["definition"]
    assert payload["rationale"]


def test_report_renders_markdown_and_json(rejected):
    _, root = rejected
    markdown = howlproof("report", str(root), expect=0).stdout
    assert markdown.startswith("# HowlProof result")
    assert "It does not repair the artifact it is judging." in markdown
    payload = json.loads(howlproof("report", str(root), "--format", "json", expect=0).stdout)
    assert payload["verdict"] == "REJECT"


def test_findings_can_be_listed_and_filtered(rejected):
    _, root = rejected
    listed = howlproof("findings", str(root), expect=0).stdout
    assert "HP-SEC-0001" in listed
    high = json.loads(
        howlproof("findings", str(root), "--severity", "HIGH", "--json", expect=0).stdout
    )
    assert high and all(row["severity"] == "HIGH" for row in high)


def test_the_ledger_keeps_identifiers_across_runs(rejected, tmp_path):
    _, root = rejected
    howlproof("evaluate", str(VULNERABLE), "--evidence-root", str(root), expect=EXIT_REJECT)
    rows = json.loads(howlproof("findings", "--ledger", str(root), "--json", expect=0).stdout)
    identifiers = [row["id"] for row in rows]
    assert len(identifiers) == len(set(identifiers))
    assert "HP-SEC-0001" in identifiers


def test_compare_names_what_changed_between_two_runs(rejected, accepted):
    _, rejected_root = rejected
    _, accepted_root = accepted
    payload = json.loads(
        howlproof("compare", str(rejected_root), str(accepted_root), expect=0).stdout
    )
    assert payload["verdict"] == ["REJECT", "CONDITIONALLY_PROVEN"]


# -- reproduction and re-verification ---------------------------------------


def test_a_recorded_reproduction_still_observes_the_defect(rejected):
    _, root = rejected
    payload = json.loads(
        howlproof(
            "reproduce",
            "HP-SEC-0001",
            "--bundle",
            str(root),
            "--target",
            str(VULNERABLE),
            "--json",
            expect=0,
        ).stdout
    )
    assert payload["outcome"] == "CONFIRMED"


def test_a_reproduction_the_replayer_cannot_execute_says_so(rejected):
    _, root = rejected
    findings = json.loads(howlproof("findings", str(root), "--json", expect=0).stdout)
    unreplayable = next(
        f
        for f in findings
        if f["reproduction"]
        and any(step["kind"] == "reevaluate" for step in f["reproduction"]["steps"])
    )
    payload = json.loads(
        howlproof(
            "reproduce",
            unreplayable["id"],
            "--bundle",
            str(root),
            "--target",
            str(VULNERABLE),
            "--json",
        ).stdout
    )
    assert payload["outcome"] == "NOT_SUPPORTED"
    assert "verify-fix" in payload["reason"]


def test_verify_fix_refuses_when_the_artifact_has_not_changed(rejected):
    _, root = rejected
    result = howlproof(
        "verify-fix",
        "HP-SEC-0001",
        "--bundle",
        str(root),
        "--target",
        str(VULNERABLE),
        "--evidence-root",
        str(root),
        expect=EXIT_USAGE,
    )
    message = json.loads(result.stderr)["error"]
    assert "identical" in message
    assert "not evidence" in message


def test_verify_fix_confirms_a_real_repair(rejected, tmp_path):
    import shutil

    _, root = rejected
    repaired = tmp_path / "repaired"
    shutil.copytree(VULNERABLE, repaired)
    config = (repaired / "src" / "config.py").read_text()
    (repaired / "src" / "config.py").write_text(
        config.replace('"ghp_ZmFrZUZpeHR1cmVUb2tlbkZvclRlc3RzMDAx"', 'os.environ["GITHUB_TOKEN"]')
    )
    evidence = tmp_path / "proof"
    shutil.copy(root / "ledger.json", _ensure(evidence) / "ledger.json")
    payload = json.loads(
        howlproof(
            "verify-fix",
            "HP-SEC-0001",
            "--bundle",
            str(root),
            "--target",
            str(repaired),
            "--evidence-root",
            str(evidence),
            "--json",
            expect=0,
        ).stdout
    )
    assert payload["outcome"] == "VERIFIED_FIXED"
    assert payload["still_present"] is False


def test_verify_fix_reports_a_defect_that_is_still_present(rejected, tmp_path):
    import shutil

    _, root = rejected
    unchanged = tmp_path / "cosmetic"
    shutil.copytree(VULNERABLE, unchanged)
    (unchanged / "NOTES.md").write_text("A change that repairs nothing.\n")
    evidence = tmp_path / "proof2"
    shutil.copy(root / "ledger.json", _ensure(evidence) / "ledger.json")
    result = howlproof(
        "verify-fix",
        "HP-SEC-0001",
        "--bundle",
        str(root),
        "--target",
        str(unchanged),
        "--evidence-root",
        str(evidence),
        "--json",
        expect=EXIT_REJECT,
    )
    payload = json.loads(result.stdout)
    assert payload["outcome"] == "RETESTED"
    assert payload["still_present"] is True


# -- accepting a finding ----------------------------------------------------


def test_a_dismissal_without_a_substantial_reason_is_refused(rejected):
    _, root = rejected
    result = howlproof(
        "accept",
        "HP-SEC-0001",
        "--evidence-root",
        str(root),
        "--reason",
        "fine",
        expect=EXIT_USAGE,
    )
    assert "silent dismissal" in json.loads(result.stderr)["error"]


def test_an_accepted_finding_stops_blocking_but_stays_in_the_ledger(rejected, tmp_path):
    import shutil

    _, root = rejected
    evidence = tmp_path / "accepted"
    evidence.mkdir()
    shutil.copy(root / "ledger.json", evidence / "ledger.json")
    payload = json.loads(
        howlproof(
            "accept",
            "HP-SEC-0001",
            "--evidence-root",
            str(evidence),
            "--reason",
            "This credential is authored fixture data and was never valid.",
            expect=0,
        ).stdout
    )
    assert payload["state"] == "ACCEPTED_RISK"

    # The next evaluation carries the decision forward and the finding no longer blocks.
    result = howlproof("evaluate", str(VULNERABLE), "--evidence-root", str(evidence), "--json")
    findings = {f["id"]: f for f in json.loads(result.stdout)["findings"]}
    assert findings["HP-SEC-0001"]["state"] == "ACCEPTED_RISK"
    assert findings["HP-SEC-0001"]["blocking"] is False
    assert findings["HP-SEC-0001"]["resolution_reason"]


def test_accepting_an_unknown_finding_is_a_usage_error(rejected):
    _, root = rejected
    result = howlproof(
        "accept",
        "HP-SEC-9999",
        "--evidence-root",
        str(root),
        "--reason",
        "This identifier does not exist in the ledger at all.",
        expect=EXIT_USAGE,
    )
    assert "unknown finding" in json.loads(result.stderr)["error"]


# -- ecosystem handoffs -----------------------------------------------------


def test_the_plane_handoff_uses_the_ecosystem_finding_schema(rejected):
    import yaml

    _, root = rejected
    document = yaml.safe_load(howlproof("handoff", str(root), "--for", "plane", expect=0).stdout)
    assert document["findings"]
    first = document["findings"][0]
    assert first["schema"] == "ai.review_finding/v1"
    assert first["severity"] in {"blocker", "high", "medium", "low", "informational"}
    assert first["status"] in {
        "open",
        "confirmed",
        "likely",
        "disputed",
        "false_positive",
        "out_of_scope",
        "requires_human_judgment",
    }
    assert first["reviewer_role"].startswith("howlproof-")


def test_the_board_handoff_emits_evidence_ledger_lines(rejected):
    _, root = rejected
    lines = howlproof("handoff", str(root), "--for", "board", expect=0).stdout.splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    assert entries[0]["schema"] == "ai.evidence_entry/v1"
    assert entries[0]["action"] == "verification_executed"
    assert entries[0]["defect_type"] in {"verification_caught_defect", None}


def test_the_relay_handoff_uses_headings_relay_recognises(rejected):
    _, root = rejected
    markdown = howlproof("handoff", str(root), "--for", "relay", expect=0).stdout
    for heading in ("## Known Failures", "## Blockers", "## Next Recommended Action"):
        assert heading in markdown


def test_the_changeops_handoff_states_that_no_ingest_path_exists(rejected):
    _, root = rejected
    markdown = howlproof("handoff", str(root), "--for", "changeops", expect=0).stdout
    assert "no HowlChangeOps ingest path" in markdown


def test_the_verification_plan_preserves_the_original_status(rejected):
    _, root = rejected
    plan = json.loads(
        howlproof("handoff", str(root), "--for", "verification-plan", expect=0).stdout
    )
    assert plan["schema"] == "ai.verification_plan/v1"
    assert plan["overall_status"] in {"unverified", "passed", "failed", "partial"}
    skipped = [step for step in plan["steps"] if step["status"] == "skipped"]
    assert any("[howlproof status" in step["stderr"] for step in skipped)
    assert all("step_id" in step and "required" in step for step in plan["steps"])


def test_an_unknown_handoff_target_is_a_usage_error(rejected):
    _, root = rejected
    assert howlproof("handoff", str(root), "--for", "telepathy").returncode == EXIT_USAGE


def _ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
