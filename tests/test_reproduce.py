"""A claimed fix requires a successful rerun of the original check."""

import pytest

from howlproof.config import ProofConfig
from howlproof.model import FindingState
from howlproof.registry import Registry
from howlproof.reproduce import verify_fix


@pytest.mark.parametrize(
    "checks,mutated",
    [
        ([], False),
        ([{"check_id": "secrets.scan", "status": "FAILED"}], False),
        ([{"check_id": "secrets.scanner", "status": "VERIFIED"}], False),
        ([{"check_id": "secrets.scan.other", "status": "VERIFIED"}], False),
        ([{"check_id": "secrets.scan", "status": "VERIFIED"}], True),
    ],
)
def test_fix_cannot_be_verified_without_valid_original_check(
    tmp_path, monkeypatch, checks, mutated
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "file.txt").write_text("changed")
    config = ProofConfig(schema_version=1, artifact="fixture")
    registry = Registry()
    monkeypatch.setattr("howlproof.reproduce.registry_has", lambda *_: True)
    monkeypatch.setattr(
        "howlproof.engine.evaluate",
        lambda **_: {
            "run_id": "new-run",
            "path": "proof",
            "findings": [],
            "checks": checks,
            "target": {
                "tree_digest_before": "new",
                "tree_digest_after": "other" if mutated else "new",
            },
        },
    )
    result = verify_fix(
        {
            "id": "HP-SEC-0001",
            "check_id": "secrets.scan",
            "fingerprint": "old",
            "adversary": "SECURITY",
        },
        "old-digest",
        target,
        config,
        registry,
        tmp_path / "proof",
    )
    assert result.outcome == FindingState.RETESTED.value


def secret_bundle(tmp_path):
    from howlproof.config import read_config
    from howlproof.engine import evaluate
    from howlproof.evaluators import build_registry

    target = tmp_path / "artifact"
    target.mkdir()
    (target / "howlproof.yaml").write_text(
        "schema_version: 1\nartifact: fixture\nprofiles: [secrets.scan]\n"
    )
    (target / "config.py").write_text("value = '" + "ghp_" + "A" * 40 + "'\n")
    result = evaluate(
        target,
        read_config(target / "howlproof.yaml"),
        build_registry(),
        tmp_path / "original-proof",
    )
    return target, result


def test_verify_cli_refuses_unchanged_target_without_original_ledger(tmp_path, capsys):
    import json

    from howlproof.cli import main

    target, bundle = secret_bundle(tmp_path)
    code = main(
        [
            "verify-fix",
            bundle["findings"][0]["id"],
            "--bundle",
            bundle["path"],
            "--target",
            str(target),
            "--evidence-root",
            str(tmp_path / "fresh-proof"),
        ]
    )
    assert code == 2
    assert "identical" in json.loads(capsys.readouterr().err)["error"]


def test_verify_cli_refuses_a_different_artifact_identity(tmp_path, capsys):
    import json

    from howlproof.cli import main

    _, bundle = secret_bundle(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "howlproof.yaml").write_text(
        "schema_version: 1\nartifact: other\nprofiles: [secrets.scan]\n"
    )
    code = main(
        [
            "verify-fix",
            bundle["findings"][0]["id"],
            "--bundle",
            bundle["path"],
            "--target",
            str(other),
            "--evidence-root",
            str(tmp_path / "fresh-proof"),
        ]
    )
    assert code == 2
    assert "artifact" in json.loads(capsys.readouterr().err)["error"]


def test_replay_cannot_confirm_evidence_after_mutating_the_original(tmp_path):
    import sys

    from howlproof.reproduce import NOT_SUPPORTED, replay

    root = tmp_path / "artifact"
    root.mkdir()
    original = root / "file.txt"
    original.write_text("before")
    command = "from pathlib import Path; " + f"Path({str(original)!r}).write_text('after')"
    finding = {
        "reproduction": {
            "steps": [
                {
                    "kind": "command",
                    "description": "unauthorized original mutation",
                    "payload": {
                        "argv": [
                            sys.executable,
                            "-c",
                            command,
                        ]
                    },
                    "expect": {"exit_code": 0},
                }
            ]
        }
    }
    result = replay(finding, root, ProofConfig(schema_version=1, artifact="fixture"))
    assert result.outcome == NOT_SUPPORTED
    assert "changed" in result.reason


def test_imported_bundle_cannot_close_an_unrelated_ledger_finding(tmp_path, capsys):
    import json

    from howlproof.cli import main
    from howlproof.ledger import Ledger
    from howlproof.model import Adversary, Confidence, Finding, Severity

    target, bundle = secret_bundle(tmp_path)
    (target / "config.py").write_text("value = None\n")
    evidence = tmp_path / "new-root"
    ledger = Ledger.open(evidence)
    unrelated = ledger.assign(
        "fixture",
        Finding(
            check_id="secrets.scan",
            adversary=Adversary.SECURITY,
            category="security",
            title="Unrelated observation",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="A different fingerprint",
            evidence="fixture observation",
            rule="unrelated",
            recommended_remediation="Investigate independently",
        ),
        "other-run",
        "sha",
    )
    assert unrelated.id == bundle["findings"][0]["id"]
    code = main(
        [
            "verify-fix",
            bundle["findings"][0]["id"],
            "--bundle",
            bundle["path"],
            "--target",
            str(target),
            "--evidence-root",
            str(evidence),
            "--json",
        ]
    )
    assert code == 0
    assert not json.loads(capsys.readouterr().out)["lifecycle_recorded"]
    assert Ledger.open(evidence).get("fixture", unrelated.id)["state"] == "FOUND"


def test_verify_api_requires_an_original_tree_digest(tmp_path):
    from howlproof.reproduce import FixRefused

    with pytest.raises(FixRefused, match="digest"):
        verify_fix(
            {},
            "",
            tmp_path,
            ProofConfig(schema_version=1, artifact="fixture"),
            Registry(),
            tmp_path / "proof",
        )
