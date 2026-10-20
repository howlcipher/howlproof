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
