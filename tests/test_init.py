"""A first contract is explicit, valid and never overwrites operator state."""

import json
import os

import pytest

from howlproof.cli import main
from howlproof.config import read_config


def test_init_creates_a_valid_draft_without_inventing_acceptance(tmp_path, capsys):
    target = tmp_path / "My project (demo)"
    target.mkdir()
    assert main(["init", str(target)]) == 0
    info = json.loads(capsys.readouterr().out)
    config = read_config(target / "howlproof.yaml")
    assert config.artifact == "My-project-demo"
    assert config.profiles == ["secrets.scan"]
    assert not config.acceptance
    if os.name == "posix":
        assert (target / "howlproof.yaml").stat().st_mode & 0o777 == 0o600
    assert info["requires_acceptance_review"] is True
    assert (
        main(["evaluate", str(target), "--evidence-root", str(tmp_path / "evidence"), "--json"])
        == 40
    )


def test_init_requires_only_explicitly_named_selected_checks(tmp_path):
    assert (
        main(
            [
                "init",
                str(tmp_path),
                "--profile",
                "secrets.scan",
                "--require-check",
                "secrets.scan",
                "--artifact",
                "my-service",
            ]
        )
        == 0
    )
    config = read_config(tmp_path / "howlproof.yaml")
    assert config.artifact == "my-service"
    assert config.acceptance[0].checks == ["secrets.scan"]
    assert (
        main(
            [
                "evaluate",
                str(tmp_path),
                "--evidence-root",
                str(tmp_path.parent / "proof-init"),
                "--json",
            ]
        )
        == 0
    )


@pytest.mark.parametrize("name", ["howlproof.yaml", "howlproof.yml", ".howlproof.yaml"])
def test_init_preserves_every_existing_contract_name(tmp_path, name):
    existing = tmp_path / name
    existing.write_text("operator-owned")
    assert main(["init", str(tmp_path)]) == 2
    assert existing.read_text() == "operator-owned"
    assert not (tmp_path / "howlproof.yaml").exists() or name == "howlproof.yaml"


def test_init_rejects_unknown_profiles_and_unselected_checks_without_writing(tmp_path):
    assert main(["init", str(tmp_path), "--profile", "no-such-profile"]) == 2
    assert main(["init", str(tmp_path), "--require-check", "python.tests"]) == 2
    assert not (tmp_path / "howlproof.yaml").exists()


def test_init_does_not_follow_a_dangling_contract_link(tmp_path):
    link = tmp_path / "howlproof.yaml"
    destination = tmp_path / "elsewhere"
    link.symlink_to(destination)
    assert main(["init", str(tmp_path)]) == 2
    assert link.is_symlink()
    assert not destination.exists()


def test_bare_artifact_name_with_spaces_can_be_evaluated(tmp_path):
    target = tmp_path / "No contract here!"
    target.mkdir()
    (target / "README.md").write_text("A bare artifact")
    assert (
        main(
            [
                "evaluate",
                str(target),
                "--profile",
                "secrets.scan",
                "--evidence-root",
                str(tmp_path / "proof"),
                "--json",
            ]
        )
        == 40
    )


def test_invalid_identity_and_missing_target_leave_no_contract(tmp_path):
    assert main(["init", str(tmp_path), "--artifact", "invalid identity!"]) == 2
    assert not (tmp_path / "howlproof.yaml").exists()
    assert main(["init", str(tmp_path / "missing")]) == 2
    assert not (tmp_path / "missing").exists()
