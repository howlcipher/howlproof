"""Calibration reports labelled misses, false positives and unavailable coverage."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from howlproof.calibration import calibrate, read_corpus, score
from howlproof.evaluators import build_registry

ROOT = Path(__file__).resolve().parents[1]


def test_scoring_keeps_false_positives_and_missed_defects():
    rows = [
        {
            "evaluator": "fixture.check",
            "expected_rules": ["a"],
            "observed_rules": [],
            "conclusive": True,
        },
        {
            "evaluator": "fixture.check",
            "expected_rules": [],
            "observed_rules": ["a"],
            "conclusive": True,
        },
        {
            "evaluator": "fixture.check",
            "expected_rules": [],
            "observed_rules": [],
            "conclusive": False,
        },
    ]
    result = score(rows)["fixture.check"]["a"]
    assert result == {
        "true_positive": 0,
        "false_negative": 1,
        "false_positive": 1,
        "true_negative": 0,
    }


def test_repository_corpus_matches_its_labels(tmp_path):
    report = calibrate(ROOT / "calibration.json", tmp_path / "proof", build_registry())
    assert report["passed"]
    assert len(report["cases"]) == 10
    assert len(report["by_evaluator"]) == 4
    assert all(row["conclusive"] and row["matched"] for row in report["cases"])
    assert report["corpus_hash"]
    assert "synthetic" in report["limitation"]


@pytest.mark.parametrize(
    "change",
    [
        {"extra": True},
        {"schema_version": 2},
        {
            "cases": [
                {
                    "id": "x",
                    "target": "../outside",
                    "evaluator": "secrets.scan",
                    "expected_rules": [],
                }
            ]
        },
    ],
)
def test_invalid_corpus_is_refused(tmp_path, change):
    manifest = {"schema_version": 1, "name": "fixture", "cases": []}
    manifest.update(change)
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises((ValueError, ValidationError)):
        read_corpus(path)


def paired_manifest(tmp_path):
    for name in ("bad", "good"):
        (tmp_path / name).mkdir()
    manifest = {
        "schema_version": 1,
        "name": "fixture",
        "cases": [
            {
                "id": "bad",
                "target": "bad",
                "evaluator": "secrets.scan",
                "expected_rules": ["secrets.github_token"],
            },
            {"id": "good", "target": "good", "evaluator": "secrets.scan", "expected_rules": []},
        ],
    }
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(manifest))
    return path, manifest


@pytest.mark.parametrize("version", [True, 1.0])
def test_corpus_version_does_not_accept_bool_or_float(tmp_path, version):
    path, data = paired_manifest(tmp_path)
    data["schema_version"] = version
    path.write_text(json.dumps(data))
    with pytest.raises(ValidationError):
        read_corpus(path)


def test_unavailable_cases_cannot_count_as_true_negatives(tmp_path):
    from howlproof.model import Adversary
    from howlproof.registry import Evaluator, Outcome, Registry

    class Unavailable(Evaluator):
        id = "secrets.scan"
        adversary = Adversary.SECURITY

        def evaluate(self, context):
            return Outcome(checks=[self.unavailable("fixture tool cannot run")])

    path, _ = paired_manifest(tmp_path)
    registry = Registry()
    registry.register(Unavailable())
    result = calibrate(path, tmp_path / "proof", registry)
    assert not result["passed"]
    assert result["inconclusive_cases"] == 2
    counts = result["by_evaluator"]["secrets.scan"]["secrets.github_token"]
    assert sum(counts.values()) == 0


def test_corpus_symlink_target_cannot_escape_its_directory(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    path, _ = paired_manifest(corpus_dir)
    (corpus_dir / "bad").rmdir()
    (corpus_dir / "bad").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        calibrate(path, tmp_path / "proof", build_registry())


def test_missing_corpus_target_is_a_usage_error(tmp_path):
    path, _ = paired_manifest(tmp_path)
    (tmp_path / "bad").rmdir()
    with pytest.raises(ValueError, match="directory"):
        calibrate(path, tmp_path / "proof", build_registry())
