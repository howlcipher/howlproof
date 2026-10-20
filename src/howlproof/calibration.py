"""Versioned, synthetic source-fixture calibration with explicit per-rule counts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from howlproof.config import StrictModel, default_config, find_config, read_config
from howlproof.engine import EvaluationError, evaluate
from howlproof.model import digest_bytes
from howlproof.registry import Registry

STATIC_EVALUATORS = Literal["secrets.scan", "ci.supplychain", "markup.escaping", "release.version"]


class CalibrationCase(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,60}$")
    target: str = Field(min_length=1, max_length=300)
    evaluator: STATIC_EVALUATORS
    expected_rules: list[str] = Field(max_length=100)

    @field_validator("target")
    @classmethod
    def relative_target(cls, value: str) -> str:
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("corpus targets must be relative paths inside its directory")
        return value


class Corpus(StrictModel):
    schema_version: Literal[1]
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    cases: list[CalibrationCase] = Field(min_length=2, max_length=200)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema(cls, value: Any) -> Any:
        if type(value) is not int or value != 1:
            raise ValueError("schema_version must be integer 1")
        return value

    @model_validator(mode="after")
    def labelled_pairs(self) -> Corpus:
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("corpus case IDs must be unique")
        for evaluator in {case.evaluator for case in self.cases}:
            labels = {
                bool(case.expected_rules) for case in self.cases if case.evaluator == evaluator
            }
            if labels != {True, False}:
                raise ValueError(f"{evaluator} requires both defective and clean cases")
        return self


def read_corpus(path: Path) -> Corpus:
    if path.stat().st_size > 256_000:
        raise ValueError("corpus exceeds 256000 bytes")
    return Corpus.model_validate(json.loads(path.read_text()))


def score(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Count each labelled rule on each conclusive case for its evaluator.

    Unknown observed rules count as false positives. Inconclusive cases contribute
    no reassuring true negatives and remain explicit in the report.
    """
    result: dict[str, Any] = {}
    for evaluator in sorted({row["evaluator"] for row in rows}):
        cases = [row for row in rows if row["evaluator"] == evaluator]
        rules = {rule for row in cases for rule in row["expected_rules"] + row["observed_rules"]}
        result[evaluator] = {}
        for rule in sorted(rules):
            counts = dict.fromkeys(
                ["true_positive", "false_negative", "false_positive", "true_negative"], 0
            )
            for row in cases:
                if not row["conclusive"]:
                    continue
                expected = rule in row["expected_rules"]
                observed = rule in row["observed_rules"]
                key = (
                    "true_positive"
                    if expected and observed
                    else "false_negative"
                    if expected
                    else "false_positive"
                    if observed
                    else "true_negative"
                )
                counts[key] += 1
            result[evaluator][rule] = counts
    return result


def calibrate(corpus_path: Path, evidence_root: Path, registry: Registry) -> dict[str, Any]:
    corpus_path = corpus_path.resolve()
    corpus_hash = digest_bytes(corpus_path.read_bytes())
    corpus = read_corpus(corpus_path)
    rows = []
    for case in corpus.cases:
        target = (corpus_path.parent / case.target).resolve()
        if corpus_path.parent not in target.parents:
            raise ValueError(f"corpus target escapes its directory: {case.id}")
        if not target.is_dir():
            raise ValueError(f"corpus target is not a directory: {case.id}")
        source = find_config(target)
        config = read_config(source) if source else default_config(target.name, [case.evaluator])
        config = config.model_copy(
            update={
                "profiles": [case.evaluator],
                "acceptance": [],
                "exclusions": [],
                "service": None,
                "adversaries": [registry.get(case.evaluator).adversary],
            }
        )
        try:
            result = evaluate(
                target,
                config,
                registry,
                evidence_root,
                config_source=f"corpus {corpus.name}: {case.id}",
            )
        except EvaluationError as error:
            raise ValueError(f"cannot evaluate corpus case {case.id}: {error}") from error
        observed = sorted({finding["rule"] for finding in result["findings"]})
        conclusive = (
            bool(result["checks"])
            and all(check["status"] in {"VERIFIED", "FAILED"} for check in result["checks"])
            and result["target"]["tree_digest_before"] == result["target"]["tree_digest_after"]
        )
        rows.append(
            {
                "id": case.id,
                "evaluator": case.evaluator,
                "expected_rules": sorted(set(case.expected_rules)),
                "observed_rules": observed,
                "conclusive": conclusive,
                "matched": conclusive and set(observed) == set(case.expected_rules),
                "bundle": result["path"],
                "tree_digest": result["target"]["tree_digest_before"],
                "implementation_hash": result["manifest"]["implementation_hash"],
                "checks": result["checks"],
            }
        )
    if digest_bytes(corpus_path.read_bytes()) != corpus_hash:
        raise ValueError("the corpus labels changed during calibration")
    return {
        "schema": "howlproof.calibration/v1",
        "corpus": corpus.name,
        "corpus_hash": corpus_hash,
        "passed": all(row["matched"] for row in rows),
        "inconclusive_cases": sum(not row["conclusive"] for row in rows),
        "cases": rows,
        "by_evaluator": score(rows),
        "limitation": "synthetic labelled fixtures only; these counts do not estimate "
        "accuracy on arbitrary artifacts or cover evaluators absent from this corpus",
    }
