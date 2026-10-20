"""Create an operator-owned contract without inventing acceptance requirements."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from howlproof.config import CONFIG_NAMES, ProofConfig
from howlproof.evaluators import build_registry
from howlproof.registry import select


def artifact_name(target: Path) -> str:
    """Make a valid default identity; operators can supply a stable explicit one."""
    return re.sub(r"[^A-Za-z0-9_-]+", "-", target.resolve().name).strip("-_")[:64] or "artifact"


def initialize(
    target: Path, profiles: list[str], required_checks: list[str], artifact: str | None = None
) -> dict[str, Any]:
    target = target.resolve()
    if not target.is_dir():
        raise ValueError("init target must be an existing directory")
    for name in CONFIG_NAMES:
        candidate = target / name
        if candidate.exists() or candidate.is_symlink():
            raise ValueError(f"refusing to overwrite an existing contract: {candidate}")
    profiles = list(dict.fromkeys(profiles or ["secrets.scan"]))
    required_checks = list(dict.fromkeys(required_checks))
    document: dict[str, Any] = {
        "schema_version": 1,
        "artifact": artifact if artifact is not None else artifact_name(target),
        "description": "Operator starter contract. Review scope and acceptance before use.",
        "profiles": profiles,
        "acceptance": (
            [{"id": "AC-01", "requirement": "checks_pass", "checks": required_checks}]
            if required_checks
            else []
        ),
    }
    config = ProofConfig.model_validate(document)
    selected = {e.id for e in select(build_registry(), config.profiles, config.adversaries)}
    unknown = set(required_checks) - selected
    if unknown:
        raise ValueError(
            "required checks must be selected evaluator IDs: " + ", ".join(sorted(unknown))
        )
    content = "# Review this scope; no acceptance requirements are inferred.\n" + yaml.safe_dump(
        document, sort_keys=False, allow_unicode=True
    )
    destination = target / "howlproof.yaml"
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {
        "written": str(destination),
        "artifact": config.artifact,
        "profiles": profiles,
        "required_checks": required_checks,
        "requires_acceptance_review": not bool(required_checks),
        "note": "Scope and requirements are operator-owned; init does not evaluate the artifact.",
    }
