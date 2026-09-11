"""Cross-run finding identity and lifecycle.

A finding needs one identity that survives re-runs, rebases and line shifts, or the
question "is this the same defect we saw last week?" has no answer. Identity comes
from a fingerprint; the readable HP-SEC-0041 number is assigned once and kept.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from howlproof.model import ADVERSARY_CODE, Finding, FindingState

LEDGER_SCHEMA = "howlproof.ledger/v1"
LEDGER_NAME = "ledger.json"


class LedgerError(ValueError):
    """The ledger is unreadable or was written by an incompatible version."""


class Ledger:
    """Durable record of every finding this evaluator has ever raised about an artifact."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        self.path = path
        self.data = data

    @classmethod
    def open(cls, evidence_root: Path) -> Ledger:
        path = (evidence_root / LEDGER_NAME).resolve()
        if path.is_symlink():
            raise LedgerError("ledger must not be a symlink")
        if not path.is_file():
            return cls(path, {"schema": LEDGER_SCHEMA, "artifacts": {}})
        data = json.loads(path.read_text())
        if data.get("schema") != LEDGER_SCHEMA:
            raise LedgerError(f"unsupported ledger schema: {data.get('schema')!r}")
        return cls(path, data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")

    # -- identity ---------------------------------------------------------

    def _artifact(self, artifact: str) -> dict[str, Any]:
        return self.data["artifacts"].setdefault(artifact, {"counters": {}, "findings": {}})

    def assign(
        self,
        artifact: str,
        finding: Finding,
        run_id: str,
        commit: str,
        tree_digest: str = "",
    ) -> Finding:
        """Give a finding its durable identifier and carry forward what is already known."""
        record = self._artifact(artifact)
        known = record["findings"].get(finding.fingerprint)
        if known is None:
            code = ADVERSARY_CODE[finding.adversary]
            number = record["counters"].get(code, 0) + 1
            record["counters"][code] = number
            finding.id = f"HP-{code}-{number:04d}"
            finding.first_seen_run = run_id
            finding.first_seen_commit = commit
            record["findings"][finding.fingerprint] = {
                "id": finding.id,
                "title": finding.title,
                "adversary": finding.adversary.value,
                "severity": finding.severity.value,
                "state": finding.state.value,
                "first_seen_run": run_id,
                "first_seen_commit": commit,
                "first_seen_tree_digest": tree_digest,
                "last_seen_run": run_id,
                "last_seen_tree_digest": tree_digest,
                "history": [_event(run_id, finding.state, "first observed")],
            }
        else:
            finding.id = known["id"]
            finding.first_seen_run = known["first_seen_run"]
            finding.first_seen_commit = known.get("first_seen_commit", "")
            if known.get("state") == FindingState.VERIFIED_FIXED.value:
                finding.state = FindingState.REGRESSED
                known["history"].append(
                    _event(run_id, FindingState.REGRESSED, "reappeared after a verified fix")
                )
            elif known.get("state") in {
                FindingState.ACCEPTED_RISK.value,
                FindingState.WONT_FIX.value,
            }:
                finding.state = FindingState(known["state"])
                finding.resolution_reason = known.get("resolution_reason")
            known["state"] = finding.state.value
            known["last_seen_run"] = run_id
            known["last_seen_tree_digest"] = tree_digest
            known["severity"] = finding.severity.value
        finding.last_seen_run = run_id
        return finding

    def record_state(
        self, artifact: str, finding_id: str, state: FindingState, run_id: str, note: str
    ) -> dict[str, Any]:
        """Move a finding through its lifecycle, keeping the reason attached to the move."""
        record = self._artifact(artifact)
        for fingerprint, known in record["findings"].items():
            if known["id"] == finding_id:
                known["state"] = state.value
                known.setdefault("history", []).append(_event(run_id, state, note))
                if state in {FindingState.ACCEPTED_RISK, FindingState.WONT_FIX}:
                    known["resolution_reason"] = note
                return {"fingerprint": fingerprint, **known}
        raise LedgerError(f"unknown finding: {finding_id}")

    def get(self, artifact: str, finding_id: str) -> dict[str, Any]:
        record = self._artifact(artifact)
        for fingerprint, known in record["findings"].items():
            if known["id"] == finding_id:
                return {"fingerprint": fingerprint, **known}
        raise LedgerError(f"unknown finding: {finding_id}")

    def find_anywhere(self, finding_id: str) -> tuple[str, dict[str, Any]]:
        for artifact, record in self.data["artifacts"].items():
            for fingerprint, known in record.get("findings", {}).items():
                if known["id"] == finding_id:
                    return artifact, {"fingerprint": fingerprint, **known}
        raise LedgerError(f"unknown finding: {finding_id}")

    def fixed_fingerprints(self, artifact: str) -> set[str]:
        """Findings a previous evaluation proved fixed. Their return is a regression."""
        record = self._artifact(artifact)
        return {
            fingerprint
            for fingerprint, known in record["findings"].items()
            if known.get("state") == FindingState.VERIFIED_FIXED.value
        }

    def entries(self, artifact: str | None = None) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for name, record in sorted(self.data["artifacts"].items()):
            if artifact and name != artifact:
                continue
            for fingerprint, known in record.get("findings", {}).items():
                rows.append({"artifact": name, "fingerprint": fingerprint, **known})
        return sorted(rows, key=lambda row: row["id"])


def _event(run_id: str, state: FindingState, note: str) -> dict[str, str]:
    return {
        "run_id": run_id,
        "state": state.value,
        "note": note,
        "at": datetime.now(UTC).isoformat(),
    }
