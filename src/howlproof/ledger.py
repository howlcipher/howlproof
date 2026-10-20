"""Cross-run finding identity and lifecycle.

A finding needs one identity that survives re-runs, rebases and line shifts, or the
question "is this the same defect we saw last week?" has no answer. Identity comes
from a fingerprint; the readable HP-SEC-0041 number is assigned once and kept.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from howlproof.model import ADVERSARY_CODE, Finding, FindingState

LEDGER_SCHEMA = "howlproof.ledger/v1"
LEDGER_NAME = "ledger.json"
LOCK_TIMEOUT = 10.0


class LedgerError(ValueError):
    """The ledger is unreadable or was written by an incompatible version."""


class Ledger:
    """Durable record of every finding this evaluator has ever raised about an artifact."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        self.path = path
        self.data = data

    @classmethod
    def open(cls, evidence_root: Path) -> Ledger:
        path = evidence_root.resolve() / LEDGER_NAME
        if path.is_symlink():
            raise LedgerError("ledger must not be a symlink")
        if not path.is_file():
            return cls(path, {"schema": LEDGER_SCHEMA, "artifacts": {}})
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as error:
            raise LedgerError("ledger is not readable JSON") from error
        if not isinstance(data, dict):
            raise LedgerError("ledger must be an object")
        if data.get("schema") != LEDGER_SCHEMA:
            raise LedgerError(f"unsupported ledger schema: {data.get('schema')!r}")
        if not isinstance(data.get("artifacts"), dict):
            raise LedgerError("ledger artifacts must be an object")
        return cls(path, data)

    @contextmanager
    def _update(self) -> Iterator[None]:
        """Serialize reload, mutation and replacement on local POSIX filesystems."""
        if os.name != "posix":
            raise LedgerError("ledger writes require POSIX file locking")
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(".lock")
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError as error:
            raise LedgerError("cannot safely open the ledger lock") from error
        with os.fdopen(descriptor, "a") as lock:
            deadline = time.monotonic() + LOCK_TIMEOUT
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise LedgerError("timed out waiting for the ledger lock") from error
                    time.sleep(0.05)
            self.data = self.open(self.path.parent).data
            yield
            self._write_atomic()

    def _write_atomic(self) -> None:
        descriptor, name = tempfile.mkstemp(prefix=".ledger-", dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(self.data, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self) -> None:
        """Compatibility flush; mutations are already committed under the lock.

        Never write this instance's snapshot over another writer's updates.
        """
        with self._update():
            pass

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
        with self._update():
            return self._assign(artifact, finding, run_id, commit, tree_digest)

    def _assign(
        self, artifact: str, finding: Finding, run_id: str, commit: str, tree_digest: str
    ) -> Finding:
        record = self._artifact(artifact)
        known = record["findings"].get(finding.fingerprint)
        if known is None:
            code = ADVERSARY_CODE[finding.adversary]
            number = (
                max(
                    (
                        row.get("counters", {}).get(code, 0)
                        for row in self.data["artifacts"].values()
                    ),
                    default=0,
                )
                + 1
            )
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
        with self._update():
            return self._record_state(artifact, finding_id, state, run_id, note)

    def _record_state(
        self, artifact: str, finding_id: str, state: FindingState, run_id: str, note: str
    ) -> dict[str, Any]:
        if state in {FindingState.ACCEPTED_RISK, FindingState.WONT_FIX} and not note.strip():
            raise LedgerError("dismissing a finding requires an explicit resolution reason")
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
        matches = [
            (artifact, {"fingerprint": fingerprint, **known})
            for artifact, record in self.data["artifacts"].items()
            for fingerprint, known in record.get("findings", {}).items()
            if known["id"] == finding_id
        ]
        if len(matches) > 1:
            raise LedgerError(f"ambiguous legacy finding identifier: {finding_id}")
        if matches:
            return matches[0]
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
