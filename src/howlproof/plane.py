"""Bounded ingestion into Plane's existing reconciliation CLI; never promotion."""

from __future__ import annotations

import json
import math
import os
import subprocess
from pathlib import Path
from typing import Any

from howlproof.handoff import render
from howlproof.model import EXIT_CODES, Verdict
from howlproof.process import stop


def ingest(
    result: dict[str, Any], run_dir: Path, *, executable: str = "howlplane", timeout: float = 120
) -> dict[str, Any]:
    """Persist an advisory handoff in a fresh directory and reconcile it in Plane."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite positive number")
    proof_exit = EXIT_CODES[Verdict(result["verdict"])]
    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    record = {
        "schema": "howlproof.plane_ingestion/v1",
        "authority": "ADVISORY",
        "run_id": result["run_id"],
        "verdict": result["verdict"],
        "proof_exit_code": proof_exit,
        "status": "ERROR",
    }
    process = None
    try:
        (run_dir / "proof-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        _, content = render(result, "plane")
        handoff = run_dir / "findings.yaml"
        handoff.write_text(content, encoding="utf-8")
        handoff.chmod(0o600)
        command = [
            executable,
            "reconcile",
            "--findings-file",
            str(handoff),
            "--output",
            str(run_dir / "reconciliation.md"),
        ]
        record["command"] = command
        # File-backed output prevents an unexpectedly verbose tool exhausting memory.
        with (
            (run_dir / "stdout.txt").open("w") as stdout,
            (run_dir / "stderr.txt").open("w") as stderr,
        ):
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    cwd=run_dir,
                    start_new_session=True,
                    text=True,
                )
            except OSError as error:
                raise ValueError(f"Plane could not start: {error}") from None
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise ValueError(f"Plane timed out after {timeout}s") from None
        record["plane_exit_code"] = code
        if code not in (0, 1):
            raise ValueError(f"Plane reconciliation failed with exit {code}")
        if not (run_dir / "reconciliation.md").is_file():
            raise ValueError("Plane returned without a reconciliation report")
        record.update(status="RECONCILED", exit_code=proof_exit or code)
        return record
    except (ValueError, OSError) as error:
        record["error"] = str(error)
        raise
    finally:
        if process is not None:
            stop(process)
        (run_dir / "plane-ingestion.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
        if os.name == "posix":
            for path in run_dir.iterdir():
                if path.is_file():
                    path.chmod(0o600)
