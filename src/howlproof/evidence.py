"""Evidence bundles: private by default, integrity indexed, and honest about redaction.

A bundle is the artifact a verdict rests on. If it cannot be re-read and checked,
the verdict is an assertion rather than a finding.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from howlproof import __version__
from howlproof.model import digest, digest_bytes

RUN_SCHEMA = "howlproof.run/v1"
RESULT_SCHEMA = "howlproof.result/v1"
HANDOFF_SCHEMA = "howlproof.handoff/v1"

#: HowlProof issues verdicts. It never executes, promotes or approves anything.
AUTHORITY = "ADVISORY"

#: Files every complete bundle must carry, checked on load.
REQUIRED_FILES = frozenset(
    {
        "target.json",
        "environment.json",
        "checks.jsonl",
        "result.json",
        "result.md",
        "handoff.json",
        "config.json",
    }
)

SECRET_PATTERNS = (
    r"sk-[A-Za-z0-9_-]{12,}",
    r"gh[pousr]_[A-Za-z0-9_]{12,}",
    r"github_pat_[A-Za-z0-9_]+",
    r"AKIA[0-9A-Z]{16}",
    r"(?i)(?:authorization[\"']?\s*[:=]\s*[\"']?)(?:bearer\s+)?[^\s,\"'}]+",
    r"(?i)(?:password|api_key|secret_key|token)[\"']?\s*[:=]\s*[\"']?[^\s,\"'}]+",
    r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
)

SECRET_KEYS = frozenset({"authorization", "api_key", "password", "token", "access_token", "secret"})


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def scrub(value: Any) -> Any:
    """Best-effort redaction. It reduces exposure; it does not guarantee absence."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            scrub(key): "[REDACTED]" if str(key).lower() in SECRET_KEYS else scrub(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def new_run_id() -> str:
    return f"hp-{datetime.now(UTC):%Y%m%d-%H%M%S}-{uuid4().hex[:12]}"


def implementation_hash() -> str:
    """Bind evidence to the evaluator that produced it."""
    source = Path(__file__).parent
    parts = sorted(source.rglob("*.py"))
    return digest("".join(str(p.relative_to(source)) + p.read_text() for p in parts))


class BundleError(ValueError):
    """The bundle is missing, incomplete, or does not match its own integrity index."""


class Bundle:
    """Writer and reader for one evaluation's evidence directory."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id

    # -- creation ---------------------------------------------------------

    @classmethod
    def create(cls, evidence_root: Path, target_root: Path, allow_inside: bool = False) -> Bundle:
        evidence_root = evidence_root.resolve()
        target_root = target_root.resolve()
        if not allow_inside and (
            evidence_root == target_root or target_root in evidence_root.parents
        ):
            raise BundleError(
                "refusing to write evidence inside the artifact under evaluation; "
                "choose --evidence-root outside the target or pass --allow-evidence-in-target"
            )
        run_id = new_run_id()
        path = evidence_root / run_id
        path.mkdir(parents=True)
        for sub in ("findings", "reproductions", "evidence"):
            (path / sub).mkdir()
        return cls(path, run_id)

    # -- writing ----------------------------------------------------------

    def write_json(self, name: str, value: Any) -> None:
        target = self._safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(scrub(value), indent=2, ensure_ascii=False) + "\n")
        target.chmod(0o600)

    def write_text(self, name: str, value: str) -> None:
        target = self._safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(redact(value))
        target.chmod(0o600)

    def write_bytes(self, name: str, value: bytes) -> None:
        target = self._safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        target.chmod(0o600)

    def write_jsonl(self, name: str, rows: list[Any]) -> None:
        target = self._safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "".join(json.dumps(scrub(row), ensure_ascii=False) + "\n" for row in rows)
        )
        target.chmod(0o600)

    def evidence_ref(self, check_id: str, name: str) -> str:
        return f"evidence/{check_id}/{name}"

    def _safe(self, name: str) -> Path:
        candidate = (self.path / name).resolve()
        if self.path not in candidate.parents:
            raise BundleError(f"evidence path escapes the bundle: {name}")
        return candidate

    # -- sealing ----------------------------------------------------------

    def seal(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Write the manifest last, carrying a digest of everything else in the bundle."""
        manifest = {
            "schema": RUN_SCHEMA,
            "run_id": self.run_id,
            "authority": AUTHORITY,
            "version": __version__,
            "implementation_hash": implementation_hash(),
            **manifest,
        }
        # Hash bytes, not decoded text: a screenshot is evidence too, and decoding it
        # with replacement characters would make two different images hash alike.
        manifest["file_hashes"] = {
            str(p.relative_to(self.path)): digest_bytes(p.read_bytes())
            for p in sorted(self.path.rglob("*"))
            if p.is_file() and p.name != "manifest.json"
        }
        self.write_json("manifest.json", manifest)
        return manifest

    # -- reading ----------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> dict[str, Any]:
        """Re-read a bundle and prove it still matches its own integrity index."""
        path = path.resolve()
        manifest_path = path / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise BundleError(f"no readable manifest at {path}")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("schema") != RUN_SCHEMA:
            raise BundleError(f"unsupported bundle schema: {manifest.get('schema')!r}")
        if manifest.get("authority") != AUTHORITY:
            raise BundleError("invalid bundle authority: HowlProof evidence is ADVISORY only")
        hashes = manifest.get("file_hashes") or {}
        missing = REQUIRED_FILES - set(hashes)
        if missing:
            raise BundleError(f"bundle integrity index is incomplete: {sorted(missing)}")
        for name, expected in hashes.items():
            candidate = (path / name).resolve()
            if path not in candidate.parents or candidate.is_symlink():
                raise BundleError(f"invalid bundle path: {name}")
            if not candidate.is_file():
                raise BundleError(f"bundle integrity mismatch: {name} is missing")
            if digest_bytes(candidate.read_bytes()) != expected:
                raise BundleError(f"bundle integrity mismatch: {name}")
        result = {
            "manifest": manifest,
            "path": str(path),
            "result": json.loads((path / "result.json").read_text()),
            "target": json.loads((path / "target.json").read_text()),
            "environment": json.loads((path / "environment.json").read_text()),
            "config": json.loads((path / "config.json").read_text()),
            "handoff": json.loads((path / "handoff.json").read_text()),
            "checks": [
                json.loads(line)
                for line in (path / "checks.jsonl").read_text().splitlines()
                if line.strip()
            ],
            "findings": [
                json.loads(p.read_text()) for p in sorted((path / "findings").glob("*.json"))
            ],
        }
        return result


def find_bundle(root: Path, run_id: str | None = None) -> Path:
    """Resolve a bundle directory, defaulting to the newest under an evidence root."""
    root = root.resolve()
    if (root / "manifest.json").is_file():
        return root
    if run_id:
        candidate = root / run_id
        if (candidate / "manifest.json").is_file():
            return candidate
        raise BundleError(f"no bundle {run_id} under {root}")
    bundles = sorted(p for p in root.glob("hp-*") if (p / "manifest.json").is_file())
    if not bundles:
        raise BundleError(f"no bundles under {root}")
    return bundles[-1]


def environment_probe(tools: dict[str, list[str]]) -> dict[str, Any]:
    """Record what was actually available. An unavailable tool is never reported as a pass."""
    import shutil
    import subprocess

    probed: dict[str, Any] = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "platform": os.uname().sysname if hasattr(os, "uname") else "unknown",
        "tools": {},
    }
    for name, argv in tools.items():
        path = shutil.which(argv[0])
        if path is None:
            probed["tools"][name] = {"available": False, "reason": f"{argv[0]} is not on PATH"}
            continue
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, check=False, timeout=30
            )
            version = (completed.stdout or completed.stderr).strip().splitlines()
            probed["tools"][name] = {
                "available": completed.returncode == 0,
                "path": path,
                "version": version[0][:200] if version else "",
                "reason": ""
                if completed.returncode == 0
                else f"{argv[0]} exited {completed.returncode}",
            }
        except (OSError, subprocess.SubprocessError) as error:
            probed["tools"][name] = {
                "available": False,
                "path": path,
                "reason": f"probe failed: {type(error).__name__}",
            }
    return probed
