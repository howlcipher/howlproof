"""Detached SSH signatures authenticate manifests under explicit local trust policy.

Signing is optional. It never widens evidence coverage, proves evaluator correctness,
or grants promotion authority. Signature files live outside the sealed bundle.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from howlproof.evidence import Bundle, BundleError

NAMESPACE = "howlproof-evidence"


class SignatureError(ValueError):
    """Signing or explicit-trust verification could not be established."""


def _manifest(bundle: Path) -> tuple[bytes, dict[str, Any]]:
    before = (bundle / "manifest.json").read_bytes()
    loaded = Bundle.load(bundle)
    if before != (bundle / "manifest.json").read_bytes():
        raise BundleError("manifest changed while verifying evidence")
    return before, loaded


def _ssh(args: list[str], payload: bytes) -> bytes:
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise SignatureError("ssh-keygen is unavailable; install OpenSSH to use attestations")
    try:
        result = subprocess.run(
            [executable, *args],
            input=payload,
            capture_output=True,
            timeout=30,
            start_new_session=True,
            check=False,
            env={**os.environ, "SSH_ASKPASS_REQUIRE": "never"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SignatureError(
            f"SSH signing tool unavailable or timed out: {type(error).__name__}"
        ) from None
    if result.returncode:
        raise SignatureError(f"SSH signature operation failed with exit {result.returncode}")
    return result.stdout


def sign(bundle: Path, key: Path, output: Path) -> dict[str, Any]:
    """Sign intact manifest bytes with an explicitly selected key; never overwrite."""
    bundle = bundle.resolve()
    output = output.absolute()
    if output.resolve().is_relative_to(bundle):
        raise SignatureError("detached signature must be outside the sealed bundle")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    payload, loaded = _manifest(bundle)
    target_root = loaded["result"].get("target", {}).get("root")
    if target_root and output.resolve().is_relative_to(Path(target_root).resolve()):
        raise SignatureError("detached signature must be outside the evaluated target")
    signature = _ssh(["-Y", "sign", "-f", str(key.resolve()), "-n", NAMESPACE], payload)
    # Recheck evidence after the external operation before publishing the signature.
    after, _ = _manifest(bundle)
    if payload != after:
        raise SignatureError("manifest changed during signing")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(signature)
    return {
        "signed": True,
        "authority": "ADVISORY",
        "run_id": loaded["result"]["run_id"],
        "namespace": NAMESPACE,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": str(output),
    }


def verify(bundle: Path, signature: Path, allowed_signers: Path, identity: str) -> dict[str, Any]:
    """Verify integrity and authenticate the exact manifest using caller-owned trust."""
    if not identity.strip() or identity.startswith("-"):
        raise SignatureError("an explicit signer identity is required")
    payload, loaded = _manifest(bundle.resolve())
    if signature.stat().st_size > 64_000:
        raise SignatureError("signature exceeds the supported size")
    _ssh(
        [
            "-Y",
            "verify",
            "-f",
            str(allowed_signers.resolve()),
            "-I",
            identity,
            "-n",
            NAMESPACE,
            "-s",
            str(signature.resolve()),
        ],
        payload,
    )
    after, _ = _manifest(bundle.resolve())
    if payload != after:
        raise SignatureError("manifest changed during signature verification")
    return {
        "authenticated": True,
        "authority": "ADVISORY",
        "identity": identity,
        "namespace": NAMESPACE,
        "run_id": loaded["result"]["run_id"],
        "verdict": loaded["result"]["verdict"],
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
    }
