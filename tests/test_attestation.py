"""Authenticity requires an explicit trusted signer as well as intact evidence."""

import shutil
import subprocess

import pytest

from howlproof.attestation import SignatureError, sign, verify
from howlproof.config import ProofConfig
from howlproof.engine import evaluate
from howlproof.evaluators import build_registry
from howlproof.evidence import BundleError


@pytest.fixture
def signed_setup(tmp_path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("OpenSSH signing is an optional runtime capability")
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    allowed = tmp_path / "allowed-signers"
    allowed.write_text("test-signer " + key.with_suffix(".pub").read_text())
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("fixture")
    evaluate(
        target,
        ProofConfig(schema_version=1, artifact="signed-fixture", profiles=["secrets.scan"]),
        build_registry(),
        tmp_path / "evidence",
    )
    bundle = next(p.parent for p in (tmp_path / "evidence").glob("*/manifest.json"))
    return bundle, key, allowed, tmp_path / "signature"


def test_sign_verify_and_identity_rejection(signed_setup):
    bundle, key, allowed, signature = signed_setup
    sign(bundle, key, signature)
    result = verify(bundle, signature, allowed, "test-signer")
    assert result["authenticated"] is True
    assert result["authority"] == "ADVISORY"
    with pytest.raises(SignatureError):
        verify(bundle, signature, allowed, "someone-else")
    with pytest.raises(FileExistsError):
        sign(bundle, key, signature)


def test_tampered_signature_is_rejected(signed_setup):
    bundle, key, allowed, signature = signed_setup
    sign(bundle, key, signature)
    signature.write_text("invalid signature")
    with pytest.raises(SignatureError):
        verify(bundle, signature, allowed, "test-signer")


def test_tampered_evidence_is_rejected_even_with_valid_signature(signed_setup):
    bundle, key, allowed, signature = signed_setup
    sign(bundle, key, signature)
    (bundle / "result.json").write_text("{}")
    with pytest.raises(BundleError):
        verify(bundle, signature, allowed, "test-signer")


def test_signature_cannot_be_written_into_bundle(signed_setup):
    bundle, key, _, _ = signed_setup
    with pytest.raises(SignatureError, match="outside"):
        sign(bundle, key, bundle / "signature")
    assert not (bundle / "signature").exists()


def test_reindexed_forgery_is_not_authenticated(signed_setup):
    import hashlib
    import json

    bundle, key, allowed, signature = signed_setup
    sign(bundle, key, signature)
    result_path = bundle / "result.json"
    result = json.loads(result_path.read_text())
    result["verdict"] = "PROVEN"
    result_path.write_text(json.dumps(result))
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["file_hashes"]["result.json"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    # An attacker can rebuild the unkeyed integrity index, but cannot reuse the signature.
    with pytest.raises(SignatureError):
        verify(bundle, signature, allowed, "test-signer")


def test_cli_authentication_does_not_clear_advisory_verdict(signed_setup, capsys):
    import json

    from howlproof.cli import main

    bundle, key, allowed, signature = signed_setup
    assert main(["attest", str(bundle), "--key", str(key), "--output", str(signature)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "verify-attestation",
                str(bundle),
                "--signature",
                str(signature),
                "--allowed-signers",
                str(allowed),
                "--identity",
                "test-signer",
            ]
        )
        == 0
    )
    authenticated = json.loads(capsys.readouterr().out)
    assert authenticated["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert authenticated["authority"] == "ADVISORY"
    assert (
        main(
            [
                "verify-attestation",
                str(bundle),
                "--signature",
                str(signature),
                "--allowed-signers",
                str(allowed),
                "--identity",
                "untrusted",
            ]
        )
        == 4
    )


def test_signed_ingestion_refuses_unknown_identity_before_plane(signed_setup):
    from howlproof.cli import main

    bundle, key, allowed, signature = signed_setup
    sign(bundle, key, signature)
    run_dir = signature.parent / "ingestion"
    assert (
        main(
            [
                "plane",
                str(bundle),
                "--signature",
                str(signature),
                "--allowed-signers",
                str(allowed),
                "--identity",
                "untrusted",
                "--run-dir",
                str(run_dir),
                "--executable",
                "/absent/plane",
            ]
        )
        == 4
    )
    assert not run_dir.exists()
