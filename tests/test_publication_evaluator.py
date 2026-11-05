"""Tests for publication package integrity and manifest consistency evaluators."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

from howlproof.config import ProofConfig
from howlproof.evaluators.publication import (
    PublicationManifestConsistency,
    PublicationPackageIntegrity,
)
from howlproof.evidence import Bundle
from howlproof.model import CheckStatus, Severity
from howlproof.registry import Context
from howlproof.target import Target


def _create_synthetic_png(width: int = 1200, height: int = 675) -> bytes:
    """Create a minimal valid PNG with exact width and height."""
    header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
    iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    return header + ihdr_chunk + iend_chunk


def _setup_publication_target(
    root: Path, *, modify_manifest: bool = False, bad_image: bool = False, missing_alt: bool = False
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    posts_dir = root / "POSTS" / "POST_01"
    posts_dir.mkdir(parents=True, exist_ok=True)

    summary_content = "# Season 3 Summary\n\nPublication ready."
    readme_content = "# Season 3 Campaign\n\nInstructions."
    post_content = "This is a valid technical publication post with zero fabricated claims."

    (root / "SUMMARY.md").write_text(summary_content, encoding="utf-8")
    (root / "README.md").write_text(readme_content, encoding="utf-8")
    (posts_dir / "post.txt").write_text(post_content, encoding="utf-8")

    if not missing_alt:
        (posts_dir / "alt_text.txt").write_text(
            "Detailed architectural diagram showing components.", encoding="utf-8"
        )

    img_data = b"NOT_A_VALID_PNG" if bad_image else _create_synthetic_png(1200, 675)
    (posts_dir / "image.png").write_bytes(img_data)

    files_to_track = [
        "SUMMARY.md",
        "README.md",
        "POSTS/POST_01/post.txt",
        "POSTS/POST_01/image.png",
    ]
    if not missing_alt:
        files_to_track.append("POSTS/POST_01/alt_text.txt")

    manifest_entries = []
    for rel_path in files_to_track:
        content = (root / rel_path).read_bytes()
        sha = hashlib.sha256(content).hexdigest()
        if modify_manifest and rel_path.endswith("post.txt"):
            sha = "0000000000000000000000000000000000000000000000000000000000000000"
        manifest_entries.append(
            {
                "path": rel_path,
                "size_bytes": len(content),
                "sha256": sha,
            }
        )

    manifest = {
        "campaign": "LINKEDIN_SEASON_03",
        "files_count": len(manifest_entries),
        "files": manifest_entries,
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def test_publication_evaluator_clean_package(tmp_path: Path) -> None:
    root = tmp_path / "target"
    _setup_publication_target(root)

    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(
        target,
        ProofConfig(schema_version=1, artifact="test_campaign"),
        Bundle.create(tmp_path / "proof", root),
    )

    integrity_eval = PublicationPackageIntegrity()
    app, _ = integrity_eval.applicable(context)
    assert app is True
    outcome = integrity_eval.evaluate(context)
    assert outcome.checks[0].status == CheckStatus.VERIFIED
    assert len(outcome.findings) == 0

    consistency_eval = PublicationManifestConsistency()
    app2, _ = consistency_eval.applicable(context)
    assert app2 is True
    outcome2 = consistency_eval.evaluate(context)
    assert outcome2.checks[0].status == CheckStatus.VERIFIED
    assert len(outcome2.findings) == 0


def test_publication_evaluator_corrupted_image(tmp_path: Path) -> None:
    root = tmp_path / "target_corrupt"
    _setup_publication_target(root, bad_image=True)

    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(
        target,
        ProofConfig(schema_version=1, artifact="test_campaign"),
        Bundle.create(tmp_path / "proof", root),
    )

    integrity_eval = PublicationPackageIntegrity()
    outcome = integrity_eval.evaluate(context)
    assert outcome.checks[0].status == CheckStatus.FAILED
    assert any("corrupt image format" in f.summary for f in outcome.findings)


def test_publication_evaluator_missing_alt_text(tmp_path: Path) -> None:
    root = tmp_path / "target_missing_alt"
    _setup_publication_target(root, missing_alt=True)

    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(
        target,
        ProofConfig(schema_version=1, artifact="test_campaign"),
        Bundle.create(tmp_path / "proof", root),
    )

    integrity_eval = PublicationPackageIntegrity()
    outcome = integrity_eval.evaluate(context)
    assert outcome.checks[0].status == CheckStatus.FAILED
    assert any("missing alt_text.txt" in f.summary for f in outcome.findings)


def test_publication_evaluator_manifest_sha_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "target_mismatch"
    _setup_publication_target(root, modify_manifest=True)

    target = Target.prepare(root, tmp_path / "workspace")
    context = Context(
        target,
        ProofConfig(schema_version=1, artifact="test_campaign"),
        Bundle.create(tmp_path / "proof", root),
    )

    consistency_eval = PublicationManifestConsistency()
    outcome = consistency_eval.evaluate(context)
    assert outcome.checks[0].status == CheckStatus.FAILED
    assert outcome.findings[0].severity == Severity.BLOCKER
    assert any("sha256 mismatch" in disc for disc in outcome.checks[0].detail["discrepancies"])


def test_publication_profile_loading_and_resolution() -> None:
    from howlproof.evaluators import build_registry
    from howlproof.model import Adversary
    from howlproof.registry import load_profiles, select

    profiles = load_profiles()
    assert "publication" in profiles
    assert profiles["publication"]["evaluators"] == [
        "publication.package.integrity",
        "publication.manifest.consistency",
    ]

    registry = build_registry()
    evaluators = select(registry, ["publication"], [Adversary.OPERATOR])
    eval_ids = [e.id for e in evaluators]
    assert "publication.package.integrity" in eval_ids
    assert "publication.manifest.consistency" in eval_ids
