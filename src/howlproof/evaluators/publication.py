"""Publication package integrity and manifest consistency verification."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from howlproof.model import (
    Adversary,
    Confidence,
    Reproduction,
    ReproductionStep,
    Severity,
)
from howlproof.registry import Context, Evaluator, Outcome

REQUIRED_ROOT_FILES = ("MANIFEST.json", "SUMMARY.md", "README.md")
MIN_IMAGE_WIDTH = 1200
MIN_IMAGE_HEIGHT = 675


def _parse_image_dimensions(data: bytes) -> tuple[int, int] | None:
    """Deterministically parse image width and height from PNG or JPEG headers."""
    if len(data) >= 24 and data.startswith(b"\x89PNG\r\n\x1a\n"):
        if data[12:16] == b"IHDR":
            width, height = struct.unpack(">II", data[16:24])
            return width, height
    elif len(data) >= 4 and data.startswith(b"\xff\xd8"):
        offset = 2
        while offset < len(data) - 9:
            if offset + 4 > len(data):
                break
            marker = data[offset : offset + 2]
            if marker[0] != 0xFF:
                break
            if marker in (b"\xff\xd9", b"\xff\xda"):
                break
            try:
                (length,) = struct.unpack(">H", data[offset + 2 : offset + 4])
            except struct.error:
                break
            if marker in (
                b"\xff\xc0",
                b"\xff\xc1",
                b"\xff\xc2",
                b"\xff\xc3",
                b"\xff\xc5",
                b"\xff\xc6",
                b"\xff\xc7",
            ) and offset + 4 + 5 <= len(data):
                _, height, width = struct.unpack(">BHH", data[offset + 4 : offset + 9])
                return width, height
            offset += 2 + length
    return None


class PublicationPackageIntegrity(Evaluator):
    """Check structural integrity of publication packages.

    Verifies:
    1. Required root files (MANIFEST.json, SUMMARY.md, README.md).
    2. Safe relative paths (no directory traversal or absolute escapes).
    3. Valid UTF-8 encoding across text artifacts.
    4. Valid image decode, magic signatures, and publication-ready dimensions.
    5. Alt-text presence for every illustrated post.
    """

    id = "publication.package.integrity"
    version = "1"
    adversary = Adversary.OPERATOR

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists("MANIFEST.json") or context.target.exists("SUMMARY.md"):
            return True, ""
        posts = [n for n in context.target.names if n.startswith("POSTS/")]
        if posts:
            return True, ""
        return False, "no publication manifest, summary, or POSTS directory present"

    def evaluate(self, context: Context) -> Outcome:
        problems: list[str] = []
        observed: dict[str, Any] = {"files_checked": len(context.target.names)}

        # 1. Required root files
        missing_root = [req for req in REQUIRED_ROOT_FILES if not context.target.exists(req)]
        if missing_root:
            problems.append(f"missing required root files: {', '.join(missing_root)}")

        # 2. Safe relative paths
        for name in context.target.names:
            p = Path(name)
            if p.is_absolute() or ".." in p.parts:
                problems.append(f"unsafe path detected: {name}")

        # 3. UTF-8 encoding check
        text_extensions = (".txt", ".md", ".json", ".csv", ".yaml", ".yml")
        encoding_errors: list[str] = []
        for name in context.target.names:
            if any(name.endswith(ext) for ext in text_extensions):
                try:
                    raw = context.target.read_bytes(name)
                    raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    encoding_errors.append(f"{name}: {exc}")
        if encoding_errors:
            err_summary = ", ".join(encoding_errors[:3])
            problems.append(
                f"{len(encoding_errors)} text files contain invalid UTF-8: {err_summary}"
            )

        # 4. Image decoding, dimensions, and magic headers
        image_extensions = (".png", ".jpg", ".jpeg")
        images = [
            n
            for n in context.target.names
            if any(n.lower().endswith(ext) for ext in image_extensions)
        ]
        observed["image_count"] = len(images)
        image_details: list[dict[str, Any]] = []

        for img_name in images:
            img_bytes = context.target.read_bytes(img_name)
            if not img_bytes:
                problems.append(f"empty image file: {img_name}")
                continue

            dims = _parse_image_dimensions(img_bytes)
            if dims is None:
                problems.append(f"invalid or corrupt image format: {img_name}")
                continue

            width, height = dims
            image_details.append({"path": img_name, "width": width, "height": height})
            if width < MIN_IMAGE_WIDTH or height < MIN_IMAGE_HEIGHT:
                problems.append(
                    f"image {img_name} dimensions ({width}x{height}) "
                    f"below required minimum ({MIN_IMAGE_WIDTH}x{MIN_IMAGE_HEIGHT})"
                )

        observed["images"] = image_details

        # 5. Alt-text presence for illustrated posts
        post_dirs: set[str] = set()
        for img in images:
            if "/" in img:
                parent = str(Path(img).parent)
                post_dirs.add(parent)

        missing_alt: list[str] = []
        for pdir in sorted(post_dirs):
            alt_candidates = [f"{pdir}/alt_text.txt", f"{pdir}/image_alt.txt"]
            alt_found = next((c for c in alt_candidates if context.target.exists(c)), None)
            if not alt_found:
                missing_alt.append(pdir)
            else:
                alt_content = context.target.read_text(alt_found).strip()
                if len(alt_content) < 10:
                    problems.append(f"alt text in {alt_found} is trivially short (< 10 chars)")

        if missing_alt:
            missing_dirs = ", ".join(missing_alt)
            problems.append(
                f"missing alt_text.txt or image_alt.txt in illustrated posts: {missing_dirs}"
            )

        ref = context.save_evidence_json(self.id, "package_integrity.json", observed)
        limitation = (
            "validates required package layout, path safety, text encoding, image headers,"
            " dimensions, and accessibility metadata on disk; does not evaluate stylistic prose."
        )

        if problems:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(problems)} publication package integrity issues detected",
                        limitation,
                        evidence_refs=[ref],
                        detail={"problems": problems},
                    )
                ],
                findings=[
                    self.finding(
                        title="Publication package contains integrity or accessibility defects",
                        category="correctness",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(problems),
                        evidence=json.dumps({"problems": problems, "observed": observed}, indent=2),
                        remediation=(
                            "Ensure required files exist, images are valid (width>=1200, "
                            "height>=675), text files use valid UTF-8, and alt text is supplied."
                        ),
                        rule="publication.package.defect",
                        reproduction=Reproduction(
                            summary="Inspect package root and post folders.",
                            steps=[
                                ReproductionStep(
                                    description="Check required root files and image integrity",
                                    kind="file_probe",
                                    payload={"paths": list(REQUIRED_ROOT_FILES)},
                                    expect={"exists": True},
                                )
                            ],
                        ),
                    )
                ],
            )

        return Outcome(
            checks=[
                self.verified(
                    f"publication package layout verified ({len(context.target.names)} files, "
                    f"{len(images)} images)",
                    limitation,
                    evidence_refs=[ref],
                    detail=observed,
                )
            ]
        )


class PublicationManifestConsistency(Evaluator):
    """Check consistency between MANIFEST.json and disk files.

    Verifies:
    1. MANIFEST.json exists and contains valid JSON.
    2. Every declared file exists on disk.
    3. File size matches declared size.
    4. SHA-256 matches declared digest.
    5. No extraneous untracked content files exist outside manifest.
    """

    id = "publication.manifest.consistency"
    version = "1"
    adversary = Adversary.OPERATOR

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists("MANIFEST.json"):
            return True, ""
        return False, "MANIFEST.json is absent"

    def evaluate(self, context: Context) -> Outcome:
        try:
            raw_manifest = context.target.read_text("MANIFEST.json")
            manifest_data = json.loads(raw_manifest)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            return Outcome(
                checks=[
                    self.failed(
                        f"MANIFEST.json cannot be parsed: {exc}",
                        "requires valid JSON MANIFEST.json",
                    )
                ],
                findings=[
                    self.finding(
                        title="MANIFEST.json is unparseable",
                        category="correctness",
                        severity=Severity.BLOCKER,
                        confidence=Confidence.CONFIRMED,
                        summary=str(exc),
                        evidence=context.target.read_text("MANIFEST.json", limit=1000),
                        remediation="Generate a valid JSON manifest.",
                        rule="publication.manifest.invalid_json",
                        reproduction=Reproduction(
                            summary="Parse MANIFEST.json.",
                            steps=[
                                ReproductionStep(
                                    description="Parse MANIFEST.json as JSON",
                                    kind="file_probe",
                                    payload={"path": "MANIFEST.json"},
                                    expect={"valid_json": False},
                                )
                            ],
                        ),
                    )
                ],
            )

        # Normalize manifest entries to dict: path -> {size, sha256}
        declared_files: dict[str, dict[str, Any]] = {}
        files_entry = manifest_data.get("files", [])
        if isinstance(files_entry, list):
            for item in files_entry:
                if isinstance(item, dict) and "path" in item:
                    declared_files[item["path"]] = item
        elif isinstance(files_entry, dict):
            for path_key, item in files_entry.items():
                if isinstance(item, dict):
                    declared_files[path_key] = item
                else:
                    declared_files[path_key] = {"sha256": str(item)}

        discrepancies: list[str] = []
        observed_results: dict[str, Any] = {
            "declared_count": len(declared_files),
            "verified_count": 0,
            "mismatches": [],
        }

        # Check declared files
        for rel_path, meta in declared_files.items():
            norm_path = rel_path.lstrip("./")
            if not context.target.exists(norm_path):
                discrepancies.append(f"declared file missing on disk: {norm_path}")
                continue

            content = context.target.read_bytes(norm_path)
            actual_size = len(content)
            actual_sha = hashlib.sha256(content).hexdigest()

            expected_size = meta.get("size_bytes", meta.get("size"))
            expected_sha = meta.get("sha256")

            if expected_size is not None and int(expected_size) != actual_size:
                discrepancies.append(
                    f"size mismatch for {norm_path}: expected {expected_size}, got {actual_size}"
                )
            if expected_sha and expected_sha.lower() != actual_sha.lower():
                discrepancies.append(
                    f"sha256 mismatch for {norm_path}: expected {expected_sha}, got {actual_sha}"
                )

            if not discrepancies or norm_path not in discrepancies[-1]:
                observed_results["verified_count"] += 1

        # Check for untracked content files
        ignored_names = {
            "MANIFEST.json",
            ".howlproof.json",
            "proof.json",
            "evidence.json",
        }
        untracked = [
            n
            for n in context.target.names
            if n not in declared_files
            and n.lstrip("./") not in declared_files
            and Path(n).name not in ignored_names
            and not n.startswith(".")
        ]
        if untracked:
            omitted = ", ".join(untracked[:5])
            discrepancies.append(
                f"{len(untracked)} files exist on disk but are omitted from manifest: {omitted}"
            )

        ref = context.save_evidence_json(self.id, "manifest_consistency.json", observed_results)
        limitation = (
            "verifies cryptographic digest (SHA-256) and exact byte lengths of files declared "
            "in MANIFEST.json against disk copies; does not attest to external publication status."
        )

        if discrepancies:
            observed_results["mismatches"] = discrepancies
            return Outcome(
                checks=[
                    self.failed(
                        f"manifest check failed with {len(discrepancies)} discrepancies",
                        limitation,
                        evidence_refs=[ref],
                        detail={"discrepancies": discrepancies},
                    )
                ],
                findings=[
                    self.finding(
                        title="Publication manifest does not match disk contents",
                        category="correctness",
                        severity=Severity.BLOCKER,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(discrepancies),
                        evidence=json.dumps({"discrepancies": discrepancies}, indent=2),
                        remediation=(
                            "Re-run manifest generation to record accurate hashes and file sizes."
                        ),
                        rule="publication.manifest.mismatch",
                        reproduction=Reproduction(
                            summary="Verify disk files against manifest digests.",
                            steps=[
                                ReproductionStep(
                                    description="Check file hashes against manifest",
                                    kind="file_probe",
                                    payload={"manifest": "MANIFEST.json"},
                                    expect={"matches": False},
                                )
                            ],
                        ),
                    )
                ],
            )

        return Outcome(
            checks=[
                self.verified(
                    f"all {len(declared_files)} manifest entries match disk files and "
                    "SHA-256 digests exactly",
                    limitation,
                    evidence_refs=[ref],
                    detail=observed_results,
                )
            ]
        )


EVALUATORS: list[Evaluator] = [
    PublicationPackageIntegrity(),
    PublicationManifestConsistency(),
]
