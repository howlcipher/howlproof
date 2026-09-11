"""The security adversary looks for credentials the artifact carries in the open.

Deterministic and dependency-free on purpose: a secret scan that only runs when an
external scanner happens to be installed is a scan that silently does not run.
"""

from __future__ import annotations

import re
from typing import Any

from howlproof.model import (
    Adversary,
    Confidence,
    Finding,
    Reproduction,
    ReproductionStep,
    Severity,
)
from howlproof.registry import Context, Evaluator, Outcome

#: Patterns chosen for shape, not for guessing. Each one is a credential format.
PATTERNS: tuple[tuple[str, str, Severity], ...] = (
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{30,}", Severity.BLOCKER),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{40,}", Severity.BLOCKER),
    ("openai_key", r"sk-[A-Za-z0-9]{20,}", Severity.BLOCKER),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", Severity.BLOCKER),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}", Severity.BLOCKER),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", Severity.BLOCKER),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", Severity.HIGH),
    (
        "assigned_credential",
        (
            r"(?i)\b(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token)\b"
            r"\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        Severity.HIGH,
    ),
)

#: Values that look like credentials but are placeholders by convention.
PLACEHOLDERS = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|<[^>]+>|\$\{?[a-z_]+\}?|changeme|placeholder|example|redacted|"
    r"your[-_]?\w+|dummy|sample|test[-_]?\w*|fake[-_]?\w*|none|null|todo)$"
)

TEXT_SUFFIXES = (
    ".py",
    ".go",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".bash",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".howl",
    ".tf",
    ".conf",
    ".properties",
    ".xml",
    ".sql",
    ".rb",
    ".java",
    ".cs",
    ".php",
    ".pl",
)

#: Paths where a credential-shaped string is expected to be a fixture, not a secret.
FIXTURE_HINTS = ("test", "fixture", "example", "sample", "mock", "spec")

MAX_BYTES = 2_000_000


class SecretScan(Evaluator):
    """Look for credential-shaped strings the artifact carries in the open."""

    id = "secrets.scan"
    adversary = Adversary.SECURITY

    def evaluate(self, context: Context) -> Outcome:
        hits: list[dict[str, Any]] = []
        scanned = 0
        for name in context.target.iter_files(*TEXT_SUFFIXES):
            if name.startswith(".howlproof-venv/") or "/node_modules/" in name:
                continue
            try:
                content = context.target.read_text(name, limit=MAX_BYTES)
            except (OSError, UnicodeError):
                continue
            scanned += 1
            hits.extend(_scan(name, content))

        ref = context.save_evidence_json(self.id, "matches.json", hits)
        limitation = (
            "pattern matching over text files in the working tree; it does not inspect git "
            "history, binaries, or credentials held only in a runtime environment"
        )
        if not hits:
            return Outcome(
                checks=[
                    self.verified(
                        f"no credential-shaped strings in {scanned} text files",
                        limitation,
                        evidence_refs=[ref],
                        detail={"files_scanned": scanned},
                    )
                ]
            )

        findings = [self._finding(hit) for hit in hits]
        return Outcome(
            checks=[
                self.failed(
                    f"{len(hits)} credential-shaped strings in {scanned} text files",
                    limitation,
                    evidence_refs=[ref],
                    detail={"files_scanned": scanned, "hits": len(hits)},
                )
            ],
            findings=findings,
        )

    def _finding(self, hit: dict[str, Any]) -> Finding:
        location = f"{hit['file']}:{hit['line']}"
        severity = Severity[str(hit["severity"])]
        fixture = bool(hit["looks_like_fixture"])
        if fixture and severity is not Severity.BLOCKER:
            severity = Severity.LOW
        reproduction = Reproduction(
            summary="Re-read the file and match the same pattern.",
            steps=[
                ReproductionStep(
                    description=f"Search {hit['file']} for the {hit['kind']} pattern.",
                    kind="file_probe",
                    payload={"path": hit["file"], "pattern": str(hit["pattern"])},
                    expect={"matches": True},
                )
            ],
        )
        return self.finding(
            title=f"Credential-shaped {hit['kind']} in {hit['file']}",
            category="security",
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                f"A string matching the {hit['kind']} credential format appears at {location}. "
                + (
                    "The path suggests a fixture, so this may be intentional test data."
                    if fixture
                    else "Nothing in the path suggests this is test data."
                )
            ),
            evidence=str(hit["excerpt"]),
            remediation=(
                "Remove the value from the tree, rotate it if it was ever real, and load it "
                "from the environment or a secret store instead."
            ),
            location=location,
            rule=f"secrets.{hit['kind']}",
            reproduction=reproduction,
            detail=dict(hit),
        )


def _scan(name: str, content: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lowered = name.lower()
    fixture = any(hint in lowered for hint in FIXTURE_HINTS)
    for kind, pattern, severity in PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(1) if match.groups() else match.group(0)
            if PLACEHOLDERS.match(value):
                continue
            line = content.count("\n", 0, match.start()) + 1
            hits.append(
                {
                    "file": name,
                    "line": line,
                    "kind": kind,
                    "pattern": pattern,
                    "severity": severity.name,
                    "looks_like_fixture": fixture,
                    "excerpt": _mask(content, match),
                }
            )
    return hits


def _mask(content: str, match: re.Match[str]) -> str:
    """Quote enough context to act on without reprinting the credential."""
    start = max(0, match.start() - 60)
    end = min(len(content), match.end() + 20)
    raw = match.group(0)
    keep = raw[:4]
    return (
        content[start : match.start()]
        + f"{keep}...[{len(raw)} chars redacted]"
        + content[match.end() : end]
    ).strip()


EVALUATORS: list[Evaluator] = [SecretScan()]
