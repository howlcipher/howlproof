"""The artifact under evaluation, held read-only.

HowlProof judges; it does not repair. That separation is enforced here rather than
promised in documentation: evaluators receive a copy to work in, and the original
tree is digested before and after so a mutation cannot pass unnoticed.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: A single file larger than this is not copied into the workspace; it is listed instead.
MAX_FILE_BYTES = 40_000_000
#: A target with more files than this is refused rather than silently truncated.
MAX_FILES = 20_000
#: Directories never copied even when a target tracks them.
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__", ".mypy_cache"})

DEFAULT_TIMEOUT = 300


class TargetError(RuntimeError):
    """The artifact could not be prepared for evaluation."""


class TargetMutatedError(RuntimeError):
    """The artifact changed while it was being evaluated, so the evidence is not trustworthy."""


@dataclass
class CommandResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "stdout": self.stdout[-20_000:],
            "stderr": self.stderr[-20_000:],
        }


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _is_git_repo(root: Path) -> bool:
    return _git(root, "rev-parse", "--is-inside-work-tree") is not None


def _tracked_and_untracked(root: Path) -> list[str] | None:
    """Files git would consider part of the working tree, gitignored entries excluded."""
    raw = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if raw is None:
        return None
    return sorted({name for name in raw.split("\0") if name})


def _walked(root: Path) -> list[str]:
    names: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if SKIP_DIRS & set(relative.parts):
            continue
        names.append(str(relative))
        if len(names) > MAX_FILES:
            raise TargetError(f"target holds more than {MAX_FILES} files; narrow the target")
    return names


def file_digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            sha.update(block)
    return sha.hexdigest()


def tree_digest(root: Path, names: Sequence[str]) -> str:
    """One digest over the names and contents of the evaluated file set."""
    sha = hashlib.sha256()
    for name in sorted(names):
        path = root / name
        sha.update(name.encode())
        sha.update(b"\0")
        if path.is_symlink():
            sha.update(b"symlink:" + os.readlink(path).encode())
        elif path.is_file():
            sha.update(file_digest(path).encode())
        else:
            sha.update(b"absent")
        sha.update(b"\n")
    return sha.hexdigest()


@dataclass
class Target:
    """A read-only handle on the artifact plus a scratch copy evaluators may execute in."""

    root: Path
    workspace: Path
    names: list[str]
    digest_before: str
    commit: str = ""
    branch: str = ""
    dirty: bool = False
    is_git: bool = False
    oversized: list[str] = field(default_factory=list)
    include_ignored: list[str] = field(default_factory=list)
    digest_after: str = ""

    # -- construction -----------------------------------------------------

    @classmethod
    def prepare(cls, root: Path, workspace: Path, include_ignored: Sequence[str] = ()) -> Target:
        root = root.resolve()
        if not root.is_dir():
            raise TargetError(f"target is not a directory: {root}")
        workspace = workspace.resolve()
        if workspace == root or root in workspace.parents:
            raise TargetError("the workspace must not live inside the target")

        is_git = _is_git_repo(root)
        discovered, is_git = cls._discover(root, is_git)
        extra = cls._expand_ignored(root, include_ignored)
        names = sorted(set(discovered) | set(extra))

        workspace.mkdir(parents=True, exist_ok=True)
        oversized = cls._materialise(root, workspace, names)

        commit = (_git(root, "rev-parse", "HEAD") or "").strip() if is_git else ""
        branch = (_git(root, "rev-parse", "--abbrev-ref", "HEAD") or "").strip() if is_git else ""
        dirty = bool((_git(root, "status", "--porcelain") or "").strip()) if is_git else False

        return cls(
            root=root,
            workspace=workspace,
            names=names,
            digest_before=tree_digest(root, names),
            commit=commit,
            branch=branch,
            dirty=dirty,
            is_git=is_git,
            oversized=oversized,
            include_ignored=list(include_ignored),
        )

    @staticmethod
    def _discover(root: Path, is_git: bool) -> tuple[list[str], bool]:
        names = _tracked_and_untracked(root) if is_git else None
        if names is None:
            names = _walked(root)
            is_git = False
        names = [n for n in names if not (SKIP_DIRS & set(Path(n).parts))]
        if len(names) > MAX_FILES:
            raise TargetError(f"target holds more than {MAX_FILES} files; narrow the target")
        return names, is_git

    @staticmethod
    def _expand_ignored(root: Path, include_ignored: Sequence[str]) -> list[str]:
        """Named build outputs a target gitignores but an evaluation genuinely needs."""
        found: list[str] = []
        for entry in include_ignored:
            candidate = (root / entry).resolve()
            if root not in candidate.parents and candidate != root:
                raise TargetError(f"include_ignored escapes the target: {entry}")
            if candidate.is_file():
                found.append(str(candidate.relative_to(root)))
            elif candidate.is_dir():
                for path in sorted(candidate.rglob("*")):
                    if path.is_file() and not path.is_symlink():
                        found.append(str(path.relative_to(root)))
        return found

    @staticmethod
    def _materialise(root: Path, workspace: Path, names: Sequence[str]) -> list[str]:
        oversized: list[str] = []
        for name in names:
            source = root / name
            if source.is_symlink() or not source.is_file():
                continue
            if source.stat().st_size > MAX_FILE_BYTES:
                oversized.append(name)
                continue
            destination = workspace / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return oversized

    # -- read-only access -------------------------------------------------

    def exists(self, relative: str) -> bool:
        return self._resolve(relative).is_file()

    def read_text(self, relative: str, limit: int = 4_000_000) -> str:
        path = self._resolve(relative)
        return path.read_text(encoding="utf-8", errors="replace")[:limit]

    def read_bytes(self, relative: str, limit: int = 4_000_000) -> bytes:
        return self._resolve(relative).read_bytes()[:limit]

    def iter_files(self, *suffixes: str) -> Iterator[str]:
        for name in self.names:
            if not suffixes or name.endswith(suffixes):
                yield name

    def glob(self, pattern: str) -> list[str]:
        return sorted(str(p.relative_to(self.workspace)) for p in self.workspace.glob(pattern))

    def _resolve(self, relative: str) -> Path:
        path = (self.workspace / relative).resolve()
        if self.workspace not in path.parents and path != self.workspace:
            raise TargetError(f"path escapes the workspace: {relative}")
        return path

    # -- execution --------------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        cwd_rel: str = ".",
        timeout: int = DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Run a command inside the workspace copy. The original tree is never the cwd."""
        cwd = self._resolve(cwd_rel)
        if not cwd.is_dir():
            raise TargetError(f"working directory missing from workspace: {cwd_rel}")
        environment = dict(os.environ)
        environment.update(env or {})
        environment["HOWLPROOF_TARGET_READONLY"] = "1"
        started = time.monotonic()
        try:
            completed = subprocess.run(
                list(argv),
                cwd=str(cwd),
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=environment,
            )
        except subprocess.TimeoutExpired as expired:
            return CommandResult(
                argv=list(argv),
                exit_code=124,
                stdout=_text(expired.stdout),
                stderr=_text(expired.stderr),
                duration_ms=int((time.monotonic() - started) * 1000),
                timed_out=True,
            )
        except FileNotFoundError as missing:
            raise TargetError(f"command not found: {argv[0]}") from missing
        return CommandResult(
            argv=list(argv),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    # -- the separation guard ---------------------------------------------

    def verify_unchanged(self) -> str:
        """Recompute the target digest over a fresh discovery.

        Re-discovering the file set matters as much as re-hashing it: an evaluator that
        writes a new file into the artifact would leave every recorded hash intact.
        """
        self.digest_after = tree_digest(self.root, self.names)
        added, removed = self._set_difference()
        if self.digest_after != self.digest_before or added or removed:
            detail = ""
            if added:
                detail += f" Added: {', '.join(added[:10])}."
            if removed:
                detail += f" Removed: {', '.join(removed[:10])}."
            raise TargetMutatedError(
                "the artifact under evaluation changed during evaluation; "
                "evidence gathered while mutating the subject is not trustworthy." + detail
            )
        return self.digest_after

    def _set_difference(self) -> tuple[list[str], list[str]]:
        try:
            discovered, _ = self._discover(self.root, self.is_git)
        except TargetError:
            return [], []
        current = set(discovered) | set(self._expand_ignored(self.root, self.include_ignored))
        recorded = set(self.names)
        return sorted(current - recorded), sorted(recorded - current)

    def changed_paths(self) -> list[str]:
        """Which paths differ from the recorded state, for an integrity finding's evidence."""
        added, removed = self._set_difference()
        changed = [f"{name} (added)" for name in added]
        changed += [f"{name} (removed)" for name in removed]
        for name in self.names:
            source = self.root / name
            copied = self.workspace / name
            if not source.is_file():
                changed.append(f"{name} (missing)")
            elif copied.is_file() and file_digest(source) != file_digest(copied):
                changed.append(f"{name} (modified)")
        return changed[:50]

    def describe(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "is_git": self.is_git,
            "commit": self.commit,
            "branch": self.branch,
            "dirty": self.dirty,
            "file_count": len(self.names),
            "oversized_files_not_copied": self.oversized,
            "tree_digest_before": self.digest_before,
            "tree_digest_after": self.digest_after,
        }


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
