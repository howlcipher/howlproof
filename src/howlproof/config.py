"""Strict, versioned evaluation configuration. Ambiguity here becomes a false verdict later."""

from __future__ import annotations

from datetime import date
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from howlproof.model import Adversary, Severity

#: A configuration larger than this is a mistake, not a configuration.
MAX_CONFIG_BYTES = 256_000

CONFIG_NAMES = ("howlproof.yaml", "howlproof.yml", ".howlproof.yaml")


def _coerce(enum: type[Enum]) -> Any:
    """Accept the enum's written value while the rest of the model stays strict.

    Strict validation is what stops a configuration typo becoming a silent behaviour
    change. It should not force an author to write Python enum instances in YAML, so
    exactly one conversion is allowed, and an unknown value still fails loudly.
    """

    def convert(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return enum(value)
            except ValueError as unknown:
                allowed = ", ".join(member.value for member in enum)
                raise ValueError(f"expected one of: {allowed}") from unknown
        return value

    return BeforeValidator(convert)


AdversaryName = Annotated[Adversary, _coerce(Adversary)]
SeverityName = Annotated[Severity, _coerce(Severity)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ChecksPass(StrictModel):
    """Named checks must all reach VERIFIED. SKIPPED and UNAVAILABLE do not satisfy it."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["checks_pass"]
    checks: list[str] = Field(min_length=1, max_length=200)
    optional: bool = False


class MaxFindings(StrictModel):
    """Cap findings at or above a severity, optionally scoped to one adversary."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["max_findings"]
    limit: int = Field(ge=0, le=10_000)
    min_severity: SeverityName = Severity.HIGH
    adversary: AdversaryName | None = None
    optional: bool = False


class ToolRequired(StrictModel):
    """Named tools must actually be present. An absent tool fails; it never silently skips."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["tool_required"]
    tools: list[str] = Field(min_length=1, max_length=50)
    optional: bool = False


class NoRegressions(StrictModel):
    """No finding previously recorded as VERIFIED_FIXED may reappear."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["no_regressions"]
    optional: bool = False


class RequiredEvidence(StrictModel):
    """Named evidence artifacts must exist in the bundle."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["required_evidence"]
    artifacts: list[str] = Field(min_length=1, max_length=100)
    optional: bool = False


class CoverageFloor(StrictModel):
    """A fraction of applicable checks must have produced a conclusive result.

    Conclusive means VERIFIED or FAILED. Checks that were skipped, unavailable or
    errored count against coverage, which is the point: a run where most checks
    never executed cannot support a confident verdict.
    """

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    requirement: Literal["coverage_floor"]
    min_conclusive_fraction: float = Field(ge=0.0, le=1.0)
    optional: bool = False


Criterion = Annotated[
    ChecksPass | MaxFindings | ToolRequired | NoRegressions | RequiredEvidence | CoverageFloor,
    Field(discriminator="requirement"),
]


class Exclusion(StrictModel):
    """A deliberate gap. Any active exclusion prevents PROVEN and forces the weaker verdict."""

    check: str = Field(pattern=r"^[A-Za-z0-9_.*-]{1,60}$")
    reason: str = Field(min_length=10, max_length=1000)
    expires: date | None = None


class ServiceConfig(StrictModel):
    """How to bring the artifact up so live adversaries have something to attack."""

    base_url: str = Field(pattern=r"^http://(127\.0\.0\.1|localhost)(:\d{2,5})?$")
    start: list[str] = Field(default_factory=list, max_length=30)
    stop: list[str] = Field(default_factory=list, max_length=30)
    workdir: str = "."
    ready_path: str = "/"
    ready_method: Literal["GET", "POST"] = "GET"
    ready_timeout_seconds: int = Field(default=30, ge=1, le=300)
    seed: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("workdir", "ready_path")
    @classmethod
    def no_parent_escape(cls, value: str) -> str:
        if ".." in Path(value).parts:
            raise ValueError("path must not traverse outside the target")
        return value


class AuthorityProbe(StrictModel):
    """One request the artifact is expected to refuse, and the refusal that proves it."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,60}$")
    method: Literal["GET", "POST"] = "POST"
    path: str = Field(pattern=r"^/[A-Za-z0-9_./-]{0,200}$")
    body: dict[str, Any] = Field(default_factory=dict)
    setup: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    expect_status: int = Field(default=403, ge=100, le=599)
    expect_body_contains: str = ""
    description: str = Field(default="", max_length=500)


class ApiConfig(StrictModel):
    """Endpoints and denial expectations for the functional and security adversaries."""

    endpoints: list[str] = Field(default_factory=list, max_length=100)
    mutating_endpoint: str = ""
    mutating_body: dict[str, Any] = Field(default_factory=dict)
    authority_probes: list[AuthorityProbe] = Field(default_factory=list, max_length=50)
    max_body_bytes: int = Field(default=2_000_000, ge=1024, le=64_000_000)


class WebConfig(StrictModel):
    """Static site surface for the web adversary."""

    root: str = "docs"
    pages: list[str] = Field(default_factory=lambda: ["index.html"], max_length=50)
    viewports: list[int] = Field(default_factory=lambda: [375, 768, 1440], max_length=10)
    require_skip_link: bool = True
    canonical_prefix: str = ""

    @field_validator("root")
    @classmethod
    def no_parent_escape(cls, value: str) -> str:
        if ".." in Path(value).parts:
            raise ValueError("web.root must not traverse outside the target")
        return value


class MarkupConfig(StrictModel):
    """Where the artifact builds HTML, so unescaped interpolation can be found."""

    sources: list[str] = Field(default_factory=list, max_length=200)
    sink_functions: list[str] = Field(default_factory=lambda: ["set_html", "innerHTML"])
    escape_functions: list[str] = Field(default_factory=lambda: ["esc", "escapeHtml"])


class InjectionPayload(StrictModel):
    """One authored payload placed into data the artifact will render."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,60}$")
    file: str = Field(min_length=1, max_length=300)
    pointer: str = Field(pattern=r"^(/[^/]+)+$")
    value: str = Field(min_length=1, max_length=2000)
    description: str = Field(default="", max_length=500)

    @field_validator("file")
    @classmethod
    def stays_inside(cls, value: str) -> str:
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("injection payload files must be relative paths inside the target")
        return value


class InjectionConfig(StrictModel):
    """A browser-level proof that untrusted data reaches an execution context.

    Static analysis can show an escaper is insufficient for a context. Only loading
    the real interface can show the value actually executes, so a confirmed finding
    needs this.
    """

    app_root: str = "frontend"
    page: str = "index.html"
    marker: str = Field(default="__howlproof_injection", pattern=r"^[A-Za-z_][A-Za-z0-9_]{3,60}$")
    seed_request: str = "POST /api/seed"
    settle_ms: int = Field(default=2500, ge=100, le=30_000)
    payloads: list[InjectionPayload] = Field(default_factory=list, max_length=20)

    @field_validator("app_root")
    @classmethod
    def no_parent_escape(cls, value: str) -> str:
        if ".." in Path(value).parts:
            raise ValueError("injection.app_root must not traverse outside the target")
        return value


class CliConfig(StrictModel):
    """The artifact's own command line, for the functional and operator adversaries."""

    command: list[str] = Field(default_factory=list, max_length=20)
    help_flag: str = "--help"
    destructive_subcommands: list[str] = Field(default_factory=list, max_length=50)
    #: Set when the command only exists after the artifact is installed into its own
    #: environment, so the check provisions one instead of reporting a missing binary.
    needs_python_env: bool = False


class AiConfig(StrictModel):
    """Declared AI surface. Absent means the AI adversary reports NOT_APPLICABLE, honestly."""

    entrypoint: list[str] = Field(default_factory=list, max_length=20)
    untrusted_input_paths: list[str] = Field(default_factory=list, max_length=50)
    policy_markers: list[str] = Field(default_factory=list, max_length=50)


class DocsConfig(StrictModel):
    """Documents whose absolute claims the operator adversary will try to falsify."""

    claim_sources: list[str] = Field(default_factory=list, max_length=100)
    synced_pairs: list[list[str]] = Field(default_factory=list, max_length=50)

    @field_validator("synced_pairs")
    @classmethod
    def pairs_are_pairs(cls, value: list[list[str]]) -> list[list[str]]:
        for pair in value:
            if len(pair) != 2:
                raise ValueError("each synced pair needs exactly two paths")
        return value


class ProofConfig(StrictModel):
    """The whole contract between an artifact and its adversary."""

    schema_version: Literal[1]
    artifact: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    description: str = Field(default="", max_length=2000)
    profiles: list[str] = Field(default_factory=lambda: ["default"], min_length=1, max_length=20)
    adversaries: list[AdversaryName] = Field(
        default_factory=lambda: [
            Adversary.FUNCTIONAL,
            Adversary.SECURITY,
            Adversary.RELIABILITY,
            Adversary.AI,
            Adversary.OPERATOR,
        ],
        min_length=1,
    )
    blocking_severity: SeverityName = Severity.HIGH
    acceptance: list[Criterion] = Field(default_factory=list, max_length=100)
    exclusions: list[Exclusion] = Field(default_factory=list, max_length=50)
    include_ignored: list[str] = Field(default_factory=list, max_length=50)
    service: ServiceConfig | None = None
    api: ApiConfig | None = None
    web: WebConfig | None = None
    markup: MarkupConfig | None = None
    injection: InjectionConfig | None = None
    cli: CliConfig | None = None
    ai: AiConfig | None = None
    docs: DocsConfig | None = None

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version_type(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("schema_version must be integer 1")
        return value

    @field_validator("include_ignored")
    @classmethod
    def ignored_paths_stay_inside(cls, value: list[str]) -> list[str]:
        """Build outputs a target ignores but an evaluation needs, named explicitly."""
        for entry in value:
            path = Path(entry)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("include_ignored entries must be relative paths inside the target")
        return value

    @model_validator(mode="after")
    def unique_criteria(self) -> ProofConfig:
        ids = [criterion.id for criterion in self.acceptance]
        if len(ids) != len(set(ids)):
            raise ValueError("acceptance criterion IDs must be unique")
        if len({p for p in self.profiles}) != len(self.profiles):
            raise ValueError("profiles must be unique")
        excluded = [exclusion.check for exclusion in self.exclusions]
        if len(excluded) != len(set(excluded)):
            raise ValueError("exclusions must name each check at most once")
        return self

    def active_exclusions(self, today: date) -> list[Exclusion]:
        return [e for e in self.exclusions if e.expires is None or e.expires >= today]

    def expired_exclusions(self, today: date) -> list[Exclusion]:
        return [e for e in self.exclusions if e.expires is not None and e.expires < today]


def find_config(target: Path) -> Path | None:
    for name in CONFIG_NAMES:
        candidate = target / name
        if candidate.is_file():
            return candidate
    return None


def read_config(path: Path) -> ProofConfig:
    if path.is_symlink():
        raise ValueError("configuration must not be a symlink")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"configuration exceeds {MAX_CONFIG_BYTES} bytes")
    loaded = yaml.safe_load(path.read_text())
    if not isinstance(loaded, dict):
        raise ValueError("configuration must be a YAML mapping")  # noqa: TRY004
    return ProofConfig.model_validate(loaded)


def default_config(artifact: str, profiles: list[str]) -> ProofConfig:
    """A configuration for a target that ships none. Deliberately cannot reach PROVEN alone."""
    return ProofConfig(
        schema_version=1,
        artifact=artifact,
        description="Generated default: the artifact declares no acceptance criteria.",
        profiles=profiles,
    )
