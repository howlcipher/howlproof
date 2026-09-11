"""Command line for HowlProof.

Exit codes carry the verdict so a pipeline can branch without parsing output, and
every failure path prints a single machine-readable JSON object on stderr rather
than a traceback.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from yaml import YAMLError

from howlproof import __version__
from howlproof.config import ProofConfig, default_config, find_config, read_config
from howlproof.evaluators import build_registry
from howlproof.evidence import Bundle, BundleError, environment_probe, find_bundle
from howlproof.handoff import TARGETS, render, verification_plan
from howlproof.ledger import Ledger, LedgerError
from howlproof.model import (
    EXIT_CODES,
    EXIT_INTEGRITY,
    EXIT_INTERNAL,
    EXIT_USAGE,
    VERDICT_DEFINITIONS,
    VERDICT_RANK,
    FindingState,
    Verdict,
)
from howlproof.registry import load_profiles, select
from howlproof.report import render_report, render_terminal
from howlproof.reproduce import FixRefused, replay, verify_fix
from howlproof.target import TargetError

DEFAULT_EVIDENCE_ROOT = Path("proof")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="howlproof",
        description=(
            "Independent red-team QA for the Howl ecosystem. HowlProof judges artifacts and "
            "produces evidence; it never repairs the artifact it is judging."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    evaluate = commands.add_parser("evaluate", help="challenge an artifact and issue a verdict")
    evaluate.add_argument("target", type=Path)
    evaluate.add_argument(
        "--config",
        type=Path,
        help="evaluation contract; defaults to the artifact's own howlproof.yaml",
    )
    evaluate.add_argument("--profile", action="append", dest="profiles", default=[])
    evaluate.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    evaluate.add_argument(
        "--allow-network", action="store_true", help="permit checks that reach outside this machine"
    )
    evaluate.add_argument(
        "--allow-evidence-in-target",
        action="store_true",
        help="write the bundle inside the artifact; refused by default",
    )
    evaluate.add_argument("--json", action="store_true", help="print the result document")
    evaluate.add_argument(
        "--fail-under", choices=[v.value for v in Verdict], help="exit 0 for this verdict or better"
    )

    validate = commands.add_parser("validate", help="strictly validate an evaluation contract")
    validate.add_argument("config", type=Path)

    profiles = commands.add_parser("profiles", help="list or show evaluation profiles")
    profiles.add_argument("name", nargs="?")

    commands.add_parser("doctor", help="report which tooling is actually available")

    for name, help_text in (
        ("inspect", "re-verify a bundle's integrity and print its result"),
        ("explain", "show why a bundle reached its verdict"),
        ("report", "print a bundle's report"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("bundle", type=Path)
        if name == "report":
            sub.add_argument("--format", choices=["md", "json"], default="md")

    findings = commands.add_parser("findings", help="list findings from a bundle or the ledger")
    findings.add_argument("bundle", type=Path, nargs="?")
    findings.add_argument("--ledger", type=Path, help="read the finding ledger under this root")
    findings.add_argument("--artifact")
    findings.add_argument("--severity")
    findings.add_argument("--state")
    findings.add_argument("--json", action="store_true")

    reproduce = commands.add_parser("reproduce", help="re-execute a finding's recorded steps")
    reproduce.add_argument("finding")
    reproduce.add_argument("--bundle", type=Path, required=True)
    reproduce.add_argument("--target", type=Path, required=True)
    reproduce.add_argument("--config", type=Path)
    reproduce.add_argument("--json", action="store_true")

    verify = commands.add_parser(
        "verify-fix", help="re-run the evaluator that raised a finding against a changed artifact"
    )
    verify.add_argument("finding")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--target", type=Path, required=True)
    verify.add_argument("--config", type=Path)
    verify.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    verify.add_argument("--allow-network", action="store_true")
    verify.add_argument("--json", action="store_true")

    compare = commands.add_parser("compare", help="compare two evaluations of the same artifact")
    compare.add_argument("bundles", type=Path, nargs=2)

    handoff = commands.add_parser("handoff", help="write a sibling component's file contract")
    handoff.add_argument("bundle", type=Path)
    handoff.add_argument(
        "--for", dest="target", required=True, choices=[*TARGETS, "verification-plan"]
    )
    handoff.add_argument("--output", type=Path, help="write here instead of standard output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except (BundleError, LedgerError, TargetError, FixRefused, KeyError) as error:
        return _fail(str(error).strip("'"), EXIT_USAGE)
    except ValidationError as error:
        details = [
            {"field": ".".join(map(str, item["loc"])), "problem": item["msg"]}
            for item in error.errors()
        ]
        print(
            json.dumps({"error": "invalid configuration", "details": details[:20]}),
            file=sys.stderr,
        )
        return EXIT_USAGE
    except (YAMLError, ValueError) as error:
        return _fail(str(error), EXIT_USAGE)
    except OSError as error:
        return _fail(f"{type(error).__name__}: {error}", EXIT_USAGE)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERNAL)


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "validate":
        config = read_config(args.config)
        print(
            json.dumps(
                {
                    "valid": True,
                    "artifact": config.artifact,
                    "profiles": config.profiles,
                    "criteria": len(config.acceptance),
                }
            )
        )
        return 0
    if args.command == "profiles":
        return _profiles(args)
    if args.command == "doctor":
        return _doctor()
    if args.command in {"inspect", "explain", "report"}:
        return _read_bundle(args)
    if args.command == "findings":
        return _findings(args)
    if args.command == "reproduce":
        return _reproduce(args)
    if args.command == "verify-fix":
        return _verify_fix(args)
    if args.command == "compare":
        return _compare(args)
    if args.command == "handoff":
        return _handoff(args)
    return _fail(f"unknown command: {args.command}", EXIT_USAGE)


def _load_config(
    target: Path, explicit: Path | None, profiles: list[str]
) -> tuple[ProofConfig, str]:
    if explicit is not None:
        config = read_config(explicit)
        source = str(explicit)
    else:
        found = find_config(target)
        if found is None:
            config = default_config(
                target.resolve().name.replace(".", "-"), profiles or ["default"]
            )
            source = "generated default (the artifact declares no contract)"
            return config, source
        config = read_config(found)
        source = str(found)
    if profiles:
        config = ProofConfig.model_validate({**config.model_dump(), "profiles": profiles})
    return config, source


def _evaluate(args: argparse.Namespace) -> int:
    from howlproof.engine import EvaluationError, evaluate

    config, source = _load_config(args.target, args.config, args.profiles)
    try:
        result = evaluate(
            target_root=args.target,
            config=config,
            registry=build_registry(),
            evidence_root=args.evidence_root,
            allow_network=args.allow_network,
            allow_evidence_in_target=args.allow_evidence_in_target,
            config_source=source,
        )
    except EvaluationError as error:
        return _fail(str(error), EXIT_USAGE)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_terminal(result))

    verdict = Verdict(result["verdict"])
    if result["deciding_rule"] == "integrity":
        return EXIT_INTEGRITY
    if args.fail_under:
        return (
            0
            if VERDICT_RANK[verdict] <= VERDICT_RANK[Verdict(args.fail_under)]
            else EXIT_CODES[verdict]
        )
    return EXIT_CODES[verdict]


def _profiles(args: argparse.Namespace) -> int:
    profiles = load_profiles()
    if args.name:
        if args.name not in profiles:
            return _fail(f"unknown profile: {args.name}", EXIT_USAGE)
        registry = build_registry()
        detail = {
            "name": args.name,
            **profiles[args.name],
            "adversaries": sorted(
                {registry.get(e).adversary.value for e in profiles[args.name]["evaluators"]}
            ),
        }
        print(json.dumps(detail, indent=2))
        return 0
    print(
        json.dumps(
            {
                name: {
                    "description": data.get("description", "").strip(),
                    "evaluators": len(data["evaluators"]),
                }
                for name, data in profiles.items()
            },
            indent=2,
        )
    )
    return 0


def _doctor() -> int:
    registry = build_registry()
    probe = environment_probe(registry.tools(registry.names()))
    unavailable = [name for name, row in probe["tools"].items() if not row.get("available")]
    probe["evaluators"] = registry.names()
    probe["unavailable"] = unavailable
    probe["note"] = (
        "Checks whose tooling is unavailable report UNAVAILABLE and never VERIFIED. An "
        "evaluation run on this machine will be correspondingly narrower."
    )
    print(json.dumps(probe, indent=2))
    return 0 if not unavailable else EXIT_CODES[Verdict.CONDITIONALLY_PROVEN]


def _read_bundle(args: argparse.Namespace) -> int:
    bundle = Bundle.load(find_bundle(args.bundle))
    result = bundle["result"]
    if args.command == "report":
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(render_report(result))
        return 0
    if args.command == "explain":
        print(
            json.dumps(
                {
                    "run_id": result["run_id"],
                    "verdict": result["verdict"],
                    "definition": VERDICT_DEFINITIONS[Verdict(result["verdict"])],
                    "deciding_rule": result["deciding_rule"],
                    "rationale": result["rationale"],
                    "criteria": result["criteria"],
                    "validation_modes": result["validation_modes"],
                    "limitations": result["limitations"],
                },
                indent=2,
            )
        )
        return 0
    print(
        json.dumps(
            {
                "integrity": "VERIFIED",
                "run_id": result["run_id"],
                "artifact": result["artifact"],
                "verdict": result["verdict"],
                "files": len(bundle["manifest"]["file_hashes"]),
                "implementation_hash": bundle["manifest"]["implementation_hash"],
                "path": bundle["path"],
            },
            indent=2,
        )
    )
    return EXIT_CODES[Verdict(result["verdict"])]


def _findings(args: argparse.Namespace) -> int:
    if args.ledger:
        rows: list[dict[str, Any]] = Ledger.open(args.ledger).entries(args.artifact)
    elif args.bundle:
        rows = Bundle.load(find_bundle(args.bundle))["findings"]
    else:
        return _fail("findings needs either a bundle path or --ledger", EXIT_USAGE)
    if args.severity:
        rows = [row for row in rows if row.get("severity") == args.severity.upper()]
    if args.state:
        rows = [row for row in rows if row.get("state") == args.state.upper()]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No findings match.")
        return 0
    for row in rows:
        print(
            f"{row.get('id', '?'):<14} {row.get('severity', '?'):<13} "
            f"{row.get('state', '?'):<22} {row.get('title', '')}"
        )
    return 0


def _reproduce(args: argparse.Namespace) -> int:
    bundle = Bundle.load(find_bundle(args.bundle))
    finding = _find(bundle, args.finding)
    config, _ = _load_config(args.target, args.config, [])
    outcome = replay(finding, args.target, config)
    payload = {"finding": finding["id"], **outcome.to_dict()}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{finding['id']}: {outcome.outcome}")
        print(f"  {outcome.reason}")
        for step in outcome.steps:
            mark = {True: "observed", False: "not observed", None: "setup"}[step.matched]
            print(f"  [{mark}] {step.description}")
    return 0 if outcome.outcome in {"CONFIRMED", "NOT_REPRODUCED"} else EXIT_USAGE


def _verify_fix(args: argparse.Namespace) -> int:
    bundle = Bundle.load(find_bundle(args.bundle))
    finding = _find(bundle, args.finding)
    config, _ = _load_config(args.target, args.config, [])
    ledger = Ledger.open(args.evidence_root)
    try:
        artifact, record = ledger.find_anywhere(finding["id"])
    except LedgerError:
        artifact, record = config.artifact, {}
    outcome = verify_fix(
        finding=finding,
        recorded_tree_digest=str(record.get("first_seen_tree_digest", "")),
        target_root=args.target,
        config=config,
        registry=build_registry(),
        evidence_root=args.evidence_root,
        allow_network=args.allow_network,
    )
    ledger = Ledger.open(args.evidence_root)
    try:
        ledger.record_state(
            artifact,
            finding["id"],
            FindingState(outcome.outcome),
            outcome.detail.get("run_id", ""),
            outcome.reason,
        )
        ledger.save()
    except LedgerError:
        pass
    payload = {"finding": finding["id"], "artifact": artifact, **outcome.to_dict()}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{finding['id']}: {outcome.outcome}")
        print(f"  {outcome.reason}")
        print(f"  re-evaluation: {outcome.detail.get('path', 'none')}")
    return 0 if outcome.outcome == FindingState.VERIFIED_FIXED.value else EXIT_CODES[Verdict.REJECT]


def _compare(args: argparse.Namespace) -> int:
    first, second = (Bundle.load(find_bundle(path))["result"] for path in args.bundles)
    ids = {f["id"] for f in first["findings"]}, {f["id"] for f in second["findings"]}
    print(
        json.dumps(
            {
                "artifact": [first["artifact"], second["artifact"]],
                "run_id": [first["run_id"], second["run_id"]],
                "commit": [
                    first["target"].get("commit", ""),
                    second["target"].get("commit", ""),
                ],
                "verdict": [first["verdict"], second["verdict"]],
                "resolved": sorted(ids[0] - ids[1]),
                "introduced": sorted(ids[1] - ids[0]),
                "persisting": sorted(ids[0] & ids[1]),
                "counts": [first["counts"], second["counts"]],
            },
            indent=2,
        )
    )
    return 0


def _handoff(args: argparse.Namespace) -> int:
    result = Bundle.load(find_bundle(args.bundle))["result"]
    if args.target == "verification-plan":
        name, content = "verification_plan.json", json.dumps(verification_plan(result), indent=2)
    else:
        name, content = render(result, args.target)
    if args.output:
        destination = args.output if args.output.suffix else args.output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
        print(json.dumps({"written": str(destination), "target": args.target}))
    else:
        print(content, end="")
    return 0


def _find(bundle: dict[str, Any], finding_id: str) -> dict[str, Any]:
    for finding in bundle["findings"]:
        if finding["id"] == finding_id:
            return finding
    known = ", ".join(sorted(f["id"] for f in bundle["findings"])) or "none"
    raise BundleError(f"{finding_id} is not in this bundle; it holds {known}")


def _fail(message: str, code: int) -> int:
    print(json.dumps({"error": message}), file=sys.stderr)
    return code


def _select_check(config: ProofConfig) -> list[str]:
    registry = build_registry()
    return [e.id for e in select(registry, config.profiles, config.adversaries)]


if __name__ == "__main__":
    sys.exit(main())
