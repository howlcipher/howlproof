"""research.claims: evaluate a howl.claim_bundle/v1 claim by claim.

A claim bundle is a directory holding `claims.json` plus the evidence files it names.
Everything inside is untrusted data. Nothing here executes evidence, follows its
instructions, or reaches the network.

Claim-level outcomes are SUPPORTED, REFUTED, INCONCLUSIVE, REQUIRES_EXTERNAL_VALIDATION
and ERROR. They map onto HowlProof's existing check statuses without widening what
VERIFIED means: only SUPPORTED is VERIFIED, and SUPPORTED requires a check the bundle
author grounded in advance plus evidence declared independent whose bytes still match
their registered digest. A citation, a quotation, a reachable URL or a passing unit
test never reaches SUPPORTED on its own.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import PurePosixPath
from typing import Any

from howlproof.model import (
    Adversary,
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    Mode,
    Severity,
)
from howlproof.registry import Context, Evaluator, Outcome, timed

SCHEMA = "howl.claim_bundle/v1"
BUNDLE_FILE = "claims.json"
CATEGORIES = ("EMPIRICAL", "TECHNICAL", "HYPOTHESIS", "VALUE_JUDGMENT")
CHECK_TYPES = ("fact_compare", "arithmetic")
OPS = ("eq", "approx", "lt", "le", "gt", "ge")
MAX_CLAIMS = 500
MAX_EXPONENT = 64

LIMITATION = (
    "compares author-grounded checks against evidence whose independence is as declared "
    "in the bundle and is not authenticated; establishes only the compared fact, not that "
    "a source is correct, current or representative"
)

#: Phrases that read like instructions to an agent. They are flagged for the record and
#: otherwise ignored: evidence text can never change a status.
INSTRUCTION_PATTERN = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)"
    r"|disregard (?:the |all )?(?:previous|prior|above)"
    r"|(?:you|assistant) (?:must|should) now"
    r"|system prompt|mark (?:every|all|this) (?:claim|claims) (?:as )?\w+"
    r"|\brm -rf\b|\bcurl [^|\n]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

_CURRENCY = {"$": "usd", "€": "eur", "£": "gbp"}
_SCALES = {
    "k": 10**3,
    "m": 10**6,
    "b": 10**9,
    "thousand": 10**3,
    "million": 10**6,
    "billion": 10**9,
}
_QUANTITY = re.compile(
    r"^\s*(?P<cur>[$€£])?\s*(?P<num>[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)\s*"
    r"(?P<scale>(?i:thousand|million|billion)|[kKMB](?![A-Za-z]))?\s*(?P<rest>.*?)\s*$"
)
_UNIT = re.compile(r"^(?:%|/?[a-z][a-z /]*)?$")


@dataclass(frozen=True)
class Quantity:
    value: Decimal
    unit: str


def parse_quantity(text: str) -> Quantity:
    """Parse a number with an optional currency, scale and unit. Refuse to guess."""
    if not isinstance(text, str) or not text.strip() or len(text) > 100:
        raise ValueError(f"cannot read a quantity from {text!r}")
    match = _QUANTITY.match(text)
    if not match:
        raise ValueError(f"cannot read a quantity from {text!r}")
    try:
        value = Decimal(match["num"].replace(",", ""))
    except InvalidOperation as bad:
        raise ValueError(f"cannot read a quantity from {text!r}") from bad
    if match["scale"]:
        value *= _SCALES[match["scale"].lower()]
    rest = re.sub(r"\s*per\s+", "/", match["rest"].strip().lower())
    rest = re.sub(r"\s*/\s*", "/", rest)
    if not _UNIT.match(rest):
        raise ValueError(f"cannot read the unit {match['rest']!r} in {text!r}")
    unit = _CURRENCY[match["cur"]] + rest if match["cur"] else rest
    return Quantity(value, unit)


def compare(observed: Quantity, op: str, expected: Quantity, tolerance: str) -> bool:
    """Whether `observed <op> expected`. Quantities in different units are not compared."""
    if op not in OPS:
        raise ValueError(f"unsupported comparison {op!r}; expected one of {', '.join(OPS)}")
    if observed.unit != expected.unit:
        raise ValueError(
            f"unit mismatch: observed {observed.unit or 'unitless'}, "
            f"expected {expected.unit or 'unitless'}"
        )
    delta = observed.value - expected.value
    if op == "eq":
        return delta == 0
    if op == "approx":
        slack = parse_quantity(tolerance)
        if slack.unit not in ("", expected.unit):
            raise ValueError(f"unit mismatch: tolerance {slack.unit} against {expected.unit}")
        return abs(delta) <= slack.value
    return {"lt": delta < 0, "le": delta <= 0, "gt": delta > 0, "ge": delta >= 0}[op]


def _arith(node: ast.AST) -> Fraction:
    if isinstance(node, ast.Expression):
        return _arith(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return Fraction(str(node.value))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        inner = _arith(node.operand)
        return inner if isinstance(node.op, ast.UAdd) else -inner
    if isinstance(node, ast.BinOp):
        left, right = _arith(node.left), _arith(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("division by zero")
            return left / right
        if isinstance(node.op, ast.Pow):
            if right.denominator != 1 or abs(right) > MAX_EXPONENT or abs(left) > 10**6:
                raise ValueError("exponent outside the permitted range")
            return left ** int(right)
    raise ValueError("only numbers and + - * / ** are permitted in an arithmetic check")


def evaluate_arithmetic(check: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a closed arithmetic grammar. No names, calls or attributes exist in it."""
    expression = check.get("expression")
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 200:
        raise ValueError("arithmetic check needs an expression of 1 to 200 characters")
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as bad:
        raise ValueError(f"arithmetic expression is not valid: {bad.msg}") from bad
    result = _arith(tree)
    value = Decimal(result.numerator) / Decimal(result.denominator)
    expected = parse_quantity(str(check.get("expected", "")))
    holds = compare(
        Quantity(value, ""), str(check.get("op", "")), expected, str(check.get("tolerance", "0"))
    )
    return holds, format(value.normalize(), "f")


def _fail(message: str) -> None:
    raise ValueError(message)


def validate_bundle(document: Any) -> None:
    """Raise ValueError naming the first structural problem and the field it concerns."""
    if not isinstance(document, dict):
        _fail("claims.json must be a JSON object")
    if document.get("schema") != SCHEMA:
        _fail(f"unsupported schema {document.get('schema')!r}; expected {SCHEMA!r}")
    for key in ("claims", "evidence", "candidate"):
        if key not in document:
            _fail(f"missing required field: {key}")
    if not isinstance(document["claims"], list) or len(document["claims"]) > MAX_CLAIMS:
        _fail(f"claims must be a list of at most {MAX_CLAIMS} entries")
    if not isinstance(document["evidence"], list):
        _fail("evidence must be a list")
    ids: set[str] = set()
    for index, entry in enumerate(document["evidence"]):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            _fail(f"evidence[{index}] needs a string id")
        if entry["id"] in ids:
            _fail(f"duplicate evidence id {entry['id']!r}")
        ids.add(entry["id"])
        path = entry.get("path")
        pure = PurePosixPath(path) if isinstance(path, str) and path else None
        if pure is None or pure.is_absolute() or ".." in pure.parts:
            _fail(f"evidence[{index}].path must be a relative path inside the bundle")
        if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
            _fail(f"evidence[{index}].sha256 must be a 64 character hex digest")
    seen: set[str] = set()
    for index, item in enumerate(document["claims"]):
        if not isinstance(item, dict) or not isinstance(item.get("claim_id"), str):
            _fail(f"claims[{index}] needs a string claim_id")
        if item["claim_id"] in seen:
            _fail(f"duplicate claim_id {item['claim_id']!r}")
        seen.add(item["claim_id"])
        if not isinstance(item.get("text"), str) or not item["text"].strip():
            _fail(f"claims[{index}].text must be a non-empty string")
        if item.get("category") not in CATEGORIES:
            _fail(
                f"claims[{index}].category {item.get('category')!r} is not one of "
                f"{', '.join(CATEGORIES)}"
            )
        refs = item.get("evidence_refs", [])
        if not isinstance(refs, list):
            _fail(f"claims[{index}].evidence_refs must be a list")
        for ref in refs:
            if ref not in ids:
                _fail(f"claims[{index}].evidence_refs references unknown evidence id {ref!r}")
        check = item.get("check")
        if check is not None and (not isinstance(check, dict) or "type" not in check):
            _fail(f"claims[{index}].check must be an object with a type")


@dataclass
class Loaded:
    entry: dict[str, Any]
    integrity: str
    facts: dict[str, str]
    flags: list[str]
    note: str = ""

    @property
    def independent(self) -> bool:
        return self.entry.get("independent") is True


def _load_evidence(context: Context, entry: dict[str, Any]) -> Loaded:
    path = entry["path"]
    if not context.target.exists(path):
        return Loaded(entry, "missing", {}, [], "evidence file is absent")
    raw = context.target.read_bytes(path)
    if hashlib.sha256(raw).hexdigest() != entry["sha256"].lower():
        return Loaded(entry, "mismatch", {}, [], "bytes differ from the registered sha256")
    try:
        body = json.loads(raw.decode("utf-8"))
        facts_raw = body.get("facts", {}) if isinstance(body, dict) else {}
        text = body.get("text", "") if isinstance(body, dict) else ""
        facts = (
            {str(k): str(v) for k, v in facts_raw.items()} if isinstance(facts_raw, dict) else {}
        )
        note = "" if isinstance(body, dict) else "evidence file is not a JSON object"
    except (UnicodeDecodeError, ValueError) as bad:
        return Loaded(entry, "ok", {}, [], f"evidence file is unreadable: {bad}")
    haystack = " ".join([str(text), *facts.values()])
    flags = sorted({m.group(0).lower() for m in INSTRUCTION_PATTERN.finditer(haystack)})
    return Loaded(entry, "ok", facts, flags, note)


def _date(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


class ResearchClaims(Evaluator):
    """Evaluate each claim in a claim bundle on its own."""

    id = "research.claims"
    version = "1"
    adversary = Adversary.FUNCTIONAL

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.target.exists(BUNDLE_FILE) and "howl.claim_bundle" in context.target.read_text(
            BUNDLE_FILE, 65_536
        ):
            return True, ""
        return False, "no claims.json claim bundle present"

    def evaluate(self, context: Context) -> Outcome:
        started = time.monotonic()
        raw = context.target.read_bytes(BUNDLE_FILE)
        try:
            document = json.loads(raw.decode("utf-8"))
            validate_bundle(document)
        except (ValueError, UnicodeDecodeError) as bad:
            return Outcome(checks=[self.errored(f"invalid claim bundle: {bad}", suffix="bundle")])

        digest = hashlib.sha256(raw).hexdigest()
        candidate = document["candidate"] if isinstance(document["candidate"], dict) else {}
        candidate_id = str(candidate.get("candidate_id", ""))
        loaded = {e["id"]: _load_evidence(context, e) for e in document["evidence"]}
        outcome = Outcome()

        results = []
        for item in document["claims"]:
            result = self._claim(item, loaded)
            result.update(bundle_sha256=digest, candidate_id=candidate_id)
            results.append(result)
        ref = context.save_evidence_json(self.id, "claim_results.json", results)

        broken = sorted(i for i, e in loaded.items() if e.integrity != "ok")
        if not document["claims"]:
            bundle_check = self.unavailable("the bundle contains no claims", suffix="bundle")
        elif broken:
            bundle_check = self._result(
                CheckStatus.FAILED,
                f"evidence integrity failed for {', '.join(broken)}",
                "evidence that fails its digest is excluded from every claim",
                "bundle",
                "",
                [ref],
                {
                    "bundle_sha256": digest,
                    "candidate_id": candidate_id,
                    "integrity": {i: loaded[i].integrity for i in broken},
                },
                timed(started),
                Mode.REAL,
            )
            for evidence_id in broken:
                outcome.findings.append(self._integrity_finding(loaded[evidence_id]))
        else:
            bundle_check = self.verified(
                f"claim bundle is well formed and {len(loaded)} evidence file(s) match their "
                "registered digests",
                "establishes structure and byte integrity only; no claim is verified by this check",
                suffix="bundle",
                evidence_refs=[ref],
                detail={
                    "bundle_sha256": digest,
                    "candidate_id": candidate_id,
                    "claims": len(document["claims"]),
                },
                duration_ms=timed(started),
            )
        outcome.checks.append(bundle_check)

        for index, result in enumerate(results, start=1):
            outcome.checks.append(self._check(index, result, ref))
            if result["claim_status"] == "REFUTED":
                outcome.findings.append(self._refuted_finding(index, result))
        return outcome

    # -- one claim ------------------------------------------------------------

    def _claim(self, item: dict[str, Any], loaded: dict[str, Loaded]) -> dict[str, Any]:
        refs = list(item.get("evidence_refs", []))
        considered = [
            {
                "id": r,
                "integrity": loaded[r].integrity,
                "independent": loaded[r].independent,
                "source_type": loaded[r].entry.get("source_type"),
                "relation": "unexamined",
                "published_at": loaded[r].entry.get("published_at"),
                "sha256": loaded[r].entry["sha256"],
            }
            for r in refs
        ]
        flags = sorted({f for r in refs for f in loaded[r].flags})
        result: dict[str, Any] = {
            "claim_id": item["claim_id"],
            "category": item["category"],
            "assumption": bool(item.get("assumption")),
            "method": "none",
            "claim_status": "INCONCLUSIVE",
            "explanation": "",
            "evidence_considered": considered,
            "conflicts": [],
            "untrusted_flags": flags,
            "not_checked": [],
        }
        check = item.get("check")
        category = item["category"]

        if category == "VALUE_JUDGMENT":
            return self._set(
                result,
                "REQUIRES_EXTERNAL_VALIDATION",
                "value judgments and forecasts cannot be established by an "
                "automated check, and citations do not change that",
                ["the truth of the judgment or forecast"],
            )
        if check is None:
            missing = "no evidence cited and " if not refs else ""
            return self._set(
                result,
                "INCONCLUSIVE",
                f"{missing}no grounded check was supplied for this claim; a "
                "citation or quotation is not proof, and any verification plan "
                "stays proposed until the author grounds it",
                ["whether the cited sources establish the claim"],
            )
        kind = check["type"]
        result["method"] = kind if isinstance(kind, str) else "unknown"
        if kind not in CHECK_TYPES:
            result["claim_status"] = "INCONCLUSIVE"
            result["unsupported_evaluator"] = str(kind)
            result["explanation"] = (
                f"evaluator {kind!r} is not available in research.claims/v1 "
                f"(supported: {', '.join(CHECK_TYPES)}); nothing was checked"
            )
            return result
        try:
            if kind == "arithmetic":
                self._arithmetic(result, check)
            else:
                self._fact_compare(result, check, refs, loaded)
        except ValueError as bad:
            self._set(result, "ERROR", f"malformed check: {bad}", [])
        if result["claim_status"] in ("SUPPORTED", "REFUTED") and (
            category == "HYPOTHESIS" or result["assumption"]
        ):
            self._set(
                result,
                "INCONCLUSIVE",
                "a research hypothesis or stated assumption stays unresolved until "
                f"investigated; the check outcome was {result['claim_status']}",
                ["the hypothesis itself"],
            )
        return result

    @staticmethod
    def _set(result: dict[str, Any], status: str, why: str, unchecked: list[str]) -> dict[str, Any]:
        result.update(claim_status=status, explanation=why, not_checked=unchecked)
        return result

    def _arithmetic(self, result: dict[str, Any], check: dict[str, Any]) -> None:
        holds, value = evaluate_arithmetic(check)
        if result["category"] != "TECHNICAL":
            self._set(
                result,
                "INCONCLUSIVE",
                "arithmetic establishes internal consistency only, not an empirical claim",
                ["the empirical truth of the claim"],
            )
            return
        verdict = "SUPPORTED" if holds else "REFUTED"
        self._set(
            result,
            verdict,
            f"{check['expression']} = {value}; expected {check['op']} {check['expected']}"
            f" -> {'holds' if holds else 'does not hold'}",
            ["inputs of the expression were taken from the claim, not independently sourced"],
        )

    def _fact_compare(self, result, check, refs, loaded) -> None:
        fact = check.get("fact")
        if not isinstance(fact, str) or not fact:
            raise ValueError("fact_compare needs a fact name")
        expected = parse_quantity(str(check.get("expected", "")))
        op, tolerance = str(check.get("op", "")), str(check.get("tolerance", "0"))
        compare(expected, op, expected, tolerance)  # validates op and tolerance units early
        if not refs:
            self._set(
                result,
                "INCONCLUSIVE",
                "no evidence cited for this claim",
                ["any evidence for or against the claim"],
            )
            return
        sides: dict[str, list[str]] = {"supports": [], "contradicts": []}
        for row in result["evidence_considered"]:
            source = loaded[row["id"]]
            if source.integrity != "ok":
                row["relation"] = "unusable"
                row["note"] = f"integrity {source.integrity}: {source.note}"
            elif fact not in source.facts:
                row["relation"] = "irrelevant"
                row["note"] = f"the evidence has no fact named {fact!r}"
            else:
                row["observed"] = source.facts[fact]
                try:
                    holds = compare(parse_quantity(source.facts[fact]), op, expected, tolerance)
                except ValueError as bad:
                    row["relation"], row["note"] = "incomparable", str(bad)
                    continue
                row["relation"] = "supports" if holds else "contradicts"
            if row["relation"] in sides and row["independent"]:
                sides[row["relation"]].append(row["id"])
        pro, con = sides["supports"], sides["contradicts"]
        if pro and con:
            involved = sorted(pro + con)
            dates = {i: _date(loaded[i].entry.get("published_at")) for i in involved}
            newer = None
            stamps = [(d, i) for i, d in dates.items() if d is not None]
            if len(stamps) == len(involved):
                newer = max(stamps)[1]
            result["conflicts"] = [
                {"kind": "supports_vs_contradicts", "evidence": involved, "newer": newer}
            ]
            self._set(
                result,
                "INCONCLUSIVE",
                f"independent evidence conflicts ({', '.join(pro)} supports, "
                f"{', '.join(con)} contradicts); a newer source is not a resolution",
                ["which conflicting source is correct"],
            )
        elif con:
            self._set(
                result,
                "REFUTED",
                f"independent evidence {', '.join(con)} contradicts {fact} {op} "
                f"{check['expected']}",
                ["whether the contradicting source is itself correct"],
            )
        elif pro:
            self._set(
                result,
                "SUPPORTED",
                f"independent evidence {', '.join(pro)} satisfies {fact} {op} {check['expected']}",
                ["whether the source is correct, current or representative"],
            )
        elif any(
            r["relation"] in ("supports", "contradicts") for r in result["evidence_considered"]
        ):
            self._set(
                result,
                "INCONCLUSIVE",
                "matching evidence exists but none is declared independent; evidence that "
                "is not independent cannot support or refute a claim",
                ["independent corroboration"],
            )
        else:
            self._set(
                result,
                "INCONCLUSIVE",
                "no cited evidence is both usable and relevant to the compared fact "
                "("
                + "; ".join(f"{r['id']}: {r['relation']}" for r in result["evidence_considered"])
                + ")",
                ["whether the cited sources address the claim"],
            )

    # -- mapping to the existing result model ---------------------------------------

    def _check(self, index: int, result: dict[str, Any], ref: str) -> CheckResult:
        status = result["claim_status"]
        mapped = {
            "SUPPORTED": CheckStatus.VERIFIED,
            "REFUTED": CheckStatus.FAILED,
            "INCONCLUSIVE": CheckStatus.UNAVAILABLE,
            "ERROR": CheckStatus.ERROR,
            "REQUIRES_EXTERNAL_VALIDATION": CheckStatus.SKIPPED,
        }[status]
        reason = (
            "" if mapped in (CheckStatus.VERIFIED, CheckStatus.FAILED) else result["explanation"]
        )
        if result.get("unsupported_evaluator"):
            reason = result["explanation"]
        return self._result(
            mapped,
            f"claim {result['claim_id']}: {status}",
            LIMITATION
            if status in ("SUPPORTED", "REFUTED")
            else "nothing was established about this claim",
            f"c{index:03d}",
            reason,
            [ref],
            result,
            0,
            Mode.REAL,
        )

    def _refuted_finding(self, index: int, result: dict[str, Any]) -> Finding:
        return self.finding(
            title=f"Claim {result['claim_id']} refuted by independent evidence",
            category="correctness",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary=f"claim {result['claim_id']}: {result['explanation']}",
            evidence=json.dumps(result["evidence_considered"], indent=2, sort_keys=True)[:2000],
            remediation="Revise or withdraw the claim, or supply independent evidence that "
            "resolves the contradiction.",
            rule="research.claims.refuted",
            suffix=f"c{index:03d}",
        )

    def _integrity_finding(self, source: Loaded) -> Finding:
        return self.finding(
            title=f"Evidence integrity failure: {source.entry['id']}",
            category="correctness",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary=f"evidence {source.entry['id']} is {source.integrity}: {source.note}",
            evidence=json.dumps(
                {"path": source.entry["path"], "expected_sha256": source.entry["sha256"]},
                sort_keys=True,
            ),
            remediation="Re-register the evidence from its original source and re-export.",
            rule="research.claims.integrity",
            suffix="bundle",
        )


EVALUATORS: list[Evaluator] = [ResearchClaims()]
