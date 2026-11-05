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

Trust model (`howl.evidence_trust/v1`, see `howlproof.trust`): declarations in the bundle
(`independent`, `source_type`, `represents_observed_reality`, a URL, a digest) are *claimed
provenance* and never confer authority. A sourced claim (EMPIRICAL, or TECHNICAL via
`fact_compare`) reaches SUPPORTED or REFUTED only on evidence whose source bytes were
observed by an acquisition event in the operator's acquisition store, in which the compared
fact and the claim's subject terms actually appear. Everything else keeps the arithmetic of
the supplied numbers in `check_outcome` and reports INCONCLUSIVE. Each result carries an
`assurance` record that keeps check, integrity, origin, relevance, methodology,
corroboration and real-world truth apart.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import PurePosixPath
from typing import Any

from howlproof.acquire import AcquisitionStore
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
from howlproof.trust import (
    AGENT_AUTHORED_TYPES,
    ORIGIN_RANK,
    REAL_ORIGINS,
    SYNTHETIC_AUTHORSHIP,
    TRUST_MODEL,
    classify_reference,
    locate_phrase,
    locate_value,
    locations_agree,
    source_text,
)

SCHEMA = "howl.claim_bundle/v1"
BUNDLE_FILE = "claims.json"
CATEGORIES = ("EMPIRICAL", "TECHNICAL", "HYPOTHESIS", "VALUE_JUDGMENT")
CHECK_TYPES = ("fact_compare", "arithmetic", "text_presence")
NATURES = ("measurement", "reported_fact")
MAX_SOURCE_CHARS = 2_000_000
#: Retained source text across all evidence in one bundle; overflow is unverifiable.
MAX_TOTAL_SOURCE_CHARS = 32_000_000
MAX_EVIDENCE = 200
MIN_METHODOLOGY_CHARS = 25
MIN_METHODOLOGY_WORDS = 4
OPS = ("eq", "approx", "lt", "le", "gt", "ge")
MAX_CLAIMS = 500
MAX_EXPONENT = 64

LIMITATION = (
    "compares author-grounded checks against evidence; sourced claims need an observed "
    "acquisition in which the fact and subject terms appear. Establishes only the compared "
    "proposition within its stated scope, not that a source is correct, current, "
    "representative or independent in origin"
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
    if not isinstance(document["evidence"], list) or len(document["evidence"]) > MAX_EVIDENCE:
        _fail(f"evidence must be a list of at most {MAX_EVIDENCE} entries")
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
    #: Text of the evidence record itself (what the submitter wrote); not the source.
    record_text: str = ""
    #: Text of the acquired source bytes, present only for an observed acquisition.
    source: str | None = None
    #: Orthogonal trust dimensions that do not depend on the claim being evaluated.
    trust: dict[str, Any] = field(default_factory=dict)

    @property
    def independent(self) -> bool:
        return self.entry.get("independent") is True

    def searchable(self, synthetic: bool) -> str | None:
        """The text a claim may be checked against: the acquired source, or for a declared
        synthetic fixture only, the fixture's own text. Never an unobserved real-world record."""
        if self.source is not None:
            return self.source
        if synthetic and self.integrity == "ok":
            return self.record_text
        return None


def _bundle_authorship(document: dict[str, Any]) -> str:
    authorship = document.get("authorship")
    return str(authorship.get("kind", "UNKNOWN")) if isinstance(authorship, dict) else "UNKNOWN"


def _observe(context: Context, entry: dict[str, Any]) -> tuple[str, dict[str, Any], bytes]:
    """Verify an evidence entry's acquisition pointer against the operator's store."""
    pointer = entry.get("acquisition")
    if pointer is None:
        return "NONE", {}, b""
    if not isinstance(pointer, dict):
        return "POINTER_MALFORMED", {}, b""
    store_root = getattr(context, "acquisition_store", None)
    if store_root is None:
        return "NO_STORE", {}, b""
    verified = AcquisitionStore(store_root).verify(pointer.get("id"), pointer.get("content_sha256"))
    if verified.status != "OBSERVED":
        return verified.status, verified.record or {}, b""
    record = verified.record or {}
    ref = entry.get("source_ref")
    has_location = any(
        record.get(k) for k in ("requested_url", "observed_url", "claimed_source_url")
    )
    if ref and has_location and not locations_agree(str(ref), record):
        return "SOURCE_REF_MISMATCH", record, b""
    return "OBSERVED", record, verified.raw


def _origin(
    entry: dict[str, Any], authorship: str, acquisition: str, record: dict[str, Any]
) -> str:
    if entry.get("source_type") in AGENT_AUTHORED_TYPES:
        return "AGENT_AUTHORED"
    if acquisition == "OBSERVED":
        return (
            "OPERATOR_ATTESTED_FILE"
            if record.get("kind") == "OPERATOR_FILE"
            else ("OBSERVED_ACQUISITION")
        )
    if authorship in SYNTHETIC_AUTHORSHIP:
        return "SYNTHETIC_FIXTURE"
    if acquisition != "NONE":
        return "UNVERIFIABLE"
    kind = classify_reference(str(entry.get("source_ref", "")))
    return {"PLACEHOLDER": "PLACEHOLDER", "URL": "CLAIMED_ONLY", "FREE_TEXT": "CLAIMED_ONLY"}[kind]


def _load_evidence(
    context: Context,
    entry: dict[str, Any],
    authorship: str = "UNKNOWN",
    budget: list[int] | None = None,
) -> Loaded:
    path = entry["path"]
    claimed = {
        "source_type": entry.get("source_type"),
        "independent": entry.get("independent") is True,
        "represents_observed_reality": entry.get("represents_observed_reality") is True,
        "source_ref": entry.get("source_ref"),
        "produced_by": entry.get("produced_by"),
        "note": "as declared by the bundle author; not verified provenance",
    }
    acquisition, record, raw_source = _observe(context, entry)
    if acquisition == "OBSERVED" and budget is not None:
        if len(raw_source) > budget[0]:
            acquisition, raw_source = "SOURCE_BUDGET_EXCEEDED", b""
        else:
            budget[0] -= len(raw_source)
    trust: dict[str, Any] = {
        "integrity": "ok",
        "claimed_provenance": claimed,
        "acquisition": acquisition,
        "acquisition_id": (entry.get("acquisition") or {}).get("id")
        if isinstance(entry.get("acquisition"), dict)
        else None,
        "acquisition_kind": record.get("kind"),
        "acquisition_method": record.get("method"),
        "retrieved_at": record.get("retrieved_at"),
        "observed_location": record.get("observed_url") or record.get("claimed_source_url"),
        "content_sha256": record.get("content_sha256") if acquisition == "OBSERVED" else None,
        "reference_class": classify_reference(str(entry.get("source_ref", ""))),
        "source_origin": _origin(entry, authorship, acquisition, record),
        "evidence_form": "EXTRACT_OF_ACQUIRED_SOURCE"
        if acquisition == "OBSERVED"
        else "SUBMITTED_EXTRACT",
    }
    if not context.target.exists(path):
        trust["integrity"] = "missing"
        return Loaded(entry, "missing", {}, [], "evidence file is absent", trust=trust)
    raw = context.target.read_bytes(path)
    if hashlib.sha256(raw).hexdigest() != entry["sha256"].lower():
        trust["integrity"] = "mismatch"
        return Loaded(
            entry, "mismatch", {}, [], "bytes differ from the registered sha256", trust=trust
        )
    source = None
    if acquisition == "OBSERVED":
        source = source_text(raw_source, record.get("content_type"))[:MAX_SOURCE_CHARS]
    try:
        body = json.loads(raw.decode("utf-8"))
        facts_raw = body.get("facts", {}) if isinstance(body, dict) else {}
        text = body.get("text", "") if isinstance(body, dict) else ""
        facts = (
            {str(k): str(v) for k, v in facts_raw.items()} if isinstance(facts_raw, dict) else {}
        )
        note = "" if isinstance(body, dict) else "evidence file is not a JSON object"
    except (UnicodeDecodeError, ValueError) as bad:
        return Loaded(entry, "ok", {}, [], f"evidence file is unreadable: {bad}", trust=trust)
    haystack = " ".join([str(text), *facts.values(), source or ""])
    flags = sorted({m.group(0).lower() for m in INSTRUCTION_PATTERN.finditer(haystack)})
    return Loaded(entry, "ok", facts, flags, note, str(text), source, trust)


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
        authorship = _bundle_authorship(document)
        budget = [MAX_TOTAL_SOURCE_CHARS]
        loaded = {
            e["id"]: _load_evidence(context, e, authorship, budget) for e in document["evidence"]
        }
        outcome = Outcome()

        results = []
        for item in document["claims"]:
            result = self._claim(item, loaded, authorship)
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
                    "trust_model": TRUST_MODEL,
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

    @staticmethod
    def _row(source: Loaded) -> dict[str, Any]:
        entry = source.entry
        return {
            "id": entry["id"],
            "integrity": source.integrity,
            "independent": source.independent,
            "source_type": entry.get("source_type"),
            "relation": "unexamined",
            "published_at": entry.get("published_at"),
            "sha256": entry["sha256"],
            "claimed_provenance": source.trust["claimed_provenance"],
            "trust": {
                **{k: v for k, v in source.trust.items() if k != "claimed_provenance"},
                "facts_located_in_source": None,
                "relevance": "NOT_EVALUATED",
                "methodology": "NOT_EVALUATED",
            },
            "eligible": False,
        }

    def _claim(
        self, item: dict[str, Any], loaded: dict[str, Loaded], authorship: str = "UNKNOWN"
    ) -> dict[str, Any]:
        synthetic = authorship in SYNTHETIC_AUTHORSHIP
        refs = list(item.get("evidence_refs", []))
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else None
        result: dict[str, Any] = {
            "claim_id": item["claim_id"],
            "category": item["category"],
            "assumption": bool(item.get("assumption")),
            "method": "none",
            "claim_status": "INCONCLUSIVE",
            "explanation": "",
            "evidence_considered": [self._row(loaded[r]) for r in refs],
            "conflicts": [],
            "untrusted_flags": sorted({f for r in refs for f in loaded[r].flags}),
            "not_checked": [],
            "checked_proposition": str(item.get("checked_proposition") or item["text"]),
            "scope": scope,
            "scope_limited": scope is not None
            and scope.get("extent") not in (None, "FULL_QUESTION"),
            "broader_question": "NOT_EVALUATED",
            "check_outcome": None,
            "check_passed": None,
        }
        self._decide(result, item, loaded, refs, synthetic)
        result["assurance"] = self._assurance(result, synthetic)
        return result

    def _decide(
        self,
        result: dict[str, Any],
        item: dict[str, Any],
        loaded: dict[str, Loaded],
        refs: list[str],
        synthetic: bool,
    ) -> None:
        check = item.get("check")
        category = item["category"]
        if category == "VALUE_JUDGMENT":
            self._set(
                result,
                "REQUIRES_EXTERNAL_VALIDATION",
                "value judgments and forecasts cannot be established by an "
                "automated check, and citations do not change that",
                ["the truth of the judgment or forecast"],
            )
            return
        if check is None:
            missing = "no evidence cited and " if not refs else ""
            self._set(
                result,
                "INCONCLUSIVE",
                f"{missing}no grounded check was supplied for this claim; a "
                "citation or quotation is not proof, and any verification plan "
                "stays proposed until the author grounds it",
                ["whether the cited sources establish the claim"],
            )
            return
        kind = check["type"]
        result["method"] = kind if isinstance(kind, str) else "unknown"
        if kind not in CHECK_TYPES:
            result["claim_status"] = "INCONCLUSIVE"
            result["unsupported_evaluator"] = str(kind)
            result["explanation"] = (
                f"evaluator {kind!r} is not available in research.claims/v1 "
                f"(supported: {', '.join(CHECK_TYPES)}); nothing was checked"
            )
            return
        try:
            if kind == "arithmetic":
                self._arithmetic(result, check)
            elif kind == "text_presence":
                self._text_presence(result, check, item, refs, loaded, synthetic)
            else:
                self._fact_compare(result, check, item, refs, loaded, synthetic)
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
        result.update(check_outcome=verdict, check_passed=holds)
        self._set(
            result,
            verdict,
            f"{check['expression']} = {value}; expected {check['op']} {check['expected']}"
            f" -> {'holds' if holds else 'does not hold'}",
            ["inputs of the expression were taken from the claim, not independently sourced"],
        )

    # -- is a piece of evidence usable for this claim? ---------------------------------

    @staticmethod
    def _origin_reasons(row: dict[str, Any]) -> list[str]:
        origin = row["trust"]["source_origin"]
        if origin in REAL_ORIGINS:
            return []
        return [
            {
                "CLAIMED_ONLY": "no acquisition record: source_ref is a claim, not an observation",
                "PLACEHOLDER": "source_ref is a placeholder and no acquisition record exists",
                "UNVERIFIABLE": f"acquisition could not be verified ({row['trust']['acquisition']})",
                "AGENT_AUTHORED": "evidence is agent-authored "
                f"({row['source_type']}), not a primary source",
                "SYNTHETIC_FIXTURE": "evidence is a synthetic fixture, not a real-world source",
                "NONE": "no source reference or acquisition recorded",
            }[origin]
        ]

    @staticmethod
    def _subject_relevance(row: dict[str, Any], item: dict[str, Any], text: str) -> list[str]:
        terms = item.get("subject_terms")
        terms = (
            [t for t in terms if isinstance(t, str) and t.strip()]
            if isinstance(terms, list)
            else []
        )
        if not terms:
            row["trust"]["relevance"] = "NOT_ESTABLISHED"
            return [
                "claim lists no subject_terms, so relevance to the source cannot be established"
            ]
        absent = [t for t in terms if not locate_phrase(t, text)]
        row["trust"]["relevance"] = "NOT_ESTABLISHED" if absent else "STRUCTURAL_MATCH"
        return [f"subject term(s) {absent} not found in the acquired source"] if absent else []

    def _qualify(
        self,
        row: dict[str, Any],
        source: Loaded,
        item: dict[str, Any],
        fact: str,
        nature: str,
        synthetic: bool,
    ) -> None:
        """Decide whether this evidence may carry a SUPPORTED/REFUTED for this claim."""
        reasons = [] if source.independent else ["not declared independent"]
        if not synthetic:
            reasons += self._origin_reasons(row)
            if row["trust"]["source_origin"] in REAL_ORIGINS and source.source is not None:
                located = locate_value(source.facts[fact], source.source)
                row["trust"]["facts_located_in_source"] = located
                if not located:
                    reasons.append(
                        f"fact value {source.facts[fact]!r} not found in the acquired source"
                    )
                reasons += self._subject_relevance(row, item, source.source)
                if nature == "reported_fact":
                    row["trust"]["methodology"] = "NOT_REQUIRED"
                else:
                    quote = source.entry.get("methodology_quote")
                    recorded = (
                        isinstance(quote, str)
                        and len(quote.strip()) >= MIN_METHODOLOGY_CHARS
                        and len(quote.split()) >= MIN_METHODOLOGY_WORDS
                        and locate_phrase(quote, source.source)
                    )
                    row["trust"]["methodology"] = "RECORDED" if recorded else "NOT_RECORDED"
                    if not recorded:
                        reasons.append(
                            "no methodology recorded: a quantitative measurement needs a "
                            f"methodology_quote of at least {MIN_METHODOLOGY_WORDS} words that "
                            "appears in the acquired source"
                        )
        row["eligible"] = not reasons
        row["ineligible_reasons"] = reasons

    # -- fact_compare --------------------------------------------------------------------

    def _fact_compare(self, result, check, item, refs, loaded, synthetic) -> None:
        fact = check.get("fact")
        if not isinstance(fact, str) or not fact:
            raise ValueError("fact_compare needs a fact name")
        nature = check.get("nature", "measurement")
        if nature not in NATURES:
            raise ValueError(f"nature {nature!r} is not one of {', '.join(NATURES)}")
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
                self._qualify(row, source, item, fact, nature, synthetic)
        rows = result["evidence_considered"]

        def pick(relation: str, only_eligible: bool) -> list[str]:
            return [
                r["id"]
                for r in rows
                if r["relation"] == relation
                and r["independent"]
                and (r["eligible"] or not only_eligible)
            ]

        pro, con = pick("supports", False), pick("contradicts", False)
        elig_pro, elig_con = pick("supports", True), pick("contradicts", True)
        claimed = f"{fact} {op} {check['expected']}"
        if elig_pro or elig_con:
            if pro and con:
                self._conflict(result, rows, pro, con)
            elif elig_con:
                result.update(check_outcome="REFUTED", check_passed=False)
                self._set(
                    result,
                    "REFUTED",
                    f"evidence {', '.join(elig_con)} contradicts {claimed}",
                    ["whether the contradicting source is itself correct"],
                )
            else:
                result.update(check_outcome="SUPPORTED", check_passed=True)
                self._set(
                    result,
                    "SUPPORTED",
                    f"evidence {', '.join(elig_pro)} satisfies {claimed}",
                    ["whether the source is correct, current or representative"],
                )
            return
        if pro and con:
            self._conflict(result, rows, pro, con)
        elif pro or con:
            outcome = "SUPPORTED" if pro else "REFUTED"
            result.update(check_outcome=outcome, check_passed=bool(pro))
            why = "; ".join(
                f"{r['id']}: {' and '.join(r['ineligible_reasons'])}"
                for r in rows
                if r["relation"] in ("supports", "contradicts")
            )
            self._set(
                result,
                "INCONCLUSIVE",
                f"the supplied evidence {'satisfies' if pro else 'contradicts'} {claimed}, but "
                f"it cannot be treated as verified: {why}",
                [
                    "whether the supplied numbers come from an authentic source",
                    "real-world truth",
                ],
            )
        elif any(r["relation"] in ("supports", "contradicts") for r in rows):
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
                "(" + "; ".join(f"{r['id']}: {r['relation']}" for r in rows) + ")",
                ["whether the cited sources address the claim"],
            )

    def _conflict(self, result, rows, pro: list[str], con: list[str]) -> None:
        involved = sorted(pro + con)
        dates = {r["id"]: _date(r["published_at"]) for r in rows if r["id"] in involved}
        stamps = [(d, i) for i, d in dates.items() if d is not None]
        newer = max(stamps)[1] if len(stamps) == len(involved) else None
        result["conflicts"] = [
            {"kind": "supports_vs_contradicts", "evidence": involved, "newer": newer}
        ]
        self._set(
            result,
            "INCONCLUSIVE",
            f"evidence conflicts ({', '.join(pro)} supports, {', '.join(con)} contradicts); "
            "a newer source is not a resolution",
            ["which conflicting source is correct"],
        )

    # -- text_presence: a deliberately narrow check ----------------------------------------

    def _text_presence(self, result, check, item, refs, loaded, synthetic) -> None:
        term, expect = check.get("term"), check.get("expect", "present")
        if not isinstance(term, str) or not term.strip() or len(term) > 200:
            raise ValueError("text_presence needs a term of 1 to 200 characters")
        if expect not in ("present", "absent"):
            raise ValueError("text_presence expect must be 'present' or 'absent'")
        result["scope_limited"] = True
        if not refs:
            self._set(result, "INCONCLUSIVE", "no evidence cited for this claim", ["any evidence"])
            return
        for row in result["evidence_considered"]:
            source = loaded[row["id"]]
            text = source.searchable(synthetic)
            if source.integrity != "ok":
                row["relation"], row["note"] = "unusable", f"integrity {source.integrity}"
                continue
            reasons = [] if synthetic else self._origin_reasons(row)
            if not reasons and text is None:
                reasons = ["no source text is available"]
            if not reasons and not synthetic:
                reasons = self._subject_relevance(row, item, text or "")
            row["eligible"], row["ineligible_reasons"] = not reasons, reasons
            if reasons:
                row["relation"], row["note"] = "unverified", "; ".join(reasons)
            else:
                row["relation"] = "contains" if locate_phrase(term, text or "") else "lacks"
        rows = result["evidence_considered"]
        decided = [r for r in rows if r["relation"] in ("contains", "lacks")]
        result["not_checked"] = [
            (
                "whether the feature or behaviour exists outside the checked artifact(s); "
                "absence from a document is not absence from the project"
            ),
            "whether the artifact's statements are true",
        ]
        if not decided:
            self._set(
                result,
                "INCONCLUSIVE",
                "no cited artifact could be searched: "
                + "; ".join(f"{r['id']}: {r.get('note', r['relation'])}" for r in rows),
                result["not_checked"],
            )
            return
        found = [r["id"] for r in decided if r["relation"] == "contains"]
        lacking = [r["id"] for r in decided if r["relation"] == "lacks"]
        if found and lacking:
            involved = sorted(found + lacking)
            dates = {r["id"]: _date(r["published_at"]) for r in decided}
            stamps = [(d, i) for i, d in dates.items() if d is not None]
            result["conflicts"] = [
                {
                    "kind": "artifacts_disagree",
                    "contains": sorted(found),
                    "lacks": sorted(lacking),
                    "evidence": involved,
                    "newer": max(stamps)[1] if len(stamps) == len(decided) else None,
                }
            ]
        holds = bool(found) if expect == "present" else not found
        subject = [t for t in item.get("subject_terms") or [] if isinstance(t, str)]
        elsewhere = sorted(
            i
            for i, other in loaded.items()
            if i not in refs
            and other.integrity == "ok"
            and (other_text := other.searchable(synthetic)) is not None
            and locate_phrase(term, other_text)
            # only artifacts about the same subject count as related context
            and (synthetic or (subject and all(locate_phrase(t, other_text) for t in subject)))
        )
        result["also_found_in"] = elsewhere
        result.update(check_outcome="SUPPORTED" if holds else "REFUTED", check_passed=holds)
        where = ", ".join(r["id"] for r in decided)
        if not item.get("checked_proposition"):
            # Never echo a broader claim as if it were what was checked.
            result["checked_proposition"] = (
                f"The cited artifact(s) {where} "
                f"{'contain' if expect == 'present' else 'do not contain'} the text {term!r}"
            )
        note = (
            f"; the term does appear in other bundle evidence ({', '.join(elsewhere)}), so the "
            "broader question is open"
            if elsewhere and not found
            else ""
        )
        self._set(
            result,
            "SUPPORTED" if holds else "REFUTED",
            f"{term!r} is {'found' if found else 'not found'} in {where} "
            f"(expected {expect}); this concerns only the checked artifact(s){note}",
            result["not_checked"],
        )

    # -- the assurance record --------------------------------------------------------------

    def _assurance(self, result: dict[str, Any], synthetic: bool) -> dict[str, Any]:
        rows = result["evidence_considered"]
        method = result["method"]
        sourced = method in ("fact_compare", "text_presence")
        # Origin and integrity describe evidence a check actually examined. A forecast, a
        # claim with no check, or arithmetic never reads its citations, so reporting their
        # origin would make an unexamined claim look verified.
        origins = [r["trust"]["source_origin"] for r in rows]
        origin = (
            next((o for o in ORIGIN_RANK if o in origins), "NONE") if sourced else "NOT_EXAMINED"
        )
        integrities = {r["integrity"] for r in rows}
        integrity = (
            "not_applicable"
            if not rows or not sourced
            else "mismatch"
            if "mismatch" in integrities
            else "missing"
            if "missing" in integrities
            else "ok"
        )
        eligible = [r for r in rows if r["eligible"]]
        decided = result["claim_status"] in ("SUPPORTED", "REFUTED")
        real_eligible = bool(decided and sourced and not synthetic) and any(
            r["trust"]["source_origin"] in REAL_ORIGINS for r in eligible
        )
        artifacts = {r["trust"].get("content_sha256") or r["sha256"] for r in eligible}
        if not eligible:
            corroboration = "NONE"
        elif len(artifacts) < 2:
            corroboration = "SINGLE_SOURCE" if len(eligible) == 1 else "DUPLICATES_ONLY"
        else:
            corroboration = "SEPARATE_ARTIFACTS_ORIGIN_UNASSESSED"
        methods = {
            r["trust"]["methodology"]
            for r in rows
            if r["eligible"] or r["relation"] != "irrelevant"
        }
        methodology = next(
            (m for m in ("RECORDED", "NOT_REQUIRED", "NOT_RECORDED") if m in methods),
            "NOT_EVALUATED",
        )
        relevances = {r["trust"]["relevance"] for r in rows}
        if synthetic and sourced:
            relevance = "NOT_APPLICABLE_SYNTHETIC"
        elif sourced:
            relevance = (
                "STRUCTURAL_MATCH" if "STRUCTURAL_MATCH" in relevances else "NOT_ESTABLISHED"
            )
        else:
            relevance = "NOT_APPLICABLE"
        outcome = result["check_outcome"]
        if method == "arithmetic" and result["check_passed"] is not None:
            status = "DETERMINISTIC_CHECK_ONLY"
        elif decided and synthetic:
            status = "SYNTHETIC_FIXTURE_ONLY"
        elif real_eligible:
            status = "SOURCE_VERIFIED_SCOPED" if result["scope_limited"] else "SOURCE_VERIFIED"
        elif outcome:
            status = (
                "SUPPLIED_DATA_AGREES" if outcome == "SUPPORTED" else "SUPPLIED_DATA_CONTRADICTS"
            )
        else:
            status = "UNRESOLVED"
        return {
            "trust_model": TRUST_MODEL,
            "check_passed": result["check_passed"],
            "evidence_integrity": integrity,
            "source_origin": origin,
            "claim_relevance": relevance,
            "methodology": methodology,
            "corroboration": corroboration,
            "corroborated": False,
            "input_provenance": "UNVERIFIED"
            if method == "arithmetic"
            else "NOT_APPLICABLE"
            if not sourced
            else "SEE_EVIDENCE",
            "real_world_eligible": real_eligible,
            "real_world_truth": "NOT_APPLICABLE_SYNTHETIC"
            if synthetic and sourced
            else "NOT_ESTABLISHED"
            if method == "arithmetic"
            else "UNRESOLVED",
            "evidence_status": status,
        }

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
