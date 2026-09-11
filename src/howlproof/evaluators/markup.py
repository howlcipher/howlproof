"""The security adversary asks whether escaping matches the context it lands in.

Most escaping bugs are not missing escaping. They are escaping that is correct for
one context and applied in another: an HTML-entity escaper is sufficient for element
text and attribute values, and insufficient inside a JavaScript string literal in an
event-handler attribute, where a single quote ends the string and the rest is code.

This check reads the artifact's own escape function to learn which characters it
actually handles, then finds interpolations whose context needs more than that.
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

#: The entity forms that prove a character is handled, per character.
ENTITY_FORMS: dict[str, tuple[str, ...]] = {
    "&": ("&amp;", "&#38;", "&#x26;"),
    "<": ("&lt;", "&#60;", "&#x3c;"),
    ">": ("&gt;", "&#62;", "&#x3e;"),
    '"': ("&quot;", "&#34;", "&#x22;"),
    "'": ("&#39;", "&apos;", "&#x27;"),
}

EVENT_ATTRIBUTE = re.compile(r"\bon[a-z]{3,15}\s*=\s*\\?\"", re.IGNORECASE)
INTERPOLATION = re.compile(r"\$\{|\(call\s+|\"\s*\(|\+\s*[A-Za-z_]|%s|\{\{")
DEFINITION_FORMS = (
    "(defun {name}",
    "function {name}",
    "const {name}",
    "let {name}",
    "var {name}",
    "def {name}",
)
BODY_WINDOW = 2000
ATTRIBUTE_WINDOW = 400
STRING_WINDOW = 300


class MarkupEscaping(Evaluator):
    """Check that the artifact's escaping is adequate for the context each value lands in."""

    id = "markup.escaping"
    adversary = Adversary.SECURITY

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.markup and context.config.markup.sources:
            return True, ""
        return False, "the artifact declares no markup sources to analyse"

    def evaluate(self, context: Context) -> Outcome:
        markup = context.config.markup
        assert markup is not None
        sources = _resolve(context, markup.sources)
        if not sources:
            return Outcome(
                checks=[
                    self.unavailable(
                        "the declared markup sources match no file in this checkout: "
                        + ", ".join(markup.sources)
                    )
                ]
            )

        coverage = _escape_coverage(context, sources, markup.escape_functions)
        issues: list[dict[str, Any]] = []
        for name in sources:
            content = context.target.read_text(name)
            issues.extend(_js_string_contexts(name, content, markup.escape_functions, coverage))
            issues.extend(_unescaped_sinks(name, content, markup))

        ref = context.save_evidence_json(
            self.id,
            "analysis.json",
            {"sources": sources, "escape_coverage": coverage, "issues": issues},
        )
        limitation = (
            "static reading of HTML construction sites and the artifact's own escape function; "
            "it shows that an escaper's character set is insufficient for a context, not that a "
            "particular input reaches that context at runtime"
        )
        if not issues:
            return Outcome(
                checks=[
                    self.verified(
                        f"{len(sources)} markup sources escape every interpolation adequately "
                        "for the context it lands in",
                        limitation,
                        evidence_refs=[ref],
                        detail={"escape_coverage": coverage},
                    )
                ]
            )
        return Outcome(
            checks=[
                self.failed(
                    f"{len(issues)} interpolations are escaped inadequately for their context",
                    limitation,
                    evidence_refs=[ref],
                    detail={"escape_coverage": coverage, "issues": len(issues)},
                )
            ],
            findings=[self._finding(issue) for issue in issues],
        )

    def _finding(self, issue: dict[str, Any]) -> Finding:
        return self.finding(
            title=str(issue["title"]),
            category="security",
            severity=Severity[str(issue["severity"])],
            confidence=Confidence.HIGH,
            summary=str(issue["summary"]),
            evidence=str(issue["evidence"]),
            remediation=str(issue["remediation"]),
            location=f"{issue['file']}:{issue['line']}",
            rule=str(issue["rule"]),
            reproduction=Reproduction(
                summary="Re-read the source and match the same construction.",
                steps=[
                    ReproductionStep(
                        description=f"Inspect {issue['file']} around line {issue['line']}.",
                        kind="file_probe",
                        payload={"path": issue["file"], "pattern": str(issue["pattern"])},
                        expect={"matches": True},
                    )
                ],
            ),
            detail=dict(issue),
        )


def _resolve(context: Context, patterns: list[str]) -> list[str]:
    resolved: list[str] = []
    for pattern in patterns:
        for name in context.target.glob(pattern):
            if name not in resolved and context.target.exists(name):
                resolved.append(name)
    return sorted(resolved)


def _escape_coverage(
    context: Context, sources: list[str], escape_functions: list[str]
) -> dict[str, dict[str, Any]]:
    """Read each escape function's body and record which characters it demonstrably handles."""
    coverage: dict[str, dict[str, Any]] = {}
    for function in escape_functions:
        for name in sources:
            content = context.target.read_text(name)
            index = _definition_index(content, function)
            if index is None:
                continue
            body = content[index : index + BODY_WINDOW]
            handled = sorted(
                character
                for character, forms in ENTITY_FORMS.items()
                if any(form in body.lower() for form in forms)
            )
            coverage[function] = {
                "defined_in": name,
                "line": content.count("\n", 0, index) + 1,
                "escapes": handled,
                "missing": sorted(set(ENTITY_FORMS) - set(handled)),
            }
            break
    return coverage


def _definition_index(content: str, name: str) -> int | None:
    for form in DEFINITION_FORMS:
        index = content.find(form.format(name=name))
        if index >= 0:
            return index
    return None


def _js_string_contexts(
    name: str, content: str, escape_functions: list[str], coverage: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Find interpolations that land inside a JavaScript string in an event attribute."""
    issues: list[dict[str, Any]] = []
    for attribute in EVENT_ATTRIBUTE.finditer(content):
        window = content[attribute.end() : attribute.end() + ATTRIBUTE_WINDOW]
        quote = window.find("'")
        if quote < 0:
            continue
        literal = window[quote + 1 : quote + 1 + STRING_WINDOW]
        closing = literal.find("'")
        inner = literal[:closing] if closing >= 0 else literal
        if not INTERPOLATION.search(inner):
            continue
        used = [f for f in escape_functions if re.search(rf"\b{re.escape(f)}\b", inner)]
        line = content.count("\n", 0, attribute.start()) + 1
        excerpt = content[
            max(0, attribute.start() - 80) : attribute.end() + quote + len(inner) + 20
        ].strip()
        if not used:
            issues.append(
                {
                    "file": name,
                    "line": line,
                    "rule": "markup.unescaped_js_string",
                    "severity": "HIGH",
                    "title": f"Unescaped interpolation inside a JavaScript string in {name}",
                    "summary": (
                        "A value is interpolated into a single-quoted JavaScript string inside "
                        "an event-handler attribute without passing through any escape "
                        "function. A single quote in that value ends the string and the "
                        "remainder is parsed as code."
                    ),
                    "evidence": excerpt,
                    "pattern": attribute.group(0),
                    "remediation": (
                        "Stop building handlers as markup. Attach the listener in code and pass "
                        "the value as data, or JSON-encode and escape it for both the "
                        "JavaScript and HTML-attribute contexts."
                    ),
                }
            )
            continue
        for function in used:
            record = coverage.get(function)
            if record is None:
                continue
            missing = set(record.get("missing") or [])
            escaped = ", ".join(record.get("escapes") or [])
            if "'" not in missing:
                continue
            issues.append(
                {
                    "file": name,
                    "line": line,
                    "rule": "markup.escaper_context_mismatch",
                    "severity": "HIGH",
                    "title": (
                        f"`{function}` does not escape the single quote but is used inside a "
                        "JavaScript string literal"
                    ),
                    "summary": (
                        f"`{function}` escapes {escaped} and not the single "
                        f"quote (defined at {record['defined_in']}:{record['line']}). At "
                        f"{name}:{line} its output is placed inside a single-quoted JavaScript "
                        "string in an event-handler attribute. The HTML parser decodes the "
                        "attribute before JavaScript parses it, so a single quote in the value "
                        "terminates the string literal and everything after it becomes code. "
                        "Escaping the double quote prevents breaking out of the attribute; it "
                        "does not prevent breaking out of the string."
                    ),
                    "evidence": excerpt,
                    "pattern": attribute.group(0),
                    "remediation": (
                        "Escape the single quote in the escape function, or stop embedding "
                        "values in handler attributes and bind the listener in code instead. "
                        "Escaping for HTML text is not sufficient for a JavaScript context."
                    ),
                }
            )
    return issues


def _unescaped_sinks(name: str, content: str, markup: Any) -> list[dict[str, Any]]:
    """Interpolation into an HTML sink with no escape function anywhere in the expression."""
    sinks: list[str] = list(getattr(markup, "sink_functions", []))
    escapes: list[str] = list(getattr(markup, "escape_functions", []))
    issues: list[dict[str, Any]] = []
    for sink in sinks:
        for match in re.finditer(rf"\b{re.escape(sink)}\b", content):
            window = content[match.start() : match.start() + STRING_WINDOW]
            if not INTERPOLATION.search(window):
                continue
            if any(re.search(rf"\b{re.escape(f)}\b", window) for f in escapes):
                continue
            if not re.search(r"[\"'`]\s*<[a-z/]", window, re.IGNORECASE):
                continue
            issues.append(
                {
                    "file": name,
                    "line": content.count("\n", 0, match.start()) + 1,
                    "rule": "markup.sink_without_escaping",
                    "severity": "MEDIUM",
                    "title": f"`{sink}` builds markup from an interpolated value in {name}",
                    "summary": (
                        f"A call to `{sink}` assembles HTML containing an interpolated value and "
                        "no escape function appears in the surrounding expression."
                    ),
                    "evidence": window.strip()[:400],
                    "pattern": match.group(0),
                    "remediation": (
                        "Route every interpolated value through the artifact's escape function, "
                        "or set text content instead of markup."
                    ),
                }
            )
    return issues


EVALUATORS: list[Evaluator] = [MarkupEscaping()]
