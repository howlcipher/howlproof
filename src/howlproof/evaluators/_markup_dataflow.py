"""Bounded source-to-sink dataflow for markup escaping.

This is intentionally not a general JavaScript static analyser. It handles a
narrow, documented subset of JavaScript construction patterns so that an
escaper's real capabilities can be compared against the actual context a value
lands in. Anything outside the supported subset is recorded as a limitation,
not silently assumed safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Contexts the dataflow reasons about. Values are ordered from outer to inner
#: where relevant (e.g. a JS string inside an HTML attribute).
CONTEXTS = frozenset(
    {
        "html_text",
        "html_attr_double",
        "html_attr_single",
        "html_attr_unquoted",
        "js_string_single",
        "js_string_double",
        "js_code",
        "url",
        "css",
        "html_tag",
        "unsupported",
    }
)

#: Characters an escaper must demonstrably handle before the dataflow will trust
#: it for a given context. URL context is special: it requires a URL encoder.
CONTEXT_REQUIREMENTS: dict[str, set[str]] = {
    "html_text": {"<", ">", "&"},
    "html_attr_double": {'"', "<", ">", "&"},
    "html_attr_single": {"'", "<", ">", "&"},
    "html_attr_unquoted": {'"', "'", "<", ">", "&", " "},
    "js_string_double": {'"', "\\", "\n"},
    "js_string_single": {"'", "\\", "\n"},
    "js_code": {"'", '"', "\\", ";", "{"},
    "url": {"__url_encoder__"},
    "css": {";", "{", "}", '"', "'"},
}

#: Direct interpolation into these sink APIs is tracked.
HTML_SINKS = frozenset({"innerHTML", "outerHTML", "document.write", "insertAdjacentHTML"})
URL_ATTRS = frozenset({"href", "src", "action", "formaction"})

#: Syntactic forms that introduce tainted data from outside the function.
SOURCE_PATTERNS = (
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*JSON\.parse\s*\("),
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*(?:await\s+)?[\w.]+\.json\s*\("),
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*new\s+URLSearchParams\s*\([^)]*\)\.get\s*\("),
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*location\.search"),
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*document\.URL"),
    re.compile(r"(?P<target>\w+(?:\.\w+)*)\s*=\s*document\.cookie"),
)


@dataclass(frozen=True)
class Taint:
    """Set of originating source names and escaper functions seen so far."""

    sources: frozenset[str] = field(default_factory=frozenset)
    escapers: frozenset[str] = field(default_factory=frozenset)

    def with_escaper(self, name: str) -> Taint:
        return Taint(self.sources, self.escapers | {name})

    def merge(self, other: Taint) -> Taint:
        return Taint(self.sources | other.sources, self.escapers | other.escapers)


EMPTY = Taint()


@dataclass
class Segment:
    """One literal or tainted piece of an expression."""

    text: str
    taint: Taint = EMPTY


Expr = list[Segment]


def _literal(text: str) -> Expr:
    return [Segment(text)]


def _merge(a: Expr, b: Expr) -> Expr:
    return list(a) + list(b)


def _merge_many(exprs: list[Expr]) -> Expr:
    out: Expr = []
    for e in exprs:
        out.extend(e)
    return out


def _escaper_contexts(coverage: dict[str, Any]) -> dict[str, set[str]]:
    """Map each configured escape function to the contexts it demonstrably serves."""
    mapping: dict[str, set[str]] = {}
    for name, record in coverage.items():
        body = (record.get("body") or "").lower()
        handled = set(record.get("escapes") or [])
        contexts: set[str] = set()
        if {"<", ">", "&"}.issubset(handled):
            contexts.add("html_text")
        if {'"', "<", ">", "&"}.issubset(handled):
            contexts.add("html_attr_double")
        if {"'", "<", ">", "&"}.issubset(handled):
            contexts.add("html_attr_single")
        if {'"', "'", "<", ">", "&", " "}.issubset(handled):
            contexts.add("html_attr_unquoted")
        if {'"', "\\"}.issubset(handled):
            contexts.add("js_string_double")
        if {"'", "\\"}.issubset(handled):
            contexts.add("js_string_single")
        if {"'", '"', "\\", ";", "{"}.issubset(handled):
            contexts.add("js_code")
        if ";" in handled and "{" in handled and "}" in handled:
            contexts.add("css")
        if "encodeURIComponent" in body or "encodeURI" in body:
            contexts.add("url")
            # A URL encoder also satisfies the general URL token requirement.
            handled = handled | {"__url_encoder__"}
        if "__url_encoder__" in handled:
            contexts.add("url")
        mapping[name] = contexts
    return mapping


class DataflowAnalyzer:
    """Bounded single-scope dataflow for JavaScript markup construction."""

    def __init__(
        self,
        name: str,
        content: str,
        escape_functions: list[str],
        sink_functions: list[str],
        coverage: dict[str, Any],
    ) -> None:
        self.name = name
        self.content = content
        self.lines = content.splitlines()
        self.escape_functions = set(escape_functions)
        self.sink_functions = set(sink_functions)
        self.coverage = coverage
        self.contexts = _escaper_contexts(coverage)
        self.sources: set[str] = set()
        self.taints: dict[str, Taint] = {}
        self.exprs: dict[str, Expr] = {}
        self.issues: list[dict[str, Any]] = []
        self.unsupported: list[str] = []

    def analyze(self) -> tuple[list[dict[str, Any]], list[str]]:
        blocks = _function_blocks(self.content)
        if not blocks:
            return self._analyze_one()
        all_issues: list[dict[str, Any]] = []
        all_unsupported: list[str] = []
        for _name, block in blocks:
            sub = DataflowAnalyzer(
                self.name,
                block,
                list(self.escape_functions),
                list(self.sink_functions),
                self.coverage,
            )
            issues, unsupported = sub._analyze_one()
            all_issues.extend(issues)
            all_unsupported.extend(unsupported)
        return all_issues, all_unsupported

    def _analyze_one(self) -> tuple[list[dict[str, Any]], list[str]]:
        self._collect_params()
        self._collect_sources()
        self._scan()
        return self.issues, self.unsupported

    def _line_no(self, index: int) -> int:
        return self.content.count("\n", 0, index) + 1

    def _collect_params(self) -> None:
        for match in re.finditer(r"function\s+\w+\s*\(([^)]*)\)", self.content):
            for param in match.group(1).split(","):
                token = param.strip().split("=")[0].strip()
                if token:
                    self.sources.add(token)

    def _collect_sources(self) -> None:
        for pattern in SOURCE_PATTERNS:
            for match in pattern.finditer(self.content):
                self.sources.add(match.group("target"))

    def _scan(self) -> None:
        # Process variable declarations first so later assignments have taint.
        for match in re.finditer(
            r"(?:const|let|var)\s+(\w+(?:\.\w+)*)\s*=\s*([^;]+)", self.content
        ):
            self._record(match.group(1), match.group(2), match.start())
        # Then assignments.
        for match in re.finditer(r"(\w+(?:\.\w+)*)\s*=\s*([^;]+)", self.content):
            if self.content[match.start() : match.start() + 6] in ("const ", "let ", "var "):
                continue
            self._record(match.group(1), match.group(2), match.start())
        # Sinks: property assignments to innerHTML/outerHTML/etc.
        for sink in HTML_SINKS:
            for match in re.finditer(rf"(.+?)\.\b{re.escape(sink)}\b\s*=\s*([^;]+)", self.content):
                self._sink(match, match.group(2), "html")
        # Sinks: function calls (setHTML, document.write, insertAdjacentHTML).
        for match in re.finditer(r"([\w.]+)\s*\(([^)]*)\)", self.content):
            func = match.group(1)
            args = match.group(2)
            if func in self.sink_functions:
                self._sink(match, args, "html")
            elif func in self.escape_functions:
                # Escaper calls do not themselves sink; result taint was recorded.
                pass

    def _record(self, target: str, expr: str, index: int) -> None:
        parsed = self._parse_expr(expr.strip(), index)
        taint = EMPTY
        for seg in parsed:
            taint = taint.merge(seg.taint)
        self.taints[target] = taint
        self.exprs[target] = parsed

    def _parse_expr(self, expr: str, index: int) -> Expr:
        expr = expr.strip()
        # Template literal with possible ${...}
        if expr.startswith("`") and expr.endswith("`") and len(expr) > 1:
            return self._parse_template(expr[1:-1], index)
        # Escaper call: f(arg)
        call = re.match(r"(\b\w+\b)\s*\((.*)\)\s*$", expr)
        if call:
            func = call.group(1)
            inner = call.group(2).strip()
            arg_expr = self._parse_expr(inner, index)
            if func in self.escape_functions:
                return [Segment(seg.text, seg.taint.with_escaper(func)) for seg in arg_expr]
            return arg_expr
        # Concatenation with +
        if " + " in expr:
            parts = re.split(r"\s*\+\s*", expr)
            return _merge_many([self._parse_expr(part, index) for part in parts])
        # Parenthesised expression.
        if expr.startswith("(") and expr.endswith(")"):
            return self._parse_expr(expr[1:-1], index)
        # Literal string.
        if (expr.startswith('"') and expr.endswith('"')) or (
            expr.startswith("'") and expr.endswith("'")
        ):
            return _literal(expr[1:-1])
        # Numeric/boolean literal.
        if re.match(r"^(\d+|true|false|null|undefined)$", expr):
            return _literal("")
        # Identifier / member access.
        taint = self._taint_for(expr)
        return [Segment("", taint)]

    def _parse_template(self, body: str, index: int) -> Expr:
        out: Expr = []
        cursor = 0
        while cursor < len(body):
            start = body.find("${", cursor)
            if start < 0:
                out.append(Segment(body[cursor:]))
                break
            if start > cursor:
                out.append(Segment(body[cursor:start]))
            end = self._find_brace_end(body, start + 2)
            if end is None:
                self.unsupported.append(
                    f"template literal brace mismatch around {self._line_no(index)}"
                )
                out.append(Segment(body[start:]))
                break
            out.extend(self._parse_expr(body[start + 2 : end], index))
            cursor = end + 1
        return out

    def _find_brace_end(self, text: str, start: int) -> int | None:
        depth = 1
        i = start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None

    def _taint_for(self, token: str) -> Taint:
        token = token.strip()
        if token in self.sources:
            return Taint(frozenset({token}))
        # member access on a source is also treated as tainted
        if token.split(".")[0] in self.sources:
            return Taint(frozenset({token}))
        if token in self.taints:
            return self.taints[token]
        return EMPTY

    def _sink(self, match: re.Match[str], expr: str, sink_kind: str) -> None:
        line = self._line_no(match.start())
        parsed = self._parse_expr(expr.strip(), match.start())
        # If the sink argument is a single variable, expand its construction so
        # different insertion points inside it can have different contexts.
        if (
            len(parsed) == 1
            and parsed[0].text == ""
            and parsed[0].taint.sources
            and expr.strip() in self.exprs
        ):
            parsed = self.exprs[expr.strip()]
        if not any(seg.taint.sources for seg in parsed):
            return
        # Rebuild the constructed string so context can be determined at each
        # tainted insertion point.
        prefix = ""
        for seg in parsed:
            if not seg.taint.sources:
                prefix += seg.text
                continue
            context = _context_at(prefix)
            for source in seg.taint.sources:
                self._check_segment(line, match.start(), prefix, seg, source, context, sink_kind)
            prefix += seg.text

    def _check_segment(
        self,
        line: int,
        index: int,
        prefix: str,
        seg: Segment,
        source: str,
        context: str,
        sink_kind: str,
    ) -> None:
        required = set(CONTEXT_REQUIREMENTS.get(context, set()))
        adequate: set[str] = set()
        for esc in seg.taint.escapers:
            adequate |= self.contexts.get(esc, set())
        if context in adequate:
            return
        excerpt = self._excerpt(index)
        if not seg.taint.escapers:
            self.issues.append(
                {
                    "file": self.name,
                    "line": line,
                    "rule": "markup.unescaped_source_to_sink",
                    "severity": "HIGH",
                    "context": context,
                    "title": f"Source `{source}` reaches a markup sink without escaping in {self.name}",
                    "summary": (
                        f"`{source}` flows directly to a {sink_kind} sink and is inserted "
                        f"into a `{context}` context without passing through an escape function."
                    ),
                    "evidence": excerpt,
                    "pattern": source,
                    "remediation": (
                        "Route the value through an escape function appropriate for the context "
                        "(HTML text, HTML attribute, JavaScript string or URL) before it reaches "
                        "the sink, or use a safe API such as textContent."
                    ),
                }
            )
            return
        missing_labels = sorted(
            "URL encoding" if c == "__url_encoder__" else repr(c) for c in required - adequate
        )
        escapers = ", ".join(sorted(seg.taint.escapers)) or "none"
        self.issues.append(
            {
                "file": self.name,
                "line": line,
                "rule": "markup.wrong_context_escape",
                "severity": "HIGH",
                "context": context,
                "title": (f"Source `{source}` is escaped for the wrong context in {self.name}"),
                "summary": (
                    f"`{source}` reaches a `{context}` context after passing through "
                    f"{escapers}, which does not cover the characters required for that context. "
                    f"Missing for `{context}`: {', '.join(missing_labels) or 'context-specific handling'}."
                ),
                "evidence": excerpt,
                "pattern": source,
                "remediation": (
                    "Use an escaper whose character set matches the actual sink context, or "
                    "avoid placing untrusted data in that context."
                ),
            }
        )

    def _excerpt(self, index: int) -> str:
        line_start = self.content.rfind("\n", 0, index) + 1
        line_end = self.content.find("\n", index)
        if line_end < 0:
            line_end = len(self.content)
        return self.content[line_start:line_end].strip()[:200]


def _function_blocks(content: str) -> list[tuple[str, str]]:
    """Return top-level function definitions as isolated scopes."""
    blocks: list[tuple[str, str]] = []
    for match in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", content):
        start = match.end() - 1
        end = _find_matching_brace(content, start)
        if end is None:
            continue
        blocks.append((match.group(1), content[match.start() : end + 1]))
    return blocks


def _find_matching_brace(content: str, open_index: int) -> int | None:
    depth = 1
    i = open_index + 1
    while i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _context_at(prefix: str) -> str:
    """Determine the markup context at the end of `prefix`.

    Prefix is the part of a constructed string that precedes a tainted segment.
    """
    last_open = prefix.rfind("<")
    last_close = prefix.rfind(">")
    if last_open < 0 or last_close > last_open:
        return "html_text"
    tag_part = prefix[last_open:]
    # Find an attribute whose value currently extends to the insertion point.
    match = re.search(r'<[^>]*?\s([a-zA-Z][\w:-]*)\s*=\s*([\'"]?)\s*$', tag_part)
    if not match:
        return "html_tag"
    attr = match.group(1).lower()
    quote = match.group(2)
    if attr.startswith("on"):
        if quote == "'":
            return "js_string_single"
        if quote == '"':
            return "js_string_double"
        return "js_code"
    if attr in URL_ATTRS:
        return "url"
    if attr == "style":
        return "css"
    if quote == "'":
        return "html_attr_single"
    if quote == '"':
        return "html_attr_double"
    return "html_attr_unquoted"


def analyze(
    name: str,
    content: str,
    escape_functions: list[str],
    sink_functions: list[str],
    coverage: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run the bounded dataflow analyser on one source file."""
    analyzer = DataflowAnalyzer(name, content, escape_functions, sink_functions, coverage)
    return analyzer.analyze()
