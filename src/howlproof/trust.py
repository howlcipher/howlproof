"""Evidence trust model (`howl.evidence_trust/v1`).

Six different things get called "verified" in research. They are kept apart here, as
orthogonal dimensions, and never folded into one score:

1. **submitted**: an agent, user or document supplied it. Says nothing about authenticity.
2. **integrity-checked**: the stored bytes match a recorded digest. Not that they were
   truthful when made.
3. **source-observed**: an acquisition event HowlProof can inspect (`acquire.py`) produced
   the source bytes. Not that the source's claims are correct.
4. **claim-relevant**: the source actually addresses the claim. Only structurally checked
   here (required subject terms and the fact appear in the source); substantive relevance
   still needs a reviewer.
5. **corroborated**: separately obtained, substantively independent observations. HowlProof
   can detect *duplicates*; it cannot establish independence of origin, so this stays false.
6. **reproduced**: a deterministic check or experiment re-derived the result. An arithmetic
   check does not authenticate the inputs it was handed.

Agent-authored metadata (`independent`, `source_type`, `represents_observed_reality`, a URL,
a digest, a summary) is preserved as *claimed provenance* and never promoted to *observed*.
"""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

TRUST_MODEL = "howl.evidence_trust/v1"

#: Reserved by RFC 2606 / 6761: never a real publication, always a placeholder.
RESERVED_DOMAINS = frozenset({"example.com", "example.org", "example.net", "localhost"})
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local", ".internal")
PLACEHOLDER_WORDS = frozenset(
    {
        "",
        "todo",
        "tbd",
        "tba",
        "n/a",
        "na",
        "none",
        "null",
        "unknown",
        "placeholder",
        "xxx",
        "fixme",
    }
)
_PLACEHOLDER_SEGMENT = re.compile(
    r"(?:^|[/_.\-])(?:todo|tbd|tba|placeholder|fixme|xxx)(?:$|[/_.\-])"
)

#: Source types that describe agent-authored text. Such evidence is never a primary source.
AGENT_AUTHORED_TYPES = frozenset(
    {
        "MODEL_SUMMARY",
        "AGENT_SUMMARY",
        "AI_SUMMARY",
        "MODEL_GENERATED",
        "MODEL_SELF_CONSISTENCY",
        "OPERATOR_EXPECTATION",
        "SIMULATION_EXPECTATION",
    }
)
SYNTHETIC_AUTHORSHIP = frozenset({"SYNTHETIC_FIXTURE", "MOCK"})

#: Highest-first. A claim reports the strongest origin among the evidence it considered.
ORIGIN_RANK = (
    "OBSERVED_ACQUISITION",
    "OPERATOR_ATTESTED_FILE",
    "SYNTHETIC_FIXTURE",
    "UNVERIFIABLE",
    "CLAIMED_ONLY",
    "PLACEHOLDER",
    "AGENT_AUTHORED",
    "NONE",
)
REAL_ORIGINS = frozenset({"OBSERVED_ACQUISITION", "OPERATOR_ATTESTED_FILE"})

_TRACKING = re.compile(r"^(utm_|fbclid$|gclid$|ref$|ref_src$|source$)")


def _host(reference: str) -> str:
    parts = urlsplit(reference.strip())
    return (parts.hostname or "").lower() if parts.scheme in ("http", "https") else ""


def classify_reference(reference: str) -> str:
    """PLACEHOLDER, URL or FREE_TEXT. Structural only; a URL is not thereby real."""
    if is_placeholder_reference(reference):
        return "PLACEHOLDER"
    return "URL" if _host(reference) else "FREE_TEXT"


def is_placeholder_reference(reference: str) -> bool:
    """Obvious placeholders: reserved domains, loopback/private literals, TODO-style words."""
    text = (reference or "").strip().lower()
    if text in PLACEHOLDER_WORDS:
        return True
    host = _host(text)
    if not host:
        return bool(_PLACEHOLDER_SEGMENT.search(text)) and " " not in text
    try:
        address = ipaddress.ip_address(host)
        return not address.is_global
    except ValueError:
        pass
    if host in RESERVED_DOMAINS or host.endswith(RESERVED_SUFFIXES):
        return True
    if any(host.endswith("." + domain) for domain in RESERVED_DOMAINS):
        return True
    return bool(_PLACEHOLDER_SEGMENT.search(urlsplit(text).path.lower()))


def canonical_location(reference: str | None) -> str:
    """A comparison key: scheme-insensitive, no fragment, no tracking parameters."""
    if not reference:
        return ""
    parts = urlsplit(reference.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return reference.strip().lower()
    query = urlencode(
        sorted((k, v) for k, v in parse_qsl(parts.query) if not _TRACKING.match(k.lower()))
    )
    path = parts.path.rstrip("/") or ""
    return f"{parts.hostname.lower()}{path}{'?' + query if query else ''}"


def locations_agree(reference: str, record: dict) -> bool:
    """Whether a bundle's `source_ref` names a location the acquisition actually saw."""
    wanted = canonical_location(reference)
    seen = {
        canonical_location(record.get(key))
        for key in ("requested_url", "observed_url", "claimed_source_url")
        if record.get(key)
    }
    seen.update(canonical_location(u) for u in record.get("redirects", []))
    return wanted in seen


def source_text(raw: bytes, content_type: str | None = None) -> str:
    """Decode retrieved bytes to searchable text. Markup is reduced to its text; never run."""
    text = raw.decode("utf-8", errors="replace")
    kind = (content_type or "").split(";")[0].strip().lower()
    if kind in ("text/html", "application/xhtml+xml", "") and "<" in text:
        text = html.unescape(_strip_markup(text))
    return text


def _strip_markup(text: str) -> str:
    """Reduce markup to its text in one left-to-right pass.

    Deliberately not a regex: `<[^>]*>` is quadratic on hostile input such as `<<<<...` (a
    200 KB page took 17 s). Every `find` here either advances past what it consumed or ends the
    scan, so the cost is linear in the size of the page.
    """
    lower = text.lower()
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        j = text.find("<", i)
        if j == -1:
            out.append(text[i:])
            break
        out.append(text[i:j])
        for tag in ("script", "style"):
            if lower.startswith("<" + tag, j):
                end = lower.find("</" + tag, j)
                close = text.find(">", end) if end != -1 else -1
                i = close + 1 if close != -1 else n
                out.append(" ")
                break
        else:
            close = text.find(">", j)
            if close == -1:  # no later '>' exists, so nothing further can be a tag
                out.append(text[j:])
                break
            out.append(" ")
            i = close + 1
    return "".join(out)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text.lower())


def locate_value(value: str, text: str) -> bool:
    """Whether a quantity appears in a source, ignoring spacing and case but not magnitude.

    `5%` is not found inside `65%`, and `42 ms` is not found inside `142 ms`.
    """
    needle = _squash(str(value))
    if not needle or _is_bare_small_number(needle):
        return False
    return (
        re.search(rf"(?<![0-9]){re.escape(needle)}(?![0-9])(?!\.[0-9])", _squash(text)) is not None
    )


def _is_bare_small_number(squashed: str) -> bool:
    """`0`, `1`, `9`, `42`: no unit, currency or scale, fewer than three digits.

    Such a value is how an agent encodes a flag, a count or a judgment ("documented: 0"). It
    would "appear" in almost any page, so it cannot show the source said it.
    """
    return (
        re.fullmatch(r"[0-9][0-9.,]*", squashed) is not None
        and sum(c.isdigit() for c in squashed) < 3
    )


def locate_phrase(phrase: str, text: str) -> bool:
    """Case- and whitespace-insensitive containment of a phrase."""
    needle = " ".join(str(phrase).lower().split())
    return bool(needle) and needle in " ".join(text.lower().split())
