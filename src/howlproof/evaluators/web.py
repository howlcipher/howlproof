"""Adversaries against the artifact's published interface.

Link and metadata analysis are deterministic and always run. Rendering checks need
a browser: when one is not installed the result is UNAVAILABLE, because a page that
was never rendered has not been shown to work at any width.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, Self

from howlproof.model import Adversary, Confidence, Reproduction, ReproductionStep, Severity
from howlproof.registry import Context, Evaluator, Outcome
from howlproof.service import request

HREF = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
ID_ATTRIBUTE = re.compile(r"""\bid\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META = re.compile(
    r"""<meta\s+[^>]*?(?:name|property)\s*=\s*["']([^"']+)["']"""
    r"""[^>]*?content\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)
CANONICAL = re.compile(
    r"""<link\s+[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
H1 = re.compile(r"<h1[\s>]", re.IGNORECASE)
EXTERNAL = ("http://", "https://", "mailto:", "tel:")


class _WebEvaluator(Evaluator):
    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.web is None:
            return False, "the artifact declares no web surface"
        missing = [
            page
            for page in context.config.web.pages
            if not context.target.exists(f"{context.config.web.root}/{page}")
        ]
        if missing == list(context.config.web.pages):
            return False, (
                f"none of the declared pages exist under {context.config.web.root}: "
                + ", ".join(missing)
            )
        return True, ""

    def pages(self, context: Context) -> list[tuple[str, str]]:
        assert context.config.web is not None
        root = context.config.web.root
        return [
            (page, context.target.read_text(f"{root}/{page}"))
            for page in context.config.web.pages
            if context.target.exists(f"{root}/{page}")
        ]


class WebLinks(_WebEvaluator):
    """Every internal reference must resolve. External ones are only followed on request."""

    id = "web.links"
    adversary = Adversary.OPERATOR

    def evaluate(self, context: Context) -> Outcome:
        assert context.config.web is not None
        root = context.config.web.root
        broken: list[dict[str, Any]] = []
        external: list[str] = []
        checked = 0
        for page, content in self.pages(context):
            identifiers = set(ID_ATTRIBUTE.findall(content))
            for reference in HREF.findall(content):
                checked += 1
                if reference.startswith(EXTERNAL):
                    external.append(reference)
                    continue
                if reference.startswith("#"):
                    if reference[1:] and reference[1:] not in identifiers:
                        broken.append(
                            {"page": page, "href": reference, "why": "no element has that id"}
                        )
                    continue
                if reference.startswith(("data:", "//")):
                    continue
                relative = reference.split("#", 1)[0].split("?", 1)[0]
                if not relative:
                    continue
                candidate = f"{root}/{relative}".replace("//", "/")
                if relative.endswith("/"):
                    candidate = f"{candidate}index.html"
                if not context.target.exists(candidate):
                    broken.append(
                        {
                            "page": page,
                            "href": reference,
                            "why": f"{candidate} is missing from the artifact",
                        }
                    )

        external_results: list[dict[str, Any]] = []
        if context.allow_network and external:
            external_results = _probe_external(sorted(set(external)))
            broken.extend(
                {"page": "external", "href": row["url"], "why": f"HTTP {row['status']}"}
                for row in external_results
                if row["status"] == 0 or row["status"] >= 400
            )

        ref = context.save_evidence_json(
            self.id,
            "links.json",
            {
                "checked": checked,
                "broken": broken,
                "external": sorted(set(external)),
                "external_results": external_results,
            },
        )
        limitation = "internal references and page fragments are resolved against this checkout" + (
            "; external destinations were fetched once"
            if context.allow_network
            else "; external destinations were not fetched because network access was not granted"
        )
        if broken:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(broken)} of {checked} references do not resolve",
                        limitation,
                        evidence_refs=[ref],
                        detail={"broken": broken[:40]},
                    )
                ],
                findings=[
                    self.finding(
                        title=f"{len(broken)} broken references on the published site",
                        category="correctness",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        summary="References that a reader can follow lead nowhere.",
                        evidence=json.dumps(broken[:20], indent=2),
                        remediation="Repair or remove each reference.",
                        rule="web.links.broken",
                        aggregate=True,
                        reproduction=Reproduction(
                            summary="Re-resolve the site's references from this checkout.",
                            steps=[
                                ReproductionStep(
                                    description=f"Resolve {row['href']} from {row['page']}",
                                    kind="file_probe",
                                    payload={
                                        "path": f"{root}/{row['page']}",
                                        "pattern": re.escape(str(row["href"])),
                                    },
                                    expect={"matches": True},
                                )
                                for row in broken[:10]
                            ],
                        ),
                    )
                ],
            )
        return Outcome(
            checks=[
                self.verified(
                    f"all {checked} references resolve",
                    limitation,
                    evidence_refs=[ref],
                    detail={"external_count": len(set(external))},
                )
            ]
        )


class WebMetadata(_WebEvaluator):
    """Discovery metadata the ecosystem's other sites all carry."""

    id = "web.metadata"
    adversary = Adversary.OPERATOR

    def evaluate(self, context: Context) -> Outcome:
        assert context.config.web is not None
        root = context.config.web.root
        problems: list[dict[str, str]] = []
        observed: dict[str, Any] = {}
        for page, content in self.pages(context):
            meta = {name.lower(): value for name, value in META.findall(content)}
            title = TITLE.search(content)
            canonical = CANONICAL.search(content)
            record = {
                "title": title.group(1).strip() if title else "",
                "description": meta.get("description", ""),
                "canonical": canonical.group(1) if canonical else "",
                "og": {k: v for k, v in meta.items() if k.startswith("og:")},
                "h1_count": len(H1.findall(content)),
            }
            observed[page] = record
            if not record["title"]:
                problems.append({"page": page, "why": "no <title>"})
            if not record["description"]:
                problems.append({"page": page, "why": "no meta description"})
            elif not 20 < len(record["description"]) <= 200:
                problems.append(
                    {
                        "page": page,
                        "why": f"meta description is {len(record['description'])} characters",
                    }
                )
            if not record["canonical"]:
                problems.append({"page": page, "why": "no canonical link"})
            elif context.config.web.canonical_prefix and not record["canonical"].startswith(
                context.config.web.canonical_prefix
            ):
                problems.append(
                    {
                        "page": page,
                        "why": f"canonical {record['canonical']} is outside the "
                        f"declared prefix {context.config.web.canonical_prefix}",
                    }
                )
            if record["h1_count"] != 1:
                problems.append({"page": page, "why": f"{record['h1_count']} h1 elements"})
            for required in ("og:title", "og:description", "og:url"):
                if required not in record["og"]:
                    problems.append({"page": page, "why": f"no {required}"})

        for asset in ("robots.txt", "sitemap.xml"):
            if not context.target.exists(f"{root}/{asset}"):
                problems.append({"page": asset, "why": "missing"})

        ref = context.save_evidence_json(
            self.id, "metadata.json", {"observed": observed, "problems": problems}
        )
        limitation = (
            "presence and shape of declared metadata in this checkout; it does not verify what "
            "a search engine or social platform will actually render"
        )
        if problems:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(problems)} metadata problems across {len(observed)} pages",
                        limitation,
                        evidence_refs=[ref],
                        detail={"problems": problems[:40]},
                    )
                ],
                findings=[
                    self.finding(
                        title="Published pages are missing discovery metadata",
                        category="other",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(f"{p['page']}: {p['why']}" for p in problems[:10]),
                        evidence=json.dumps(problems, indent=2)[:3000],
                        remediation="Add the missing tags and assets to match the ecosystem's "
                        "other published sites.",
                        rule="web.metadata.incomplete",
                        aggregate=True,
                        reproduction=Reproduction.by_reevaluation(
                            "web.metadata",
                            "Re-parse the declared pages and observe the missing tags.",
                        ),
                    )
                ],
            )
        return Outcome(
            checks=[
                self.verified(
                    f"{len(observed)} pages carry title, description, canonical, Open Graph "
                    "tags and a single h1, alongside robots.txt and sitemap.xml",
                    limitation,
                    evidence_refs=[ref],
                )
            ]
        )


class WebResponsive(_WebEvaluator):
    """Render each page at each declared width and look for what a reader would hit."""

    id = "web.responsive"
    adversary = Adversary.OPERATOR
    tools: ClassVar[dict[str, list[str]]] = {
        "playwright": [sys.executable, "-c", "import playwright.sync_api"]
    }

    def evaluate(self, context: Context) -> Outcome:
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return Outcome(
                checks=[
                    self.unavailable(
                        "playwright is not importable, so no page was rendered and nothing "
                        "about the site's behaviour at any width was established"
                    )
                ]
            )
        assert context.config.web is not None
        web = context.config.web
        root = context.target.workspace / web.root
        problems: list[dict[str, Any]] = []
        refs: list[str] = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                for page_name, _ in self.pages(context):
                    url = (root / page_name).as_uri()
                    for width in web.viewports:
                        page = browser.new_page(viewport={"width": width, "height": 1000})
                        page.goto(url, wait_until="networkidle")
                        problems.extend(_render_problems(page, page_name, width, web))
                        shot = page.screenshot(full_page=True)
                        name = f"{Path(page_name).stem}-{width}.png"
                        refs.append(context.save_evidence_bytes(self.id, name, shot))
                        page.close()
                browser.close()
        except PlaywrightError as error:
            return Outcome(
                checks=[
                    self.unavailable(
                        f"the browser could not render the site ({error}); no width was checked"
                    )
                ]
            )

        ref = context.save_evidence_json(self.id, "rendered.json", problems)
        refs.append(ref)
        limitation = (
            "rendered checks for overflow, landmarks, headings and keyboard entry at the "
            "declared widths; it is not a full accessibility audit and does not replace review "
            "with assistive technology"
        )
        if problems:
            return Outcome(
                checks=[
                    self.failed(
                        f"{len(problems)} rendering problems across {len(web.viewports)} widths",
                        limitation,
                        evidence_refs=refs,
                        detail={"problems": problems[:30]},
                    )
                ],
                findings=[
                    self.finding(
                        title="The published site fails rendered checks at declared widths",
                        category="other",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        summary="; ".join(
                            f"{p['page']}@{p['width']}: {p['why']}" for p in problems[:8]
                        ),
                        evidence=json.dumps(problems, indent=2)[:3000],
                        remediation="Correct the layout or markup so each width renders without "
                        "these defects.",
                        rule="web.responsive.defects",
                        aggregate=True,
                        reproduction=Reproduction.by_reevaluation(
                            "web.responsive",
                            "Render the declared pages again at each declared width.",
                        ),
                    )
                ],
            )
        widths = ", ".join(f"{w}px" for w in web.viewports)
        return Outcome(
            checks=[
                self.verified(
                    f"{len(self.pages(context))} pages render at {widths} with one h1, a main "
                    "landmark, resolvable fragments, keyboard entry and no horizontal overflow",
                    limitation,
                    evidence_refs=refs,
                )
            ]
        )


def _render_problems(page: Any, name: str, width: int, web: Any) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []

    def note(why: str) -> None:
        problems.append({"page": name, "width": width, "why": why})

    if page.locator("h1").count() != 1:
        note(f"{page.locator('h1').count()} h1 elements")
    if not page.title():
        note("empty document title")
    if page.locator("main").count() == 0:
        note("no main landmark")
    if not page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"):
        note("the document scrolls horizontally")
    for link in page.locator('a[href^="#"]').all():
        fragment = (link.get_attribute("href") or "#")[1:]
        if fragment and page.locator(f'[id="{fragment}"]').count() != 1:
            note(f"fragment #{fragment} resolves to no unique element")
    if web.require_skip_link:
        page.keyboard.press("Tab")
        focused = page.evaluate(
            "() => { const a = document.activeElement; return a ? a.className + '|' +"
            " (a.textContent || '').trim().slice(0, 40) : ''; }"
        )
        if "skip" not in focused.lower():
            note(f"the first tab stop is not a skip link (focus landed on {focused!r})")
    return problems


class DomInjection(Evaluator):
    """Place an authored payload in data the artifact renders, then watch a real browser.

    Static analysis can show that an escaper is insufficient for a context. This is
    what turns that into a confirmed finding: if the marker is set, the value was
    executed as code by a real engine rather than displayed as text.
    """

    id = "web.dom_injection"
    adversary = Adversary.SECURITY
    tools: ClassVar[dict[str, list[str]]] = {
        "playwright": [sys.executable, "-c", "import playwright.sync_api"]
    }

    def applicable(self, context: Context) -> tuple[bool, str]:
        injection = context.config.injection
        if injection is None or not injection.payloads:
            return False, "the artifact declares no injection payloads to attempt"
        if not context.target.exists(f"{injection.app_root}/{injection.page}"):
            return False, (
                f"the declared interface {injection.app_root}/{injection.page} is not present "
                "in this checkout"
            )
        return True, ""

    def evaluate(self, context: Context) -> Outcome:
        injection = context.config.injection
        assert injection is not None
        if not context.service_running:
            return Outcome(
                checks=[
                    self.unavailable(
                        "the artifact's service is not running, so its interface has no data "
                        "to render and no payload could be attempted"
                    )
                ]
            )
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return Outcome(
                checks=[
                    self.unavailable(
                        "playwright is not importable, so no payload was rendered in a browser "
                        "and exploitability was neither shown nor ruled out"
                    )
                ]
            )

        checks, findings = [], []
        method, _, seed_path = injection.seed_request.partition(" ")
        with _StaticSite(context.target.workspace / injection.app_root) as site:
            for payload in injection.payloads:
                record: dict[str, Any] = {"payload": payload.model_dump(mode="json")}
                original: str | None = None
                try:
                    original = (context.target.workspace / payload.file).read_text()
                    _poison(context, payload)
                except (OSError, ValueError, KeyError) as error:
                    checks.append(
                        self.unavailable(
                            f"{payload.name}: the seed file could not be prepared ({error})",
                            suffix=payload.name,
                        )
                    )
                    continue
                seeded = request(
                    context.service_base_url, method or "POST", seed_path or "/", body={}
                )
                record["seed"] = seeded.to_dict()
                try:
                    executed, reached, console = _render_and_probe(
                        sync_playwright,
                        site.url(injection.page),
                        injection.marker,
                        injection.settle_ms,
                        payload.value,
                    )
                except PlaywrightError as error:
                    checks.append(
                        self.unavailable(
                            f"{payload.name}: the browser could not load the interface ({error})",
                            suffix=payload.name,
                        )
                    )
                    continue
                finally:
                    # The payload was written into the workspace copy for this check only.
                    # Leaving it there would let one check's input become another's finding.
                    if original is not None:
                        (context.target.workspace / payload.file).write_text(original)
                record["marker_set"] = executed
                record["payload_reached_the_page"] = reached
                record["console"] = console[:40]
                ref = context.save_evidence_json(self.id, f"{payload.name}.json", record)
                limitation = (
                    "one authored payload rendered by a real browser against a locally started "
                    "instance; it proves this value executes, not that every value does"
                )
                if not executed and not reached:
                    checks.append(
                        self.unavailable(
                            f"{payload.name}: the payload never reached the rendered page, so "
                            "nothing was attempted against the interface and its handling of "
                            "the payload was neither shown nor ruled out",
                            suffix=payload.name,
                        )
                    )
                    continue
                if not executed:
                    checks.append(
                        self.verified(
                            f"{payload.name}: the payload reached the page and was rendered as "
                            "data rather than executed",
                            limitation,
                            suffix=payload.name,
                            evidence_refs=[ref],
                        )
                    )
                    continue
                checks.append(
                    self.failed(
                        f"{payload.name}: the payload executed in the browser",
                        limitation,
                        suffix=payload.name,
                        evidence_refs=[ref],
                    )
                )
                findings.append(
                    self.finding(
                        title=f"Stored data executes as script in the interface: {payload.name}",
                        category="security",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        summary=(
                            f"{payload.description or payload.name}. A value placed at "
                            f"{payload.pointer} in {payload.file} and loaded through the "
                            f"artifact's own seed path set `window.{injection.marker}` when the "
                            "interface rendered it, which means the value was parsed as code "
                            "rather than displayed as text."
                        ),
                        evidence=json.dumps(record, indent=2)[:4000],
                        remediation=(
                            "Escape for the context the value lands in, or stop placing data "
                            "inside executable attributes. Remediation belongs to the artifact's "
                            "builder; HowlProof only reports and re-verifies."
                        ),
                        location=f"{injection.app_root}/{injection.page}",
                        rule=f"web.dom_injection.{payload.name}",
                        suffix=payload.name,
                        reproduction=Reproduction(
                            summary=(
                                "Write the payload into the seed file, seed the running service, "
                                f"load {injection.page} and read window.{injection.marker}."
                            ),
                            requires_service=True,
                            steps=[
                                ReproductionStep(
                                    description=f"Set {payload.pointer} in {payload.file} to the "
                                    "authored payload",
                                    kind="file_probe",
                                    payload={
                                        "path": payload.file,
                                        "pointer": payload.pointer,
                                        "value": payload.value,
                                    },
                                    expect={"matches": True},
                                ),
                                ReproductionStep(
                                    description=f"{method} {seed_path}",
                                    kind="http_request",
                                    payload={
                                        "method": method or "POST",
                                        "path": seed_path or "/",
                                        "body": {},
                                    },
                                    expect={},
                                ),
                                ReproductionStep(
                                    description=(
                                        f"Load {injection.app_root}/{injection.page} in a "
                                        f"browser and read window.{injection.marker}"
                                    ),
                                    kind="command",
                                    payload={"marker": injection.marker, "page": injection.page},
                                    expect={"marker_set": True},
                                ),
                            ],
                        ),
                    )
                )
        return Outcome(checks=checks, findings=findings)


def _poison(context: Context, payload: Any) -> None:
    """Write the authored payload into the workspace copy. The original tree is untouched."""
    path = context.target.workspace / payload.file
    document = json.loads(path.read_text())
    parts = [part for part in payload.pointer.split("/") if part]
    cursor: Any = document
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    last = parts[-1]
    if isinstance(cursor, list):
        cursor[int(last)] = payload.value
    else:
        cursor[last] = payload.value
    path.write_text(json.dumps(document))


def _render_and_probe(
    sync_playwright: Any, url: str, marker: str, settle_ms: int, payload: str
) -> tuple[bool, bool, list[str]]:
    """Load the interface and report whether the payload executed, and whether it arrived.

    The two answers are different. A payload that never reached the page proves
    nothing about how the page handles it, and must not be reported as safe.
    """
    console: list[str] = []
    needle = payload.strip().strip("'\"")[:40]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(settle_ms)

        def fired() -> bool:
            return bool(page.evaluate(f"() => Boolean(window.{marker})"))

        def arrived() -> bool:
            return bool(
                page.evaluate(
                    "(needle) => document.documentElement.innerHTML.includes(needle)", needle
                )
            )

        executed, reached = fired(), arrived()
        if not executed:
            # Handler attributes only run when the element is activated, and a list
            # interface may only build the detail view once a row is opened. Elements
            # carrying a handler are tried first; page chrome is tried after.
            for selector in ("[onclick]", "button"):
                elements = page.locator(selector)
                for index in range(min(elements.count(), 20)):
                    try:
                        elements.nth(index).click(timeout=1500)
                        page.wait_for_timeout(300)
                    except Exception:  # noqa: BLE001, S112 - non-clickable is expected
                        continue
                    reached = reached or arrived()
                    if fired():
                        executed = True
                        break
                if executed:
                    break
        browser.close()
    return executed, reached, console


class _StaticSite:
    """Serve a directory from the workspace so a browser can load the real interface."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.server: ThreadingHTTPServer | None = None
        self.port = 0

    def __enter__(self) -> Self:
        handler = partial(_QuietHandler, directory=str(self.root))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_: object) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def url(self, page: str) -> str:
        return f"http://127.0.0.1:{self.port}/{page}"


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        return


def _probe_external(urls: list[str]) -> list[dict[str, Any]]:
    results = []
    for url in urls[:100]:
        if not url.startswith(("http://", "https://")):
            continue
        base, _, path = url.partition("/")[0], "", ""
        parts = url.split("/", 3)
        base = "/".join(parts[:3])
        path = "/" + (parts[3] if len(parts) > 3 else "")
        response = request(base, "GET", path, timeout=10)
        results.append({"url": url, "status": response.status, "error": response.error})
    return results


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


EVALUATORS: list[Evaluator] = [WebLinks(), WebMetadata(), WebResponsive(), DomInjection()]
