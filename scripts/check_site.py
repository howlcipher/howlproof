"""Rendered checks on the published site. Screenshots stay local.

A page that was never rendered has not been shown to work at any width, so this
script fails loudly rather than skipping when a browser is unavailable.
"""

import argparse
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

WIDTHS = (375, 768, 1440)
ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="check a deployed site instead of the local files")
    parser.add_argument("--page", default="index.html")
    arguments = parser.parse_args()

    url = arguments.url or (ROOT / "docs" / arguments.page).as_uri()
    screenshots = ROOT / "screenshots"
    screenshots.mkdir(exist_ok=True)
    failures: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in WIDTHS:
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors: list[str] = []
            page.on(
                "console",
                lambda message: errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.goto(url, wait_until="networkidle")

            def check(condition: bool, description: str) -> None:
                if not condition:
                    failures.append(f"{width}px: {description}")

            check(page.locator("h1").count() == 1, "there is not exactly one h1")
            check(bool(page.title()), "the document has no title")
            check(
                bool(page.locator('meta[name="description"]').get_attribute("content")),
                "there is no meta description",
            )
            check(page.locator("main").is_visible(), "the main landmark is not visible")
            check(
                page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"),
                "the document scrolls horizontally",
            )
            for link in page.locator('a[href^="#"]').all():
                fragment = (link.get_attribute("href") or "#")[1:]
                if fragment:
                    check(
                        page.locator(f'[id="{fragment}"]').count() == 1,
                        f"#{fragment} resolves to no unique element",
                    )
            page.keyboard.press("Tab")
            focused = page.evaluate(
                "() => (document.activeElement && document.activeElement.className) || ''"
            )
            check("skip-link" in focused, f"the first tab stop is not the skip link ({focused!r})")
            check(not errors, f"the page logged console errors: {errors[:3]}")

            page.screenshot(path=str(screenshots / f"site_{width}.png"), full_page=True)
            print(f"rendered {width}px -> screenshots/site_{width}.png")
            page.close()

        # The theme toggle and the ecosystem drawer are the only interactive parts.
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto(url, wait_until="networkidle")
        page.click("#theme-toggle")
        if page.evaluate("document.documentElement.getAttribute('data-theme')") != "dark":
            failures.append("the theme toggle does not switch to dark")
        page.click("#eco-menu-toggle")
        if page.get_attribute("#eco-drawer", "aria-hidden") != "false":
            failures.append("the ecosystem drawer does not open")
        page.click("#eco-drawer-close")
        if page.get_attribute("#eco-drawer", "aria-hidden") != "true":
            failures.append("the ecosystem drawer does not close")
        page.close()
        browser.close()

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(f"PASS {', '.join(f'{w}px' for w in WIDTHS)}: one h1, landmarks, fragments, keyboard, "
          "no overflow, no console errors, theme and drawer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
