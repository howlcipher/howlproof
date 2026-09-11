#!/usr/bin/env python3
"""
SEO & Search Discoverability Verification Suite for HowlProof.
Validates structured data, canonical tags, sitemap, robots.txt, and entity linking.
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(REPO_ROOT, "docs")
INDEX_HTML = os.path.join(DOCS_DIR, "index.html")
ROBOTS_TXT = os.path.join(DOCS_DIR, "robots.txt")
SITEMAP_XML = os.path.join(DOCS_DIR, "sitemap.xml")


def test_seo():
    print("=== Running HowlProof SEO Verification ===")

    # 1. Check docs/index.html
    assert os.path.exists(INDEX_HTML), f"Missing {INDEX_HTML}"
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html = f.read()

    # Title check
    title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    assert title_match, "Missing <title> tag in index.html"
    title = title_match.group(1).strip()
    assert "HowlProof" in title, f"Title does not mention HowlProof: {title}"
    print(f"  [PASS] HTML <title> exists: {title}")

    # Meta description check
    meta_desc_match = re.search(
        r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']',
        html,
        re.IGNORECASE,
    )
    assert meta_desc_match, "Missing meta description in index.html"
    meta_desc = meta_desc_match.group(1).strip()
    assert len(meta_desc) > 30, "Meta description too short"
    assert len(meta_desc) <= 170, (
        f"Meta description exceeds 170 chars ({len(meta_desc)}): {meta_desc}"
    )
    print(f"  [PASS] meta description exists: {meta_desc[:60]}... ({len(meta_desc)} chars)")

    # Canonical URL check
    canonical_match = re.search(
        r'<link\s+rel=["\']canonical["\']\s+href=["\'](.*?)["\']',
        html,
        re.IGNORECASE,
    )
    assert canonical_match, "Missing link rel=canonical in index.html"
    canonical_url = canonical_match.group(1).strip()
    expected_canonical = "https://howlcipher.github.io/howlproof/"
    assert canonical_url == expected_canonical, (
        f"Canonical URL mismatch: expected {expected_canonical}, got {canonical_url}"
    )
    print(f"  [PASS] Canonical URL matches: {canonical_url}")

    # Heading hierarchy check
    h1_matches = re.findall(r"<h1[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
    assert len(h1_matches) == 1, f"Expected exactly 1 <h1> tag, found {len(h1_matches)}"
    clean_h1 = re.sub(r"<[^>]+>", "", h1_matches[0]).strip()
    print(f"  [PASS] Exactly 1 H1 present: {clean_h1}")

    # Open Graph & Twitter Cards
    assert 'property="og:title"' in html or "property='og:title'" in html, "Missing og:title"
    assert 'property="og:description"' in html or "property='og:description'" in html, (
        "Missing og:description"
    )
    assert 'property="og:url"' in html or "property='og:url'" in html, "Missing og:url"
    assert 'name="twitter:card"' in html or "name='twitter:card'" in html, "Missing twitter:card"
    print("  [PASS] Open Graph and Twitter card tags verified")

    # JSON-LD Schema.org Structured Data
    json_ld_matches = re.findall(
        r'<script\s+type=["\']application/ld\+json["\']\s*>(.*?)</script>',
        html,
        re.IGNORECASE | re.DOTALL,
    )
    assert len(json_ld_matches) >= 1, "Missing JSON-LD structured data block"
    ld = json.loads(json_ld_matches[0].strip())
    assert ld.get("@context") in ("https://schema.org", "http://schema.org"), "Invalid @context"
    ld_type = ld.get("@type")
    assert ld_type == "SoftwareApplication", f"Expected SoftwareApplication, got {ld_type}"
    author = ld.get("author", {})
    expected_author = "William" + " " + "Elias"
    assert author.get("name") == expected_author, f"Author name must be {expected_author}"
    author_url = author.get("url")
    expected_author_url = "https://howlcipher.github.io/william_elias/"
    assert author_url == expected_author_url, "Author URL must point to william_elias portfolio"
    print(f"  [PASS] JSON-LD valid and correctly attributes {expected_author}")

    # Internal entity links
    william_url = "https://howlcipher.github.io/william_elias/"
    assert william_url in html, f"Missing link to William Elias portfolio ({william_url})"
    howl_url = "https://howlcipher.github.io/howl/"
    assert howl_url in html, f"Missing link to Howl hub ({howl_url})"
    print("  [PASS] Internal entity links to William Elias and Howl verified")

    # 2. Check docs/robots.txt
    assert os.path.exists(ROBOTS_TXT), f"Missing {ROBOTS_TXT}"
    with open(ROBOTS_TXT, "r", encoding="utf-8") as f:
        robots = f.read()
    assert "User-agent: *" in robots, "robots.txt missing User-agent: *"
    assert "Allow: /" in robots, "robots.txt missing Allow: /"
    assert "Sitemap: https://howlcipher.github.io/howlproof/sitemap.xml" in robots, (
        "robots.txt missing correct Sitemap directive"
    )
    print("  [PASS] docs/robots.txt valid and references sitemap")

    # 3. Check docs/sitemap.xml
    assert os.path.exists(SITEMAP_XML), f"Missing {SITEMAP_XML}"
    tree = ET.parse(SITEMAP_XML)
    root = tree.getroot()
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [elem.text.strip() for elem in root.findall(".//sm:loc", namespace)]
    assert expected_canonical in locs, (
        f"sitemap.xml does not contain canonical URL {expected_canonical}"
    )
    print("  [PASS] docs/sitemap.xml valid and contains canonical URL")

    print("\nAll SEO validations PASSED successfully!\n")


if __name__ == "__main__":
    try:
        test_seo()
    except AssertionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - a script reports any failure and exits non-zero
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
