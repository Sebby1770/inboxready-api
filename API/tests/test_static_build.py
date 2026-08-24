"""The static export used to publish the site on GitHub Pages.

The builder is run as a subprocess on purpose: it sets INBOXREADY_* variables
and imports the app to pick them up, so running it in-process would leave the
cached Settings of every other test pointing at a static build.
"""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1]
BUILDER = API_DIR / "scripts" / "build_static.py"
LINK_CHECKER = API_DIR.parent / ".github" / "scripts" / "check_links.py"

BASE_URL = "https://example.github.io/inboxready-api"
BASE_PATH = "/inboxready-api"


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site") / "build"
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--out", str(out), "--base-url", BASE_URL],
        cwd=API_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    return out


def read(site: Path, relative: str) -> str:
    target = site / relative
    assert target.exists(), f"{relative} was not generated"
    return target.read_text(encoding="utf-8")


def test_every_registered_page_is_exported(site: Path) -> None:
    from inboxready_api.site.pages import ALL_PAGES

    for page in ALL_PAGES:
        expected = "index.html" if page.path == "/" else f"{page.path.strip('/')}/index.html"
        assert (site / expected).exists(), f"{page.path} missing from the export"


def test_crawler_and_error_surfaces_are_exported(site: Path) -> None:
    # GitHub Pages serves /404.html for unknown paths, so the custom 404 carries over.
    assert "Page not found" in read(site, "404.html")
    assert "Sitemap:" in read(site, "robots.txt")
    assert read(site, "sitemap.xml").startswith("<?xml")
    assert (site / ".nojekyll").exists(), "without .nojekyll, Jekyll eats underscore paths"


def test_links_are_rewritten_onto_the_base_path(site: Path) -> None:
    home = read(site, "index.html")
    assert 'href="/inboxready-api/pricing"' in home
    assert 'href="/inboxready-api/static/css/site.css"' in home
    # The TestClient's own origin must never leak into the published HTML.
    assert "testserver" not in home


def test_canonicals_and_social_urls_are_absolute(site: Path) -> None:
    pricing = read(site, "pricing/index.html")
    assert f'<link rel="canonical" href="{BASE_URL}/pricing">' in pricing
    assert f'content="{BASE_URL}/static/img/social-card.svg"' in pricing


def test_sitemap_points_at_the_published_origin(site: Path) -> None:
    root = ET.fromstring(read(site, "sitemap.xml"))
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    locations = [element.text or "" for element in root.iter(f"{namespace}loc")]
    assert locations
    assert all(loc.startswith(BASE_URL) for loc in locations)


def test_robots_rules_are_scoped_to_the_project_path(site: Path) -> None:
    body = read(site, "robots.txt")
    assert f"Allow: {BASE_PATH}/" in body
    assert f"Disallow: {BASE_PATH}/v1/" in body


def test_api_reference_is_generated_from_the_live_schema(site: Path) -> None:
    schema = json.loads(read(site, "openapi.json"))
    assert "/v1/audits/email-domain" in schema["paths"]
    docs = read(site, "docs/index.html")
    assert f'"{BASE_PATH}/openapi.json"' in docs


def test_static_pages_declare_they_have_no_backend(site: Path) -> None:
    assert 'data-static-build="true"' in read(site, "index.html")

    contact = read(site, "contact/index.html")
    assert "mailto:hello@inboxready.dev" in contact
    assert "<form" not in contact, "a form with no backend is a dead end"
    # The parts that do not need a server must survive intact.
    assert "static-map" in contact
    assert "maps/dir" in contact


def test_dead_claims_are_dropped_rather_than_left_broken(site: Path) -> None:
    """The live health probes are a real trust signal, and a dead link here."""
    home = read(site, "index.html")
    assert 'href="/inboxready-api/healthz"' not in home
    assert "Health you can verify yourself" not in home
    # The remaining, checkable signals stay.
    assert "Source available" in home


def test_static_assets_are_copied(site: Path) -> None:
    for asset in (
        "static/css/site.css",
        "static/css/home.css",
        "static/js/app.js",
        "static/js/home.js",
        "static/img/social-card.svg",
        "static/img/team/team-photo.svg",
    ):
        assert (site / asset).exists(), f"{asset} missing from the export"


def test_no_internal_link_is_broken(site: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(LINK_CHECKER), str(site)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no broken internal links" in result.stdout
