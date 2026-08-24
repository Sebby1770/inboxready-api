#!/usr/bin/env python3
"""Render the InboxReady site to static files for GitHub Pages.

The site is a FastAPI app, but every marketing page is a pure function of the
page registry — nothing on them needs a request at view time. So the whole
public surface can be rendered once and served as files.

What survives the export: all twelve pages, breadcrumbs, structured data,
`robots.txt`, `sitemap.xml`, the custom 404, and a Redoc API reference built
from the live OpenAPI schema.

What cannot: running an audit, and the contact form. Both need a backend. The
build sets ``INBOXREADY_STATIC_BUILD``, which swaps those surfaces for honest
alternatives rather than leaving buttons that 404. Pass ``--api-base`` pointing
at a deployed instance and the audit form comes back to life against it.

Usage
-----
    python scripts/build_static.py --out ../_site \
        --base-url https://sebby1770.github.io/inboxready-api
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO_API_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_API_DIR / "src"

#: TestClient renders absolute URLs against this host; they get stripped out.
TEST_ORIGIN = "http://testserver"

#: Rewrite root-relative href/src/action targets onto the published base path.
_ROOT_REF = re.compile(r'((?:href|src|action)=")(/(?!/)[^"]*)(")')


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_API_DIR.parent / "_site",
        help="Output directory (wiped and recreated).",
    )
    parser.add_argument(
        "--base-url",
        default="https://sebby1770.github.io/inboxready-api",
        help="Absolute URL the site will be served from.",
    )
    parser.add_argument(
        "--api-base",
        default="",
        help="Origin of a running InboxReady API, if the static pages should call one.",
    )
    parser.add_argument(
        "--analytics-id",
        default="",
        help="GA4 measurement ID to embed (consent-gated). Omit for no analytics.",
    )
    return parser.parse_args(argv)


def configure_environment(args: argparse.Namespace) -> None:
    """Settings are read once and cached, so the environment comes first."""
    os.environ["INBOXREADY_STATIC_BUILD"] = "true"
    os.environ["INBOXREADY_ENVIRONMENT"] = "production"
    os.environ["INBOXREADY_SITE_BASE_URL"] = args.base_url.rstrip("/")
    os.environ["INBOXREADY_API_BASE_URL"] = args.api_base.rstrip("/")
    os.environ["INBOXREADY_ANALYTICS_GA4_ID"] = args.analytics_id
    # A file on disk cannot rate-limit anything; keep the rendered copy honest.
    os.environ["INBOXREADY_RATE_LIMIT_PER_MINUTE"] = "0"


def base_path_of(base_url: str) -> str:
    """`https://user.github.io/repo` -> `/repo`; a custom domain -> ``""``."""
    return urlsplit(base_url).path.rstrip("/")


def rewrite(html: str, base_path: str) -> str:
    html = html.replace(TEST_ORIGIN, "")
    if not base_path:
        return html
    return _ROOT_REF.sub(rf"\1{base_path}\2\3", html)


def rewrite_robots(body: str, base_path: str) -> str:
    """Prefix the rule paths with the published base path.

    Worth knowing: a GitHub Pages *project* site cannot serve the origin's
    `robots.txt` — crawlers read `https://user.github.io/robots.txt`, not
    `.../<repo>/robots.txt`. This file is still written so the export is
    complete and correct if the site later moves to a custom domain or the
    user's `<user>.github.io` root repository, but until then it is
    informational. Submit `sitemap.xml` directly in Search Console instead.
    """
    if not base_path:
        return body
    lines = []
    for line in body.splitlines():
        for directive in ("Allow:", "Disallow:"):
            if line.startswith(directive):
                target = line[len(directive) :].strip()
                line = f"{directive} {base_path}{target}" if target != "/" else f"{directive} {base_path}/"
                break
        lines.append(line)
    return "\n".join(lines) + "\n"


def write(out: Path, relative: str, content: str) -> Path:
    target = out / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def page_filename(path: str) -> str:
    """`/` -> `index.html`, `/pricing` -> `pricing/index.html`."""
    if path == "/":
        return "index.html"
    return f"{path.strip('/')}/index.html"


REDOC_TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>API reference · InboxReady</title>
    <meta name="description" content="Every InboxReady endpoint, request body, and response schema, generated from the live OpenAPI document.">
    <link rel="icon" type="image/svg+xml" href="{base_path}/static/img/favicon.svg">
    <style>
      body {{ margin: 0; font-family: system-ui, sans-serif; }}
      .back {{
        display: block; padding: 0.9rem 1.4rem; background: #0c1725; color: #fbf5ea;
        text-decoration: none; font-size: 0.92rem;
      }}
      .back:hover {{ text-decoration: underline; }}
    </style>
  </head>
  <body>
    <a class="back" href="{base_path}/">&larr; Back to InboxReady</a>
    <div id="redoc"></div>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
    <script>
      Redoc.init("{base_path}/openapi.json", {{ hideDownloadButton: false }}, document.getElementById("redoc"));
    </script>
  </body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_environment(args)

    sys.path.insert(0, str(SRC_DIR))
    from fastapi.testclient import TestClient  # noqa: PLC0415

    from inboxready_api.main import app  # noqa: PLC0415
    from inboxready_api.site.pages import ALL_PAGES  # noqa: PLC0415

    base_path = base_path_of(args.base_url)
    out: Path = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    client = TestClient(app)
    written: list[str] = []

    for page in ALL_PAGES:
        response = client.get(page.path)
        if response.status_code != 200:
            print(f"  !! {page.path} returned {response.status_code}", file=sys.stderr)
            return 1
        write(out, page_filename(page.path), rewrite(response.text, base_path))
        written.append(page.path)

    # GitHub Pages serves /404.html for anything it cannot find, which turns the
    # app's custom 404 into the host's custom 404 for free.
    not_found = client.get("/__not_found__")
    write(out, "404.html", rewrite(not_found.text, base_path))

    write(out, "sitemap.xml", client.get("/sitemap.xml").text)
    write(out, "robots.txt", rewrite_robots(client.get("/robots.txt").text, base_path))

    # The page inventory is genuinely useful to a link checker, so keep it.
    write(out, "site/pages.json", json.dumps(client.get("/site/pages").json(), indent=2))

    schema = client.get("/openapi.json").json()
    schema.setdefault("servers", [])
    if args.api_base:
        schema["servers"] = [{"url": args.api_base, "description": "Hosted API"}]
    write(out, "openapi.json", json.dumps(schema, indent=2))
    write(out, "docs/index.html", REDOC_TEMPLATE.format(base_path=base_path))

    shutil.copytree(SRC_DIR / "inboxready_api" / "static", out / "static")

    # Without this, Pages runs Jekyll and drops anything starting with an underscore.
    write(out, ".nojekyll", "")

    print(f"Built {len(written)} pages + 404, docs, sitemap, robots into {out}")
    print(f"  base url:  {args.base_url}")
    print(f"  base path: {base_path or '(root)'}")
    print(f"  api base:  {args.api_base or '(none — audit form explains itself)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
