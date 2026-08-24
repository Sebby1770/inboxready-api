#!/usr/bin/env python3
"""Fail the publish if the built site contains a broken internal link.

A static export is exactly where dead links appear: a page moves, a template
still points at the old path, and nothing complains until a visitor finds it.
This walks every generated HTML file, collects the site-local `href` and `src`
targets, and resolves them against what is actually on disk.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

REF = re.compile(r'(?:href|src)="([^"]+)"')


def is_internal(target: str) -> bool:
    if not target or target.startswith(("#", "mailto:", "tel:", "data:", "//")):
        return False
    return not urlsplit(target).scheme


def resolve(root: Path, base_path: str, target: str) -> Path | None:
    """Map a URL onto the file GitHub Pages would serve for it."""
    path = unquote(urlsplit(target).path)
    if not path:
        return None
    if base_path and path.startswith(base_path):
        path = path[len(base_path) :]
    candidate = root / path.lstrip("/")
    if candidate.is_dir():
        return candidate / "index.html"
    if candidate.suffix:
        return candidate
    # Extensionless: Pages redirects to the directory form.
    return candidate.with_suffix("") / "index.html"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_links.py <site-dir> [base-path]", file=sys.stderr)
        return 2

    root = Path(argv[1]).resolve()
    pages = sorted(root.rglob("*.html"))
    if not pages:
        print(f"no HTML found under {root}", file=sys.stderr)
        return 1

    # Infer the base path from the home page's own canonical link.
    base_path = argv[2] if len(argv) > 2 else ""
    if not base_path:
        home = (root / "index.html").read_text(encoding="utf-8")
        match = re.search(r'<link rel="canonical" href="([^"]+)"', home)
        if match:
            base_path = urlsplit(match.group(1)).path.rstrip("/")

    broken: list[tuple[str, str]] = []
    checked = 0
    for page in pages:
        html = page.read_text(encoding="utf-8")
        for target in REF.findall(html):
            if not is_internal(target):
                continue
            checked += 1
            resolved = resolve(root, base_path, target)
            if resolved is not None and not resolved.exists():
                broken.append((str(page.relative_to(root)), target))

    print(f"checked {checked} internal references across {len(pages)} pages")
    if broken:
        print(f"\n{len(broken)} broken link(s):", file=sys.stderr)
        for source, target in sorted(set(broken)):
            print(f"  {source} -> {target}", file=sys.stderr)
        return 1

    print("no broken internal links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
