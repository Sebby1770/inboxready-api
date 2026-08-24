"""Dependency-free HTML query helpers for the site test suites.

A real parser would be nicer, but the point of this suite is to guard the
public surface without adding a test-only dependency that CI has to install.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass
class Tag:
    name: str
    attrs: dict[str, str]
    start: int


class _Collector(HTMLParser):
    """Minimal DOM-free tag collector — no third-party parser required."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[Tag] = []
        self.texts: list[tuple[str, str]] = []
        self._stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        offset = self.getpos()[1] + sum(len(line) + 1 for line in self._lines[: self.getpos()[0] - 1])
        self.tags.append(Tag(tag, {k: (v or "") for k, v in attrs}, offset))
        self._stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if self._stack and tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass

    def handle_data(self, data: str) -> None:
        if self._stack:
            self.texts.append((self._stack[-1], data))


class Html:
    """Tiny query helper over a rendered page."""

    def __init__(self, markup: str) -> None:
        self.raw = markup
        #: Entity-decoded view, for asserting on copy that contains an
        #: apostrophe or a URL with an ampersand in it.
        self.text = html.unescape(markup)
        parser = _Collector()
        parser._lines = markup.splitlines()  # type: ignore[attr-defined]
        parser.feed(markup)
        self.tags = parser.tags
        self.texts = parser.texts

    def find_all(self, name: str, **attrs: str) -> list[Tag]:
        result = []
        for tag in self.tags:
            if tag.name != name:
                continue
            if all(tag.attrs.get(key) == value for key, value in attrs.items()):
                result.append(tag)
        return result

    def meta(self, *, name: str = "", property: str = "") -> str | None:
        key, wanted = ("name", name) if name else ("property", property)
        for tag in self.find_all("meta"):
            if tag.attrs.get(key) == wanted:
                return tag.attrs.get("content", "")
        return None

    def title(self) -> str:
        for tag_name, text in self.texts:
            if tag_name == "title":
                return text.strip()
        return ""

    def links(self) -> list[str]:
        return [tag.attrs.get("href", "") for tag in self.find_all("a")]

    def internal_links(self) -> list[str]:
        return [
            href.split("#")[0].split("?")[0]
            for href in self.links()
            if href.startswith("/") and not href.startswith("//")
        ]

    def json_ld(self) -> dict:
        marker = '<script type="application/ld+json">'
        start = self.raw.index(marker) + len(marker)
        end = self.raw.index("</script>", start)
        return json.loads(self.raw[start:end])

    def graph(self, type_name: str) -> list[dict]:
        return [node for node in self.json_ld()["@graph"] if node.get("@type") == type_name]
