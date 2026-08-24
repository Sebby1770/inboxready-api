.PHONY: install run test lint fmt check og-card site

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e ".[dev]"

run:
	. .venv/bin/activate && uvicorn --app-dir src inboxready_api.main:app --reload

test:
	. .venv/bin/activate && pytest

lint:
	. .venv/bin/activate && ruff check src tests scripts ../.github/scripts

fmt:
	. .venv/bin/activate && ruff check --fix src tests scripts ../.github/scripts

# Render the public site to ../_site, exactly as the Pages workflow does.
site:
	. .venv/bin/activate && python scripts/build_static.py --out ../_site
	. .venv/bin/activate && python ../.github/scripts/check_links.py ../_site
	@echo "Serve it with: python3 -m http.server -d ../_site 8080"

# What CI runs.
check: lint test

# Optional: rasterise the social card for the crawlers that still ignore SVG.
# Needs rsvg-convert (librsvg) or cairosvg on PATH.
og-card:
	@if command -v rsvg-convert >/dev/null 2>&1; then \
		rsvg-convert -w 1200 -h 630 src/inboxready_api/static/img/social-card.svg \
			-o src/inboxready_api/static/img/social-card.png && echo "wrote social-card.png"; \
	elif command -v cairosvg >/dev/null 2>&1; then \
		cairosvg src/inboxready_api/static/img/social-card.svg -W 1200 -H 630 \
			-o src/inboxready_api/static/img/social-card.png && echo "wrote social-card.png"; \
	else \
		echo "install librsvg (rsvg-convert) or cairosvg to rasterise the card"; exit 1; \
	fi
