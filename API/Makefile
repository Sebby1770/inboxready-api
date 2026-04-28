.PHONY: install run test

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e ".[dev]"

run:
	. .venv/bin/activate && uvicorn --app-dir src inboxready_api.main:app --reload

test:
	. .venv/bin/activate && pytest
