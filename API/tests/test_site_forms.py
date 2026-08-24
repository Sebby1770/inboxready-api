"""Contact form capture, validation, and the lead store."""

from __future__ import annotations

import json

import pytest

from _html import Html
from inboxready_api.site.leads import (
    LeadStore,
    LeadValidationError,
    configure_leads,
    get_leads,
    validate,
)

VALID = {
    "name": "Dana Okafor",
    "email": "dana@example.com",
    "company": "Example Co",
    "topic": "Integration help",
    "message": "We want to gate activation on the audit score. What threshold do you suggest?",
}


@pytest.fixture(autouse=True)
def fresh_store():
    configure_leads(max_entries=50, path=None)
    yield
    configure_leads(max_entries=50, path=None)


def test_valid_submission_is_stored(client) -> None:
    response = client.post("/contact", data=VALID, follow_redirects=False)

    assert response.status_code == 303
    stored = get_leads().list()
    assert len(stored) == 1
    assert stored[0].email == "dana@example.com"
    assert stored[0].topic == "Integration help"
    assert stored[0].received_at.endswith("Z")


def test_invalid_submission_re_renders_the_form_with_the_reason(client) -> None:
    response = client.post(
        "/contact",
        data={**VALID, "email": "not-an-email"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    page = Html(response.text)
    assert "does not look right" in page.text
    # The visitor's typing must survive the round trip.
    assert VALID["message"] in page.text
    assert not get_leads().list()


def test_short_messages_are_rejected(client) -> None:
    response = client.post("/contact", data={**VALID, "message": "hi"}, follow_redirects=False)

    assert response.status_code == 400
    assert "at least a sentence" in Html(response.text).text
    assert not get_leads().list()


def test_honeypot_submissions_are_dropped_silently(client) -> None:
    """A bot gets the same redirect a human does, and nothing is stored."""
    response = client.post(
        "/contact",
        data={**VALID, "website": "https://spam.example"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/thank-you?ref=contact"
    assert not get_leads().list()


def test_validation_trims_and_bounds_input() -> None:
    lead = validate(
        name="  Dana   Okafor  ",
        email=" dana@example.com ",
        company="",
        topic="",
        message="  A message with plenty of substance in it.  ",
    )

    assert lead.name == "Dana Okafor"
    assert lead.email == "dana@example.com"
    assert lead.topic == "General"
    assert lead.message == "A message with plenty of substance in it."


def test_validation_rejects_missing_name() -> None:
    with pytest.raises(LeadValidationError, match="your name"):
        validate(name="   ", email="a@b.com", company="", topic="", message="A long enough message.")


def test_oversized_messages_are_truncated_not_rejected() -> None:
    lead = validate(name="Dana", email="a@b.com", company="", topic="", message="x" * 9000)
    assert len(lead.message) == 4000


def test_store_persists_and_reloads(tmp_path) -> None:
    path = tmp_path / "leads.json"
    store = LeadStore(max_entries=10, path=path)
    store.add(validate(**{**VALID, "message": VALID["message"]}))

    assert json.loads(path.read_text())[0]["email"] == "dana@example.com"

    reloaded = LeadStore(max_entries=10, path=path)
    assert len(reloaded) == 1
    assert reloaded.list()[0].name == "Dana Okafor"


def test_store_is_bounded(tmp_path) -> None:
    store = LeadStore(max_entries=3, path=None)
    for index in range(6):
        store.add(validate(name=f"P{index}", email=f"p{index}@example.com", company="",
                           topic="", message="A message with enough substance."))

    assert len(store) == 3
    assert [lead.name for lead in store.list()] == ["P5", "P4", "P3"]


def test_corrupt_persistence_file_does_not_crash_startup(tmp_path) -> None:
    path = tmp_path / "leads.json"
    path.write_text("{not json", encoding="utf-8")

    store = LeadStore(max_entries=5, path=path)
    assert len(store) == 0
