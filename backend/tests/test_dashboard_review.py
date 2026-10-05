import functools

import pytest
from sqlalchemy import func, select, text

from app.db import engine
from app.llm import client as llm_client
from app.models import CompanyReview
from tests.test_dashboard_api import upload_and_analyze, week
from tests.test_llm_client import FakeClient

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


@pytest.fixture(scope="module")
def attack_week() -> bytes:
    return week()


def use_fake_claude(monkeypatch, answer) -> FakeClient:
    fake = FakeClient(answer)
    monkeypatch.setattr("app.api.dashboard.summarize", functools.partial(llm_client.summarize, client=fake))
    return fake


def test_no_review_yet_is_null(logged_in):
    assert logged_in.get("/api/dashboard/review").json() is None


def test_without_a_key_the_template_review_is_stored(logged_in, storage, attack_week):
    upload_and_analyze(logged_in, storage, attack_week, "w.csv")

    review = logged_in.post("/api/dashboard/review").json()

    assert review["source"] == "template" and review["model"] is None and review["stale"] is False
    assert review["summary"].startswith(tuple("123456789")) and review["created_by"] == "analyst"
    assert logged_in.get("/api/dashboard/review").json()["id"] == review["id"]


def test_an_ai_review_covers_the_company_with_real_names(logged_in, storage, attack_week, monkeypatch):
    upload_and_analyze(logged_in, storage, attack_week, "w.csv")
    fake = use_fake_claude(monkeypatch, {"summary": "user_1 needs attention first.", "incidents": []})

    review = logged_in.post("/api/dashboard/review").json()

    assert (review["source"], review["summary"]) == ("ai", "jdoe needs attention first.")
    content = fake.calls[0]["messages"][0]["content"]
    assert "Write the summary of all analyzed logs of the company." in content
    assert "jdoe" not in content  # stand-ins, as for per-upload summaries
    # An accurately named company overview, not a per-upload section ("The upload covers…").
    assert '"overview"' in content and '"upload"' not in content
    assert '"users_with_incidents"' in content and '"datasets": 1' in content


def test_a_double_click_writes_one_review(logged_in, storage, attack_week, monkeypatch, db_session):
    upload_and_analyze(logged_in, storage, attack_week, "w.csv")
    fake = use_fake_claude(monkeypatch, {"summary": "Fine.", "incidents": []})

    first = logged_in.post("/api/dashboard/review").json()
    second = logged_in.post("/api/dashboard/review").json()

    assert first["id"] == second["id"] and len(fake.calls) == 1
    assert db_session.scalar(select(func.count()).select_from(CompanyReview)) == 1


def test_a_review_becomes_stale_when_new_incidents_arrive(logged_in, storage, attack_week):
    upload_and_analyze(logged_in, storage, attack_week, "w.csv")
    logged_in.post("/api/dashboard/review")
    assert logged_in.get("/api/dashboard/review").json()["stale"] is False

    upload_and_analyze(logged_in, storage, attack_week, "copy.csv")  # same incidents: still fresh
    assert logged_in.get("/api/dashboard/review").json()["stale"] is False

    with engine.begin() as conn:  # a new analysis changed the picture (simulated: one score moved)
        conn.execute(text("UPDATE incidents SET priority_score = priority_score * 0.5 WHERE priority = 'low'"))
    assert logged_in.get("/api/dashboard/review").json()["stale"] is True


def test_requires_login(client):
    assert client.get("/api/dashboard/review").status_code == 401
    assert client.post("/api/dashboard/review").status_code == 401


def test_on_demand_reviews_get_the_longer_timeout(logged_in, storage, attack_week, monkeypatch):
    from app.config import get_settings

    upload_and_analyze(logged_in, storage, attack_week, "w.csv")
    seen = []

    def fake_summarize(*args, **kwargs):
        seen.append(kwargs["timeout"])
        return llm_client.summarize(*args, **{**kwargs, "api_key": ""})  # template: no network

    monkeypatch.setattr("app.api.dashboard.summarize", fake_summarize)
    monkeypatch.setattr("app.api.users.summarize", fake_summarize)
    logged_in.post("/api/dashboard/review")
    logged_in.post("/api/users/jdoe/review")

    settings = get_settings()
    assert seen == [settings.llm_review_timeout_seconds] * 2 == [90.0, 90.0]
    assert settings.llm_timeout_seconds == 30.0  # the worker's per-upload summary keeps its own limit


def test_reviews_carry_structured_sections(logged_in, storage, attack_week, monkeypatch):
    upload_and_analyze(logged_in, storage, attack_week, "w.csv")

    template = logged_in.post("/api/dashboard/review").json()  # no key: the template's sections
    assert template["headline"] and template["key_findings"] and template["actions"]
    assert template["key_findings"][0]["priority"] == "critical"
    assert logged_in.get("/api/dashboard/review").json()["key_findings"] == template["key_findings"]

    with engine.begin() as conn:  # not a double click
        conn.execute(text("UPDATE company_reviews SET created_at = created_at - interval '2 minutes'"))
    use_fake_claude(monkeypatch, {"summary": "Fine.", "incidents": [], "headline": "user_1 needs attention.",
                                  "key_findings": [{"priority": "high", "text": "user_1 uploaded 400 MB."}],
                                  "recommended_actions": ["Call user_1's manager."]})
    ai = logged_in.post("/api/dashboard/review").json()
    assert (ai["headline"], ai["key_findings"], ai["actions"]) == (
        "jdoe needs attention.", [{"priority": "high", "text": "jdoe uploaded 400 MB."}], ["Call jdoe's manager."])
