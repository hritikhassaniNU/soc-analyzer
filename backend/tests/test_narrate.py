import io

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.generator import Generator, GeneratorConfig
from app.models import Incident, UploadSummary
from app.pipeline.analyze import analyze
from app.pipeline.narrate import run_narrative
from tests.test_llm_client import FakeClient
from tests.test_summary_api import upload

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9)).write(out)
    return out.getvalue().encode()


@pytest.fixture
def analyzed(client, analyst, sample, storage) -> int:
    client.post("/api/login", auth=GOOD)
    upload_id = upload(client, sample)
    analyze(upload_id, storage)
    return upload_id


def test_tests_never_see_the_real_key():
    assert not get_settings().anthropic_api_key  # conftest blanks it


def test_without_a_key_the_template_summary_is_stored(analyzed, db_session):
    summary = db_session.get(UploadSummary, analyzed)
    incidents = db_session.scalars(select(Incident).where(Incident.upload_id == analyzed)).all()

    assert summary.narrative["source"] == "template" and summary.narrative["model"] is None
    assert summary.narrative["summary"].startswith(tuple("123456789"))  # "N incidents need attention…"
    medium_plus = [i for i in incidents if i.priority != "low"]
    assert medium_plus and len(medium_plus) < len(incidents)
    # Every incident, low ones too, gets the "why flagged" text (D137), labeled per incident.
    assert all(i.narrative for i in incidents)
    assert set(summary.narrative["incidents"]) == {str(i.id) for i in incidents}
    assert {w["source"] for w in summary.narrative["incidents"].values()} == {"template"}


def test_an_ai_answer_is_stored_with_real_names(analyzed, db_session):
    top = db_session.scalars(select(Incident).where(Incident.upload_id == analyzed)
                             .order_by(Incident.priority_score.desc())).first()
    fake = FakeClient({"summary": "user_1 is the main concern.",
                       "incidents": [{"id": "incident_1", "narrative": "user_1 beaconed.", "next_steps": ["Isolate it."]}]})

    run_narrative(analyzed, client=fake)

    db_session.expire_all()
    summary = db_session.get(UploadSummary, analyzed)
    assert summary.narrative["source"] == "ai"
    assert summary.narrative["summary"] == f"{top.username} is the main concern."
    assert db_session.get(Incident, top.id).narrative == f"{top.username} beaconed."
    assert top.username not in fake.calls[0]["messages"][0]["content"]  # the real name never left


def test_a_crash_in_the_summary_stage_never_fails_the_analysis(analyzed, db_session, monkeypatch, caplog):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("app.pipeline.narrate.summarize", boom)

    run_narrative(analyzed)  # must not raise

    assert "summary failed; the analysis itself is complete" in caplog.text


def test_reanalysis_clears_then_rewrites_the_summary(analyzed, storage, db_session):
    analyze(analyzed, storage)

    db_session.expire_all()
    assert db_session.get(UploadSummary, analyzed).narrative["source"] == "template"
