import io

import pytest

from app.generator import Generator, GeneratorConfig
from app.pipeline.analyze import analyze
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


def test_incidents_worst_first_with_their_evidence(client, analyzed):
    response = client.get(f"/api/uploads/{analyzed}/incidents")

    assert response.status_code == 200
    body = response.json()
    incidents = body["incidents"]
    assert set(body["counts"]) == {"critical", "high", "medium", "low"}
    assert sum(body["counts"].values()) == len(incidents)  # default min_priority=low: all
    assert [i["priority_score"] for i in incidents] == sorted((i["priority_score"] for i in incidents), reverse=True)

    top = incidents[0]
    assert (top["username"], top["priority"]) == ("jdoe", "critical")
    assert top["narrative"].startswith("jdoe")  # template text (no key in tests)
    assert top["next_steps"]
    kinds = {a["kind"] for a in top["anomalies"]}
    assert {"beaconing", "executable_download"} <= kinds or {"large_upload", "off_hours"} <= kinds
    starts = [a["window_start"] for a in top["anomalies"]]
    assert starts == sorted(starts)  # evidence in time order
    assert set(top["anomalies"][0]) == {"id", "source", "kind", "window_start", "window_end",
                                        "score", "reason", "count", "details"}


def test_min_priority_hides_lower_incidents_but_not_the_counts(client, analyzed):
    everything = client.get(f"/api/uploads/{analyzed}/incidents").json()

    body = client.get(f"/api/uploads/{analyzed}/incidents", params={"min_priority": "high"}).json()

    assert {i["priority"] for i in body["incidents"]} <= {"critical", "high"}
    assert len(body["incidents"]) == everything["counts"]["critical"] + everything["counts"]["high"]
    assert body["counts"] == everything["counts"]


def test_unknown_priority_is_rejected(client, analyzed):
    assert client.get(f"/api/uploads/{analyzed}/incidents", params={"min_priority": "urgent"}).status_code == 422


def test_not_found_and_not_ready(client, analyst, sample):
    client.post("/api/login", auth=GOOD)
    queued = upload(client, sample)  # stored but not analyzed

    missing = client.get("/api/uploads/999999/incidents")
    not_ready = client.get(f"/api/uploads/{queued}/incidents")

    assert (missing.status_code, missing.json()["detail"]) == (404, "Upload not found")
    assert not_ready.status_code == 404
    assert not_ready.json()["detail"] == "Incidents not available yet (status: queued)"


def test_requires_login(client, analyzed):
    client.post("/api/logout")

    assert client.get(f"/api/uploads/{analyzed}/incidents").status_code == 401
