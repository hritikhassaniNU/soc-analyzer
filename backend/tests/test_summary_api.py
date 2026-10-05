import io

import pytest

from app.generator import Generator, GeneratorConfig
from app.pipeline.analyze import analyze

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9)).write(out)
    return out.getvalue().encode()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def upload(client, content: bytes) -> int:
    return client.post("/api/uploads", files={"file": ("proxy.log", content, "text/plain")}).json()["id"]


def test_summary_of_a_done_upload(logged_in, sample, storage):
    upload_id = upload(logged_in, sample)
    analyze(upload_id, storage)

    response = logged_in.get(f"/api/uploads/{upload_id}/summary")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"upload_id", "stats", "timeline", "top", "computed_at", "narrative"}
    assert body["narrative"]["source"] == "template" and body["narrative"]["summary"]
    assert body["stats"]["total_events"] == sum(p["total"] for p in body["timeline"]["points"])
    assert body["timeline"]["bucket"] == "1 hour"
    assert body["top"]["users_by_bytes_out"][0]["name"] == "jdoe"
    assert set(body["top"]) == {"users_by_requests", "users_by_bytes_out", "hosts", "categories",
                                "blocked_categories", "threats"}


def test_summary_not_ready_yet(logged_in, sample):
    upload_id = upload(logged_in, sample)  # queued, never analyzed

    response = logged_in.get(f"/api/uploads/{upload_id}/summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Summary not available yet (status: queued)"


def test_summary_of_unknown_upload(logged_in):
    response = logged_in.get("/api/uploads/99999/summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Upload not found"
