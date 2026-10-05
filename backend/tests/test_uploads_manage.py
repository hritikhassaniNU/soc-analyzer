import io

import pytest
from sqlalchemy import select, update

from app.generator import Generator, GeneratorConfig
from app.models import Upload, User

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample_csv() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=6, seed=1, clean=True)).write(out)
    return "".join(out.getvalue().splitlines(keepends=True)[:200]).encode()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def upload(client, content: bytes, name: str) -> int:
    response = client.post("/api/uploads", files={"file": (name, content, "text/plain")})
    assert response.status_code == 201
    return response.json()["id"]


def test_list_is_newest_first_with_uploader(logged_in, sample_csv):
    first = upload(logged_in, sample_csv, "monday.log")
    second = upload(logged_in, sample_csv, "tuesday.log")

    items = logged_in.get("/api/uploads").json()

    assert [i["id"] for i in items] == [second, first]
    assert items[0]["filename"] == "tuesday.log" and items[0]["uploaded_by"] == "analyst"
    assert "bad_line_samples" not in items[0]  # list stays light


def test_detail_includes_processing_fields(logged_in, sample_csv, db_session):
    upload_id = upload(logged_in, sample_csv, "monday.log")
    db_session.execute(  # simulate what the worker will record (step 10)
        update(Upload).where(Upload.id == upload_id).values(
            line_count=200, bad_line_count=1,
            bad_line_samples=[{"line_no": 7, "reason": "Missing required field 'user'", "raw": "<script>x</script>"}],
        )
    )
    db_session.commit()

    detail = logged_in.get(f"/api/uploads/{upload_id}").json()

    assert detail["line_count"] == 200 and detail["bad_line_count"] == 1
    assert detail["bad_line_samples"][0]["raw"] == "<script>x</script>"  # returned as data, as-is
    assert detail["error"] is None and detail["completed_at"] is None


def test_unknown_upload_is_404(logged_in):
    assert logged_in.get("/api/uploads/99999").status_code == 404
    assert logged_in.delete("/api/uploads/99999").status_code == 404


def test_delete_removes_row_and_files_only_for_that_upload(logged_in, sample_csv, storage, db_session):
    keep = upload(logged_in, sample_csv, "keep.log")
    gone = upload(logged_in, sample_csv, "gone.log")
    gone_key = db_session.scalar(select(Upload.raw_key).where(Upload.id == gone))
    keep_key = db_session.scalar(select(Upload.raw_key).where(Upload.id == keep))

    assert logged_in.delete(f"/api/uploads/{gone}").status_code == 204

    assert logged_in.get(f"/api/uploads/{gone}").status_code == 404
    assert not (storage.root / gone_key).exists()
    assert (storage.root / keep_key).exists()


def test_cannot_delete_while_processing(logged_in, sample_csv, db_session, storage):
    upload_id = upload(logged_in, sample_csv, "busy.log")
    db_session.execute(update(Upload).where(Upload.id == upload_id).values(status="processing"))
    db_session.commit()

    response = logged_in.delete(f"/api/uploads/{upload_id}")

    assert response.status_code == 409
    assert logged_in.get(f"/api/uploads/{upload_id}").status_code == 200  # still there


def test_uploads_survive_deleting_the_uploader(logged_in, sample_csv, db_session):
    upload_id = upload(logged_in, sample_csv, "evidence.log")
    db_session.query(User).delete()  # the analyst's account is removed
    db_session.commit()

    row = db_session.scalar(select(Upload).where(Upload.id == upload_id))
    assert row is not None and row.uploaded_by is None  # ON DELETE SET NULL kept the evidence
