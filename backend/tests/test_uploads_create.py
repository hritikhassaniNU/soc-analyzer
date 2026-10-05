import hashlib
import io

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.uploads import _copy_to_storage
from app.config import get_settings
from app.generator import Generator, GeneratorConfig
from app.models import Upload

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample_csv() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=6, seed=1, clean=True)).write(out)
    return "".join(out.getvalue().splitlines(keepends=True)[:500]).encode()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def upload(client, content: bytes, name: str = "proxy.log", **form):
    return client.post("/api/uploads", files={"file": (name, content, "text/plain")}, data=form)


def stored_files(storage) -> list:
    return [p for p in storage.root.rglob("*") if p.is_file()]


def test_happy_upload_is_stored_and_queued(logged_in, sample_csv, storage, db_session):
    response = upload(logged_in, sample_csv, log_timezone="America/New_York")

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued" and body["progress"] == 0
    assert body["uploaded_by"] == "analyst" and body["log_timezone"] == "America/New_York"
    assert body["size_bytes"] == len(sample_csv)
    assert body["sha256"] == hashlib.sha256(sample_csv).hexdigest()  # evidence integrity
    assert response.headers["location"] == f"/api/uploads/{body['id']}"

    row = db_session.scalar(select(Upload).where(Upload.id == body["id"]))
    with storage.open_read(row.raw_key) as stored:
        assert stored.read() == sample_csv  # byte-for-byte what was uploaded


def test_reuploading_the_same_bytes_is_allowed_but_counted(logged_in, sample_csv, storage):
    first = upload(logged_in, sample_csv).json()
    again = upload(logged_in, sample_csv, name="renamed.txt").json()  # same bytes, other name: still a duplicate
    different = upload(logged_in, sample_csv + b"\n").json()

    assert first["previous_uploads"] == 0
    assert again["previous_uploads"] == 1 and again["id"] != first["id"]
    assert different["previous_uploads"] == 0


def test_requires_login(client, sample_csv, storage):
    assert upload(client, sample_csv).status_code == 401
    assert stored_files(storage) == []


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("malware.exe", b"MZ\x90\x00", "Unsupported file type"),
        ("image.log", b"\x89PNG\r\n\x1a\n\x00\x00\x00", "binary file"),
        ("events.log", b'{"time": "2026-09-28 03:12:44"}\n', "Doesn't look like a Zscaler JSON-lines log: line 1: Missing required field"),
        ("notes.txt", b"hello,world\nthis is not a proxy log\n", "Expected 20 or 22 columns"),
        ("empty.log", b"   \n\n", "empty"),
    ],
)
def test_rejects_bad_files_with_a_clear_reason(logged_in, storage, name, content, message):
    response = upload(logged_in, content, name=name)

    assert response.status_code == 400
    assert message in response.json()["detail"]
    assert stored_files(storage) == []  # nothing stored for rejected files


def test_rejects_unknown_timezone(logged_in, sample_csv):
    response = upload(logged_in, sample_csv, log_timezone="Mars/Olympus_Mons")

    assert response.status_code == 400
    assert "Unknown timezone" in response.json()["detail"]


def test_oversized_content_length_is_rejected_early(logged_in, storage, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")
    get_settings.cache_clear()
    try:
        response = upload(logged_in, b"x" * (2 * 1024 * 1024))
    finally:
        get_settings.cache_clear()

    assert response.status_code == 413
    assert stored_files(storage) == []


def test_copy_limit_stops_and_stores_nothing(storage):
    """Second line of defense when there is no Content-Length header."""
    with pytest.raises(HTTPException) as exc:
        _copy_to_storage(io.BytesIO(b"x" * 3000), storage, "uploads/t/raw.log", max_bytes=1000)

    assert exc.value.status_code == 413
    assert stored_files(storage) == []


def test_failed_db_insert_leaves_no_orphan_file(logged_in, sample_csv, storage, monkeypatch):
    def broken_commit(self):
        raise RuntimeError("database went away")

    monkeypatch.setattr(Session, "commit", broken_commit)

    with pytest.raises(RuntimeError):
        upload(logged_in, sample_csv)

    assert stored_files(storage) == []
