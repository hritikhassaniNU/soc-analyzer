import gzip
import io

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.generator import Generator, GeneratorConfig
from app.models import Incident, Upload
from app.parsing.base import NotZscalerLogError
from app.parsing.compression import LimitedDecompressedReader, decompress_head, is_gzip
from app.pipeline.analyze import analyze

GOOD = ("analyst", "correct-horse-1")


def generated_week(log_format: str) -> bytes:
    """The standard generated week (seed 42, 30 users) as CSV or JSON lines, built in memory."""
    out = io.StringIO()
    Generator(GeneratorConfig(seed=42, log_format=log_format)).write(out)
    return out.getvalue().encode()


@pytest.fixture(scope="module")
def week_csv() -> bytes:
    return generated_week("csv")


@pytest.fixture(scope="module")
def week_gz() -> bytes:
    return gzip.compress(generated_week("json"), mtime=0)


def gz(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


# ---- unit ----

def test_gzip_is_recognized_by_content():
    assert is_gzip(gz(b"x")) and not is_gzip(b"time,user\n") and not is_gzip(b"")


def test_the_sniff_can_read_the_start_of_a_cut_off_gzip_stream():
    compressed = gz(b"line\n" * 100_000)

    head = decompress_head(compressed[:200], max_bytes=1000)  # only the first 200 compressed bytes

    assert head.startswith(b"line\n") and len(head) <= 1000


def test_invalid_gzip_is_a_clear_error():
    with pytest.raises(ValueError, match="looks gzip-compressed but can't be read"):
        decompress_head(b"\x1f\x8b" + b"not really gzip", 1000)


def read_all(compressed: bytes, limit: int) -> bytes:
    reader = LimitedDecompressedReader(gzip.GzipFile(fileobj=io.BytesIO(compressed)), limit)
    return io.BufferedReader(reader).read()


def test_decompression_stops_at_the_limit():
    bomb = gz(b"\0" * 5_000_000)  # 5 MB of zeros compresses to ~5 KB

    assert len(bomb) < 10_000
    with pytest.raises(NotZscalerLogError, match="expands to more than"):
        read_all(bomb, limit=1_000_000)
    assert read_all(gz(b"ok\n"), limit=1_000_000) == b"ok\n"


def test_a_truncated_gzip_file_is_a_readable_error():
    with pytest.raises(NotZscalerLogError, match="damaged or incomplete"):
        read_all(gz(b"line\n" * 10_000)[:-20], limit=10**9)


# ---- through the API and the worker ----

def post(client, content: bytes, filename: str):
    return client.post("/api/uploads", files={"file": (filename, content, "application/gzip")})


@pytest.mark.integration
@pytest.mark.parametrize("filename", ["zscaler_sample.jsonl.gz", "events.log"])  # misnamed still works
def test_gzip_uploads_are_accepted_by_content(client, analyst, filename, week_gz):
    client.post("/api/login", auth=GOOD)

    response = post(client, week_gz, filename)

    assert response.status_code == 201 and response.json()["format"] == "json"


@pytest.mark.integration
@pytest.mark.parametrize(("content", "filename", "detail"), [
    (b"\x1f\x8bgarbage", "events.log.gz", "can't be read"),
    (b"time,user\n", "archive.gz", "Unsupported file type"),  # .gz needs a log extension before it
])
def test_bad_gzip_uploads_are_rejected(client, analyst, content, filename, detail):
    client.post("/api/login", auth=GOOD)

    response = post(client, content, filename)

    assert response.status_code == 400 and detail in response.json()["detail"]


@pytest.mark.integration
def test_the_gzip_json_week_gives_the_same_analysis_as_the_csv_week(client, analyst, storage, db_session, week_csv, week_gz):
    client.post("/api/login", auth=GOOD)
    gz_id = post(client, week_gz, "week.jsonl.gz").json()["id"]
    csv_id = post(client, week_csv, "week.csv").json()["id"]
    analyze(gz_id, storage)
    analyze(csv_id, storage)

    def result(upload_id):
        upload = db_session.get(Upload, upload_id)
        incidents = db_session.scalars(select(Incident).where(Incident.upload_id == upload_id)).all()
        return upload.line_count, sorted((i.username, i.priority, round(i.priority_score, 3), i.title) for i in incidents)

    db_session.expire_all()
    assert result(gz_id) == result(csv_id)
    assert result(gz_id)[0] == 17_686  # 17,679 + the AI-detector plants (2 look-alike + 5 msftconnecttest lines)


@pytest.fixture
def tiny_uncompressed_limit(monkeypatch):
    monkeypatch.setenv("MAX_UNCOMPRESSED_MB", "1")
    get_settings.cache_clear()
    yield
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.mark.integration
def test_a_file_that_expands_beyond_the_limit_fails_with_a_clear_message(
        client, analyst, storage, tiny_uncompressed_limit, week_gz):
    client.post("/api/login", auth=GOOD)
    upload_id = post(client, week_gz, "week.jsonl.gz").json()["id"]  # ~11 MB inside

    with pytest.raises(NotZscalerLogError, match="expands to more than 1 MB"):
        analyze(upload_id, storage)  # the worker turns this into status=failed with the message
