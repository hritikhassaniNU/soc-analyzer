import io
import time

import pyarrow.parquet as pq
import pytest
from sqlalchemy import select, text

from app.db import engine
from app.generator import Generator, GeneratorConfig
from app.models import Upload, events_partition_name
from app.parsing.csv_parser import CsvParser, NotZscalerLogError
from app.parsing.timestamps import load_timezone
from app.pipeline.analyze import analyze
from app.pipeline.narrate import PROGRESS_AFTER_NARRATIVE

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample_text() -> str:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=3)).write(out)  # with planted attacks
    return out.getvalue()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def make_upload(client, content: str) -> int:
    response = client.post("/api/uploads", files={"file": ("proxy.log", content.encode(), "text/plain")})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def partition_count(db, upload_id: int) -> int:
    # Own short connection: a read left open in the shared session would hold a lock that
    # blocks the next DROP TABLE (this exact bug hung the suite once).
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT count(*) FROM {events_partition_name(upload_id)}")).scalar()


def test_events_land_in_partition_and_parquet(logged_in, sample_text, storage, db_session):
    upload_id = make_upload(logged_in, sample_text)

    analyze(upload_id, storage)

    db_session.expire_all()
    upload = db_session.get(Upload, upload_id)
    expected = list(CsvParser(load_timezone("UTC")).parse(sample_text.splitlines(keepends=True)))
    assert upload.line_count == len(expected) and upload.bad_line_count == 0
    assert partition_count(db_session, upload_id) == len(expected)
    assert upload.progress == PROGRESS_AFTER_NARRATIVE  # analyze() = pass 1 (0-70) + pass 2 (70-95) + summary (99)

    # Spot-check one stored row against what the parser produced for that line.
    sample = expected[len(expected) // 2]
    row = db_session.execute(
        text("SELECT ts, username, host, bytes_out, threat FROM events WHERE upload_id = :u AND line_no = :n"),
        {"u": upload_id, "n": sample.line_no},
    ).one()
    assert tuple(row) == (sample.ts, sample.username, sample.host, sample.bytes_out, sample.threat)

    # Parquet: same rows, same columns.
    with storage.open_read(upload.parquet_key) as file:
        table = pq.read_table(file)
    assert table.num_rows == len(expected)
    assert "username" in table.column_names and "upload_id" not in table.column_names

    # Device columns (Client Connector): stored in both places, empty stays NULL.
    with_device = next(e for e in expected if e.device)
    row = db_session.execute(
        text("SELECT device, device_os FROM events WHERE upload_id = :u AND line_no = :n"),
        {"u": upload_id, "n": with_device.line_no},
    ).one()
    assert tuple(row) == (with_device.device, with_device.device_os)
    assert table.column("device").null_count == sum(e.device is None for e in expected)


def test_rerun_is_idempotent(logged_in, sample_text, storage, db_session):
    upload_id = make_upload(logged_in, sample_text)

    analyze(upload_id, storage)
    first = partition_count(db_session, upload_id)
    analyze(upload_id, storage)  # e.g. a retry after a crash

    assert partition_count(db_session, upload_id) == first  # no duplicates


def test_bad_lines_are_counted_and_good_ones_stored(logged_in, sample_text, storage, db_session):
    lines = sample_text.splitlines(keepends=True)[:300]
    lines[100] = "broken,line\n"
    lines[200] = lines[200].replace("Allowed", "Maybe", 1).replace("Blocked", "Maybe", 1)
    upload_id = make_upload(logged_in, "".join(lines))

    analyze(upload_id, storage)

    db_session.expire_all()
    upload = db_session.get(Upload, upload_id)
    assert (upload.line_count, upload.bad_line_count) == (300, 2)
    assert [s["line_no"] for s in upload.bad_line_samples] == [101, 201]
    assert partition_count(db_session, upload_id) == 298


def test_invalid_file_leaves_no_events_but_keeps_its_stats(logged_in, sample_text, storage, db_session):
    good = sample_text.splitlines(keepends=True)[:60]  # passes the 64 KB sniff...
    junk = ["not,a,zscaler,line\n"] * 200                # ...but most of the file is junk
    upload_id = make_upload(logged_in, "".join(good + junk))

    with pytest.raises(NotZscalerLogError):
        analyze(upload_id, storage)

    db_session.expire_all()
    upload = db_session.get(Upload, upload_id)
    assert partition_count(db_session, upload_id) == 0  # data transaction rolled back
    assert upload.parquet_key is None
    # ...but the counts and bad-line samples were saved separately, to show the analyst why (D55)
    assert (upload.line_count, upload.bad_line_count) == (260, 200) and len(upload.bad_line_samples) == 20
    parquet_files = [p for p in storage.root.rglob("*.parquet")]
    assert parquet_files == []  # atomic write discarded the partial Parquet file


def test_delete_drops_the_partition(logged_in, sample_text, storage, db_session):
    upload_id = make_upload(logged_in, sample_text)
    analyze(upload_id, storage)

    assert logged_in.delete(f"/api/uploads/{upload_id}").status_code == 204

    exists = db_session.execute(
        text("SELECT to_regclass(:name)"), {"name": events_partition_name(upload_id)}
    ).scalar()
    assert exists is None
    assert db_session.scalar(select(Upload).where(Upload.id == upload_id)) is None


def test_delete_answers_409_instead_of_hanging_when_events_are_being_read(
    logged_in, sample_text, storage
):
    upload_id = make_upload(logged_in, sample_text)
    analyze(upload_id, storage)

    with engine.connect() as reader:  # a slow dashboard query holding a lock on the partition
        reader.execute(text(f"SELECT count(*) FROM {events_partition_name(upload_id)}"))
        start = time.monotonic()
        response = logged_in.delete(f"/api/uploads/{upload_id}")
        waited = time.monotonic() - start
        reader.rollback()

    assert response.status_code == 409
    assert waited < 10  # bounded by lock_timeout (5 s), not forever
    assert logged_in.delete(f"/api/uploads/{upload_id}").status_code == 204  # works once free


def test_rule_hits_are_stored_in_postgres_and_parquet(logged_in, storage, db_session):
    out = io.StringIO()
    generator = Generator(GeneratorConfig(days=7, users=8, seed=3))
    generator.write(out)
    upload_id = make_upload(logged_in, out.getvalue())

    analyze(upload_id, storage)

    plants = {p.kind: p.line_nos for p in generator.plants}
    threat_line = plants["zscaler_threat"][0]
    exe_line = plants["executable_download"][0]
    with engine.connect() as conn:
        rows = dict(
            (r.line_no, (r.rule_hits, r.rule_max_score))
            for r in conn.execute(
                text("SELECT line_no, rule_hits, rule_max_score FROM events WHERE upload_id = :u"),
                {"u": upload_id},
            )
        )
    assert rows[threat_line] == (["zscaler_threat"], pytest.approx(0.90))  # blocked threat
    assert set(rows[exe_line][0]) == {"executable_download", "scripted_client"}  # python-requests too
    assert rows[exe_line][1] == pytest.approx(0.8)
    quiet = [n for n, (hits, _) in rows.items() if not hits]
    assert len(quiet) > 0.9 * len(rows)  # most lines fire nothing

    db_session.expire_all()
    with storage.open_read(db_session.get(Upload, upload_id).parquet_key) as file:
        table = pq.read_table(file).to_pydict()
    by_line = dict(zip(table["line_no"], zip(table["rule_hits"], table["rule_max_score"])))
    assert by_line[threat_line][0] == ["zscaler_threat"]
    assert by_line[exe_line][1] == pytest.approx(0.8)
