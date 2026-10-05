import io

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from app.db import SessionLocal, engine
from app.generator import Generator, GeneratorConfig
from app.models import Upload
from app.parsing.csv_parser import NotZscalerLogError
from app.worker import MAX_ATTEMPTS, claim_next_job, run_one

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=6, seed=5, clean=True)).write(out)
    return "".join(out.getvalue().splitlines(keepends=True)[:300]).encode()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def make_upload(client, content: bytes) -> int:
    response = client.post("/api/uploads", files={"file": ("proxy.log", content, "text/plain")})
    assert response.status_code == 201
    return response.json()["id"]


def fetch(db_session, upload_id: int) -> Upload:
    db_session.expire_all()
    return db_session.scalar(select(Upload).where(Upload.id == upload_id))


def test_empty_queue_returns_none(db_session):
    assert claim_next_job() is None


def test_claims_oldest_first_and_marks_processing(logged_in, sample, db_session):
    first, second = make_upload(logged_in, sample), make_upload(logged_in, sample)

    assert claim_next_job() == (first, 1)  # (id, attempt number)
    row = fetch(db_session, first)
    assert row.status == "processing" and row.attempts == 1 and row.locked_at is not None
    assert claim_next_job() == (second, 1)
    assert claim_next_job() is None


def test_concurrent_claims_never_get_the_same_job(logged_in, sample):
    a, b = make_upload(logged_in, sample), make_upload(logged_in, sample)
    claim = text("""
        UPDATE uploads SET status = 'processing' WHERE id = (
            SELECT id FROM uploads WHERE status = 'queued' ORDER BY created_at, id
            FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id""")

    with engine.connect() as worker1, engine.connect() as worker2:
        got1 = worker1.execute(claim).scalar()  # worker 1 holds its row lock (not committed yet)
        got2 = worker2.execute(claim).scalar()  # worker 2 skips it instead of waiting
        worker1.commit()
        worker2.commit()

    assert {got1, got2} == {a, b}


def test_row_locked_by_a_delete_is_skipped(logged_in, sample):
    upload_id = make_upload(logged_in, sample)

    with engine.connect() as deleter:
        deleter.execute(text("SELECT id FROM uploads WHERE id = :i FOR UPDATE"), {"i": upload_id})
        assert claim_next_job() is None  # skipped, not blocked
        deleter.rollback()

    assert claim_next_job() == (upload_id, 1)


def test_successful_job_is_done(logged_in, sample, storage, db_session):
    upload_id = make_upload(logged_in, sample)
    from app.pipeline.analyze import analyze

    assert run_one(SessionLocal, lambda uid: analyze(uid, storage)) is True

    row = fetch(db_session, upload_id)
    assert (row.status, row.progress, row.error) == ("done", 100, None)
    assert row.completed_at is not None and row.line_count == 300


def test_invalid_file_fails_with_readable_message(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)

    def reject(uid: int) -> None:
        raise NotZscalerLogError("120 of 200 lines are invalid (more than 50%)")

    run_one(SessionLocal, reject)

    row = fetch(db_session, upload_id)
    assert row.status == "failed"
    assert row.error == "120 of 200 lines are invalid (more than 50%)"


def test_unexpected_error_fails_with_generic_message(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)

    def crash(uid: int) -> None:
        raise KeyError("internal detail the UI should not show")

    run_one(SessionLocal, crash)

    row = fetch(db_session, upload_id)
    assert row.status == "failed"
    assert row.error == "Unexpected error during analysis (KeyError)"
    assert "internal detail" not in row.error


def test_no_job_returns_false(db_session):
    assert run_one(SessionLocal, lambda uid: None) is False



# ---- reliability: stale jobs, retries ----

def set_row(upload_id: int, **values) -> None:
    """Simulate the past directly in the database (e.g. a worker that died 20 minutes ago)."""
    assignments = ", ".join(f"{k} = {v}" for k, v in values.items())
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE uploads SET {assignments} WHERE id = :id"), {"id": upload_id})


def test_a_job_whose_worker_died_is_claimed_again(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, status="'processing'", attempts=1, locked_at="now() - interval '20 minutes'")

    assert claim_next_job() == (upload_id, 2)  # second attempt

    row = fetch(db_session, upload_id)
    assert row.status == "processing" and row.attempts == 2


def test_a_live_job_is_not_stolen(logged_in, sample):
    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, status="'processing'", attempts=1, locked_at="now() - interval '1 minute'")

    assert claim_next_job() is None  # heartbeat 1 minute ago: still alive


def test_a_job_interrupted_too_often_is_given_up(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, status="'processing'", attempts=MAX_ATTEMPTS, locked_at="now() - interval '20 minutes'")

    assert claim_next_job() is None

    row = fetch(db_session, upload_id)
    assert row.status == "failed" and row.completed_at is not None
    assert row.error == f"Analysis was interrupted {MAX_ATTEMPTS} times (the worker stopped or crashed); giving up"


def flaky(uid: int) -> None:
    raise OperationalError("SELECT 1", {}, Exception("server closed the connection unexpectedly"))


def test_a_temporary_error_goes_back_to_the_queue_with_a_delay(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)

    run_one(SessionLocal, flaky)

    row = fetch(db_session, upload_id)
    assert (row.status, row.attempts, row.error, row.locked_at) == ("queued", 1, None, None)
    assert row.retry_at is not None
    assert claim_next_job() is None  # not before retry_at

    set_row(upload_id, retry_at="now() - interval '1 second'")
    assert claim_next_job() == (upload_id, 2)


def test_temporary_errors_stop_after_the_last_attempt(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, attempts=MAX_ATTEMPTS - 1)  # this claim is the last attempt

    run_one(SessionLocal, flaky)

    row = fetch(db_session, upload_id)
    assert row.status == "failed"
    assert row.error == f"Failed after {MAX_ATTEMPTS} attempts (OperationalError); try again later"


def test_file_problems_and_bugs_are_never_retried(logged_in, sample, db_session):
    upload_id = make_upload(logged_in, sample)

    run_one(SessionLocal, lambda uid: (_ for _ in ()).throw(NotZscalerLogError("not a log")))

    row = fetch(db_session, upload_id)
    assert (row.status, row.attempts, row.retry_at) == ("failed", 1, None)


def test_progress_is_the_heartbeat(logged_in, sample, db_session):
    from app.pipeline.pass1 import _Progress

    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, status="'processing'", locked_at="now() - interval '20 minutes'")

    _Progress(upload_id, total_bytes=100, session_factory=SessionLocal).report(50, force=True)

    assert claim_next_job() is None  # the progress write refreshed locked_at: not stale anymore
    assert fetch(db_session, upload_id).progress == 35  # 50% of the file = 35 on the 0-70 scale



def test_a_rejected_file_keeps_its_counts_and_bad_line_samples(logged_in, sample, storage, db_session):
    from app.pipeline.analyze import analyze

    good = sample.splitlines(keepends=True)[:30]
    junk = [f"junk line {i} with no commas\n".encode() for i in range(200)]
    upload_id = make_upload(logged_in, b"".join(good + junk))  # the sniff sees mostly good lines

    run_one(SessionLocal, lambda uid: analyze(uid, storage))

    row = fetch(db_session, upload_id)
    assert row.status == "failed" and row.error == "200 of 230 lines are invalid (more than 50%)"
    assert (row.line_count, row.bad_line_count, row.parquet_key) == (230, 200, None)
    assert len(row.bad_line_samples) == 20  # the first 20, with line numbers and reasons
    assert row.bad_line_samples[0] == {"line_no": 31, "reason": "Expected 20 or 22 columns, got 1",
                                       "raw": "junk line 0 with no commas"}
    detail = logged_in.get(f"/api/uploads/{upload_id}").json()  # what the upload page shows
    assert detail["bad_line_count"] == 200 and len(detail["bad_line_samples"]) == 20



def test_the_retry_attempt_is_logged_with_its_upload_id(logged_in, sample, caplog):
    import logging

    from app.logging_config import UploadIdFilter

    upload_id = make_upload(logged_in, sample)
    set_row(upload_id, status="'processing'", attempts=1, locked_at="now() - interval '20 minutes'")
    caplog.handler.addFilter(UploadIdFilter())  # like the real handler (setup_logging)

    with caplog.at_level(logging.INFO, logger="worker"):
        run_one(SessionLocal, lambda uid: None)

    [record] = [r for r in caplog.records if "attempt 2 of" in r.getMessage()]
    assert record.upload_id == upload_id
