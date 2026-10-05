"""The analysis worker: claims queued uploads one at a time and runs analyze() on them.

    python -m app.worker

The `uploads` table is the job queue. Several workers can run at once: the claim uses
FOR UPDATE SKIP LOCKED, so each queued upload is claimed by exactly one worker.

Reliability:
- Heartbeat: every progress write refreshes `locked_at`. A 'processing' upload silent for
  STALE_AFTER (its worker crashed, was OOM-killed, or lost its machine) is claimed again.
- At most MAX_ATTEMPTS tries per upload; then it fails with a clear message.
- Temporary errors (database connection, storage I/O) put the job back in the queue with a
  growing delay (`retry_at`); file problems and bugs fail at once (retrying can't help).
  Every stage is idempotent (drop + recreate), so a retry is a clean re-run.
"""

import logging
import signal
import time
from collections.abc import Callable
from datetime import timedelta

import psycopg

from sqlalchemy import text, update
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.logging_config import job_context, setup_logging
from app.models import Upload
from app.parsing.csv_parser import NotZscalerLogError
from app.pipeline.analyze import analyze

log = logging.getLogger("worker")

IDLE_SLEEP_SECONDS = 2.0
STALE_AFTER = timedelta(minutes=15)   # no heartbeat for this long: the worker is gone
MAX_ATTEMPTS = 3
RETRY_DELAY = timedelta(seconds=30)   # x attempt number: 30 s, 60 s, ...

# Temporary problems worth another try. File problems (NotZscalerLogError) and bugs are not.
TEMPORARY_ERRORS = (OperationalError, InterfaceError, psycopg.OperationalError, OSError)

# 1) Give up on stale jobs that already used all their attempts.
GIVE_UP_SQL = text("""
    UPDATE uploads
    SET status = 'failed', completed_at = now(),
        error = 'Analysis was interrupted ' || attempts || ' times (the worker stopped or crashed); giving up'
    WHERE status = 'processing' AND locked_at < now() - :stale AND attempts >= :max_attempts
    RETURNING id
""")

# 2) One atomic statement: pick the oldest claimable upload AND mark it processing.
# Claimable = queued (and past its retry time), or processing but stale (its worker is gone).
# SKIP LOCKED: rows held by another worker (or by a DELETE) are skipped, not waited for.
CLAIM_SQL = text("""
    UPDATE uploads
    SET status = 'processing', locked_at = now(), attempts = attempts + 1, progress = 0,
        error = NULL, retry_at = NULL
    WHERE id = (
        SELECT id FROM uploads
        WHERE (status = 'queued' AND (retry_at IS NULL OR retry_at <= now()))
           OR (status = 'processing' AND locked_at < now() - :stale AND attempts < :max_attempts)
        ORDER BY created_at, id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING id, attempts
""")


def claim_next_job(session_factory: Callable[[], Session] = SessionLocal) -> tuple[int, int] | None:
    """Claim one upload; returns (id, attempt number), or None if nothing is claimable."""
    params = {"stale": STALE_AFTER, "max_attempts": MAX_ATTEMPTS}
    with session_factory() as db:
        for (given_up,) in db.execute(GIVE_UP_SQL, params):
            log.warning("upload %s: interrupted %s times; marked failed", given_up, MAX_ATTEMPTS)
        row = db.execute(CLAIM_SQL, params).one_or_none()
        db.commit()
    return None if row is None else (row.id, row.attempts)


def _finish(upload_id: int, session_factory: Callable[[], Session], **values: object) -> None:
    with session_factory() as db:
        db.execute(update(Upload).where(Upload.id == upload_id).values(**values))
        db.commit()


def run_one(
    session_factory: Callable[[], Session] = SessionLocal,
    run: Callable[[int], None] = analyze,
) -> bool:
    """Process at most one job. Returns True if a job was processed (success or failure)."""
    claimed = claim_next_job(session_factory)
    if claimed is None:
        return False
    upload_id, attempt = claimed
    with job_context(upload_id):  # every log line during this job carries upload_id
        _run_job(upload_id, attempt, session_factory, run)
    return True


def _run_job(upload_id: int, attempt: int, session_factory: Callable[[], Session], run: Callable[[int], None]) -> None:
    if attempt > 1:  # logged inside job_context, so it carries upload_id like every other job line
        log.warning("upload %s: attempt %s of %s", upload_id, attempt, MAX_ATTEMPTS)
    log.info("upload %s: analysis started", upload_id)
    started = time.monotonic()
    try:
        run(upload_id)
    except NotZscalerLogError as exc:
        # A problem with the file itself: the message is meant for the analyst. No retry.
        log.warning("upload %s: rejected: %s", upload_id, exc)
        _finish(upload_id, session_factory, status="failed", error=str(exc)[:1000],
                completed_at=text("now()"))
    except TEMPORARY_ERRORS as exc:
        if attempt < MAX_ATTEMPTS:
            delay = RETRY_DELAY * attempt
            log.warning("upload %s: temporary error (%s); retrying in %ss", upload_id,
                        type(exc).__name__, int(delay.total_seconds()), exc_info=True)
            _finish(upload_id, session_factory, status="queued", progress=0, locked_at=None,
                    retry_at=text(f"now() + interval '{int(delay.total_seconds())} seconds'"))
        else:
            log.exception("upload %s: temporary error on the last attempt", upload_id)
            _finish(upload_id, session_factory, status="failed", completed_at=text("now()"),
                    error=f"Failed after {MAX_ATTEMPTS} attempts ({type(exc).__name__}); try again later")
    except Exception as exc:
        # Our bug: full details in the log, a generic message in the UI. Retrying can't help.
        log.exception("upload %s: unexpected error", upload_id)
        _finish(upload_id, session_factory, status="failed",
                error=f"Unexpected error during analysis ({type(exc).__name__})",
                completed_at=text("now()"))
    else:
        log.info("upload %s: done in %.1fs", upload_id, time.monotonic() - started)
        _finish(upload_id, session_factory, status="done", progress=100,
                completed_at=text("now()"))


class _Shutdown:
    """SIGTERM/SIGINT (e.g. `docker stop`): finish the current job, then exit."""

    requested = False

    @classmethod
    def request(cls, signum: int, _frame: object) -> None:
        log.info("received signal %s: will exit after the current job", signum)
        cls.requested = True


def main() -> None:
    setup_logging(get_settings().log_format)
    signal.signal(signal.SIGTERM, _Shutdown.request)
    signal.signal(signal.SIGINT, _Shutdown.request)
    log.info("worker started")
    while not _Shutdown.requested:
        try:
            had_job = run_one()
        except Exception:  # e.g. database briefly unreachable: log, wait, keep going
            log.exception("worker loop error")
            had_job = False
        if not had_job:
            time.sleep(IDLE_SLEEP_SECONDS)
    log.info("worker stopped")


if __name__ == "__main__":
    main()
