"""Pass 1: stream the raw upload through the parser into Postgres (COPY) and Parquet.

Transactions (see docs/DECISIONS.md):
  1. Short: drop any old partition and create a fresh one. CREATE ... PARTITION OF takes a
     strong lock on the parent `events` table, so it is committed immediately.
  2. Data: COPY every event into the partition and save the parse stats, all-or-nothing.
     A failure rolls back to an EMPTY partition; a retry drops and recreates it (idempotent).
Progress is written through a separate short session so the UI sees it before tx 2 commits.
"""

import gzip
import io
from collections.abc import Callable
from dataclasses import asdict

import pyarrow as pa
import pyarrow.parquet as pq
from sqlalchemy import func, text, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal, engine
from app.detection.rules import apply_rules
from app.models import Upload, events_partition_name
from app.parsing.base import LineParser, NotZscalerLogError, ParseStats
from app.parsing.compression import LimitedDecompressedReader, is_gzip
from app.parsing.formats import parser_for
from app.parsing.event import ZscalerEvent
from app.parsing.timestamps import load_timezone
from app.storage import Storage

PASS1_PROGRESS_END = 70   # pass 2 uses 70-100
PROGRESS_STEP = 2         # write progress at most every 2 percentage points
ROW_GROUP_SIZE = 65_536   # Parquet row group = rows buffered in memory at a time
DDL_LOCK_TIMEOUT = "30s"  # max wait for the partition DROP/CREATE lock

# Event columns in COPY and Parquet order (events table columns except upload_id).
EVENT_COLUMNS: tuple[str, ...] = (
    "line_no", "ts", "username", "client_ip", "url", "host", "action", "risk_score",
    "bytes_out", "bytes_in", "department", "location", "server_ip", "protocol", "method",
    "category", "app_name", "threat", "malware_category", "status_code", "user_agent", "file_type",
    "device", "device_os",
    "rule_hits", "rule_max_score",  # detection layer 1, computed in pass 1
)

PARQUET_SCHEMA = pa.schema(
    [
        ("line_no", pa.int32()), ("ts", pa.timestamp("us", tz="UTC")), ("username", pa.string()),
        ("client_ip", pa.string()), ("url", pa.string()), ("host", pa.string()),
        ("action", pa.string()), ("risk_score", pa.int16()), ("bytes_out", pa.int64()),
        ("bytes_in", pa.int64()), ("department", pa.string()), ("location", pa.string()),
        ("server_ip", pa.string()), ("protocol", pa.string()), ("method", pa.string()),
        ("category", pa.string()), ("app_name", pa.string()), ("threat", pa.string()),
        ("malware_category", pa.string()), ("status_code", pa.int16()),
        ("user_agent", pa.string()), ("file_type", pa.string()),
        ("device", pa.string()), ("device_os", pa.string()),
        ("rule_hits", pa.list_(pa.string())), ("rule_max_score", pa.float32()),
    ]
)
assert PARQUET_SCHEMA.names == list(EVENT_COLUMNS)


_PARSED_COLUMNS = EVENT_COLUMNS[:-2]  # everything except the two rule columns


def _values(event: ZscalerEvent, disabled: frozenset[str] = frozenset()) -> tuple:
    """One row for COPY and Parquet: the parsed fields + the results of the enabled rules."""
    hits = apply_rules(event, disabled)
    return (
        *(getattr(event, name) for name in _PARSED_COLUMNS),
        [hit.rule for hit in hits],
        max((hit.score for hit in hits), default=0.0),
    )


class _CountingReader(io.RawIOBase):
    """Wraps a binary stream and counts bytes read (progress = bytes read / file size)."""

    def __init__(self, inner: io.BufferedIOBase) -> None:
        self.inner = inner
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self.inner.read(len(buffer))
        buffer[: len(data)] = data
        self.bytes_read += len(data)
        return len(data)


class _Progress:
    """Writes upload progress through its OWN short session (visible before tx 2 commits)."""

    def __init__(self, upload_id: int, total_bytes: int, session_factory: Callable[[], Session]) -> None:
        self.upload_id = upload_id
        self.total = max(total_bytes, 1)
        self.session_factory = session_factory
        self.last = -PROGRESS_STEP

    def report(self, bytes_read: int, force: bool = False) -> None:
        percent = min(PASS1_PROGRESS_END, PASS1_PROGRESS_END * bytes_read // self.total)
        if force or percent >= self.last + PROGRESS_STEP:
            with self.session_factory() as db:
                db.execute(update(Upload).where(Upload.id == self.upload_id)
                           .values(progress=percent, locked_at=func.now()))  # progress = heartbeat
                db.commit()
            self.last = percent


def _copy_events(pg, partition: str, upload_id: int, parser: LineParser, lines, writer: pq.ParquetWriter,
                 counter: _CountingReader, progress: _Progress, disabled: frozenset[str] = frozenset()) -> None:
    """Stream parsed events into the partition (COPY) and into Parquet row groups."""
    batch: list[tuple] = []

    def flush() -> None:
        columns = list(zip(*batch))
        writer.write_table(pa.Table.from_arrays(
            [pa.array(col, type=field.type) for col, field in zip(columns, PARQUET_SCHEMA)],
            schema=PARQUET_SCHEMA,
        ))
        batch.clear()
        progress.report(counter.bytes_read)

    copy_sql = f"COPY {partition} (upload_id, {', '.join(EVENT_COLUMNS)}) FROM STDIN"
    with pg.cursor() as cursor, cursor.copy(copy_sql) as copy:
        for event in parser.parse(lines):
            values = _values(event, disabled)
            copy.write_row((upload_id, *values))
            batch.append(values)
            if len(batch) >= ROW_GROUP_SIZE:
                flush()
        if batch:
            flush()


def _save_rejected_stats(upload_id: int, stats: ParseStats, session_factory: Callable[[], Session]) -> None:
    """Separate short transaction: the counts and bad-line samples of a rejected file."""
    with session_factory() as db:
        db.execute(update(Upload).where(Upload.id == upload_id).values(
            line_count=stats.total_lines,
            bad_line_count=stats.bad_lines,
            bad_line_samples=[asdict(sample) for sample in stats.bad_samples],
            parquet_key=None,  # no usable events from this attempt
        ))
        db.commit()


def run_pass1(
    upload_id: int, storage: Storage, session_factory: Callable[[], Session] = SessionLocal
) -> ParseStats:
    """Parse the upload's raw file into events_u<id> + events.parquet. Raises
    NotZscalerLogError if the file turns out not to be a valid log."""
    with session_factory() as db:
        upload = db.get(Upload, upload_id)
        if upload is None:
            raise LookupError(f"Upload {upload_id} not found")
        raw_key, size, log_tz = upload.raw_key, upload.size_bytes, load_timezone(upload.log_timezone)
        log_format = upload.format
        disabled = frozenset(upload.disabled_detectors)  # snapshot taken by analyze()

    partition = events_partition_name(upload_id)  # int-only name: safe to put in DDL
    parquet_key = raw_key.rsplit("/", 1)[0] + "/events.parquet"

    # Tx 1 (milliseconds): a fresh, empty partition. Dropping first makes retries idempotent.
    # lock_timeout: if a long-running reader holds the table, fail clearly instead of hanging.
    with engine.begin() as conn:
        conn.execute(text(f"SET LOCAL lock_timeout = '{DDL_LOCK_TIMEOUT}'"))
        conn.execute(text(f"DROP TABLE IF EXISTS {partition}"))
        conn.execute(text(f"CREATE TABLE {partition} PARTITION OF events FOR VALUES IN ({int(upload_id)})"))

    progress = _Progress(upload_id, size, session_factory)
    parser = parser_for(log_format, log_tz)  # chosen at upload time (detected or the analyst's)

    # Tx 2: all rows + stats commit together, or nothing does.
    try:
        with session_factory() as db:
            pg = db.connection().connection.driver_connection  # the underlying psycopg connection
            with storage.open_read(raw_key) as raw, storage.open_write(parquet_key) as parquet_out:
                counter = _CountingReader(raw)  # counts STORED (maybe compressed) bytes: progress stays true
                data = io.BufferedReader(counter)
                if is_gzip(data.peek(2)):  # recognized by content, not file name; streamed, never unpacked to disk
                    limit = get_settings().max_uncompressed_mb * 1024 * 1024
                    data = io.BufferedReader(LimitedDecompressedReader(gzip.GzipFile(fileobj=data, mode="rb"), limit))
                lines = io.TextIOWrapper(  # errors="replace": one bad byte never kills the job
                    data, encoding="utf-8", errors="replace", newline=""
                )
                # `with`: the writer is closed on every path (success writes the footer; on failure the
                # whole Parquet file is discarded by open_write anyway).
                with pq.ParquetWriter(parquet_out, PARQUET_SCHEMA, compression="zstd") as writer:
                    _copy_events(pg, partition, upload_id, parser, lines, writer, counter, progress, disabled)

            stats = parser.stats
            db.execute(
                update(Upload).where(Upload.id == upload_id).values(
                    line_count=stats.total_lines,
                    bad_line_count=stats.bad_lines,
                    bad_line_samples=[asdict(sample) for sample in stats.bad_samples],
                    parquet_key=parquet_key,
                )
            )
            db.commit()
    except NotZscalerLogError:
        # The file was rejected (too many bad lines, zip bomb, damaged gzip…): tx 2 rolled back, but
        # the analyst should still see how many lines were read and WHICH ones were bad and why.
        _save_rejected_stats(upload_id, parser.stats, session_factory)
        raise

    progress.report(size, force=True)  # exactly PASS1_PROGRESS_END
    return stats
