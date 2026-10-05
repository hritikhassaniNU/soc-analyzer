"""Pass 2, part 1: dashboard aggregates computed by DuckDB straight from the Parquet file.

Computed once per upload and stored (upload_summary), so the dashboard never scans millions of
events on page view. DuckDB is column-oriented: `GROUP BY host` reads only the host column.
"""

import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb

from app.config import get_settings

TOP_N = 10

# Pick a bucket size so the timeline chart gets roughly 100-300 points.
# (max time range covered, DuckDB interval) - checked in order.
BUCKETS: tuple[tuple[timedelta, str], ...] = (
    (timedelta(hours=2), "1 minute"),
    (timedelta(hours=12), "5 minutes"),
    (timedelta(days=2), "15 minutes"),
    (timedelta(days=14), "1 hour"),
)
LONGEST_BUCKET = "1 day"

_MEMORY_LIMIT = re.compile(r"^\d+(\.\d+)?\s*(KB|MB|GB|TB)$", re.IGNORECASE)


def duckdb_connection() -> duckdb.DuckDBPyConnection:
    """In-process DuckDB with bounded resources and UTC time."""
    settings = get_settings()
    if not _MEMORY_LIMIT.match(settings.duckdb_memory_limit):  # it goes into SQL text below
        raise ValueError(f"Invalid duckdb_memory_limit: {settings.duckdb_memory_limit!r}")
    con = duckdb.connect()  # in-memory database
    con.execute(f"SET memory_limit = '{settings.duckdb_memory_limit}'")
    con.execute(f"SET threads = {int(settings.duckdb_threads)}")
    # Spill to the system temp dir: the default ".tmp" in the working directory (/app in the
    # container) is not writable by our non-root user, so spilling would crash on big files.
    con.execute(f"SET temp_directory = '{Path(tempfile.gettempdir()) / 'duckdb'}'")
    # Bucket boundaries must be UTC, not the machine's local timezone.
    con.execute("SET TimeZone = 'UTC'")
    return con


def choose_bucket(first: datetime | None, last: datetime | None) -> str:
    if first is None or last is None:
        return "1 hour"
    span = last - first
    return next((interval for limit, interval in BUCKETS if span <= limit), LONGEST_BUCKET)


def _iso(value: datetime | None) -> str | None:
    """Timestamps come back from DuckDB as naive UTC (see `::TIMESTAMP` casts) -> ISO with +00:00.

    Why the casts: returning TIMESTAMPTZ values to Python makes DuckDB import `pytz`; we use the
    standard library's zoneinfo instead. The session is UTC, so the cast keeps the same instant.
    """
    return value.replace(tzinfo=UTC).isoformat() if value is not None else None


def compute_aggregates(parquet: Path, con: duckdb.DuckDBPyConnection | None = None) -> dict[str, Any]:
    """Summary stats, timeline and top-N lists for one upload's events (JSON-ready)."""
    con = con or duckdb_connection()
    path = [str(parquet)]  # passed as a query parameter, never formatted into SQL

    (total, first, last, users, hosts, ips, allowed, blocked,
     bytes_out, bytes_in, threats, flagged) = con.execute(
        """
        SELECT count(*), min(ts)::TIMESTAMP, max(ts)::TIMESTAMP,
               count(DISTINCT username), count(DISTINCT host), count(DISTINCT client_ip),
               count(*) FILTER (WHERE action = 'Allowed'), count(*) FILTER (WHERE action = 'Blocked'),
               coalesce(sum(bytes_out), 0), coalesce(sum(bytes_in), 0),
               count(*) FILTER (WHERE threat IS NOT NULL),
               count(*) FILTER (WHERE len(rule_hits) > 0)
        FROM read_parquet(?)
        """,
        path,
    ).fetchone()

    rule_counts = dict(
        con.execute(
            "SELECT hit, count(*) FROM (SELECT unnest(rule_hits) AS hit FROM read_parquet(?)) "
            "GROUP BY hit ORDER BY hit",
            path,
        ).fetchall()
    )

    bucket = choose_bucket(first, last)  # one of our fixed strings: safe in SQL text
    # Every bucket from first to last, including EMPTY ones (zeros): with a plain GROUP BY, quiet
    # hours (nights, weekends) would vanish and a line chart would draw activity across them.
    timeline = [
        {"t": _iso(t), "total": n, "blocked": b, "flagged": f}
        for t, n, b, f in con.execute(
            f"""
            WITH counts AS (
                SELECT time_bucket(INTERVAL '{bucket}', ts) AS t, count(*) AS n,
                       count(*) FILTER (WHERE action = 'Blocked') AS b,
                       count(*) FILTER (WHERE len(rule_hits) > 0) AS f
                FROM read_parquet(?) GROUP BY t
            ),
            buckets AS (
                SELECT unnest(generate_series(min(t), max(t), INTERVAL '{bucket}')) AS t FROM counts
            )
            SELECT buckets.t::TIMESTAMP, coalesce(n, 0), coalesce(b, 0), coalesce(f, 0)
            FROM buckets LEFT JOIN counts USING (t) ORDER BY buckets.t
            """,
            path,
        ).fetchall()
    ]

    def top(column: str, metric: str = "count(*)", where: str = "TRUE") -> list[dict[str, Any]]:
        # column/metric/where are fixed strings from this module, never user input.
        rows = con.execute(
            f"""
            SELECT {column} AS name, {metric} AS value FROM read_parquet(?)
            WHERE {column} IS NOT NULL AND {where}
            GROUP BY name ORDER BY value DESC, name LIMIT {TOP_N}
            """,
            path,
        ).fetchall()
        return [{"name": name, "value": value} for name, value in rows]

    return {
        "stats": {
            "total_events": total,
            "first_event": _iso(first),
            "last_event": _iso(last),
            "unique_users": users,
            "unique_hosts": hosts,
            "unique_client_ips": ips,
            "allowed": allowed,
            "blocked": blocked,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "threat_events": threats,
            "flagged_events": flagged,
            "rule_hits": rule_counts,
        },
        "timeline": {"bucket": bucket, "points": timeline},
        "top": {
            "users_by_requests": top("username"),
            "users_by_bytes_out": top("username", "sum(bytes_out)"),
            "hosts": top("host"),
            "categories": top("category"),
            "blocked_categories": top("category", where="action = 'Blocked'"),
            "threats": top("threat"),
        },
    }
