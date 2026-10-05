"""Behavioral detectors (statistics layer): request bursts, large uploads, off-hours activity.

Each detector: DuckDB aggregates the Parquet file into a small per-user table -> the statistics
core (stats.py) decides what is unusual -> neighboring flagged time buckets merge into ONE finding
(one episode, not one row per minute). Findings are plain data; pass 2 stores them as `anomalies`.

Every flag needs two things: statistically unusual for THIS user (robust z >= 6), and big enough
to matter (a minimum effect size). Thresholds were checked against the generated samples:
the clean file produces no bursts and no off-hours findings (see tests/test_behavior.py).
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

import duckdb

from app.detection.findings import Finding
from app.detection.stats import Baseline, choose_baseline, is_anomalous, robust_z, score_from_z

# Request bursts: requests per user per minute (active minutes only).
BURST_MIN_POINTS = 20           # active minutes needed for a personal baseline
BURST_FLOOR = 1.0               # smallest meaningful spread: 1 request per minute
BURST_MIN_PER_MINUTE = 60       # one request per second: beyond human browsing

# Large uploads: bytes sent per user per hour (active hours only).
UPLOAD_MIN_POINTS = 10
# Hourly upload volume normally varies by a few MB (attachments, photos). With a 1 MB floor every
# big upload scored 0.99; 5 MB keeps the ranking: 50 MB -> 0.63, 150 MB -> 0.95, 400 MB -> 0.99.
UPLOAD_FLOOR = 5_000_000        # 5 MB
UPLOAD_MIN_BYTES = 50_000_000   # 50 MB in one hour

# Off-hours: activity well outside the user's usual working span.
OFF_HOURS_MIN_DAYS = 3          # active days needed to know someone's usual hours
TYPICAL_HOUR_MIN_DAYS = 2       # an hour of the day is "typical" if active in it on >= 2 days
OFF_HOURS_TOLERANCE = 2         # hours beyond the usual span before activity counts as off-hours
OFF_HOURS_MIN_EVENTS = 10       # a stray request is not an episode
OFF_HOURS_BASE_SCORE = 0.6      # heuristic (no z-score here): +0.1 weekend, +0.1 if >= 50 events
OFF_HOURS_BUSY_EVENTS = 50


@dataclass(frozen=True)
class Bucket:
    """One user's activity in one time bucket (a minute or an hour)."""

    start: datetime  # bucket start (UTC)
    first: datetime  # first and last event inside the bucket (UTC)
    last: datetime
    events: int
    value: float  # the metric being judged (requests, bytes, ...)
    extra: tuple[Any, ...] = ()


def _utc(value: datetime) -> datetime:
    # DuckDB returns naive UTC for our `::TIMESTAMP` casts (see aggregates._iso).
    return value.replace(tzinfo=UTC)


def _per_user_buckets(
    con: duckdb.DuckDBPyConnection, sql: str, parquet: Path
) -> dict[str, list[Bucket]]:
    """Run a query returning (username, bucket, first, last, events, value, *extra), ordered by
    username and bucket, and group the rows per user."""
    users: dict[str, list[Bucket]] = {}
    for username, start, first, last, events, value, *extra in con.execute(sql, [str(parquet)]).fetchall():
        users.setdefault(username, []).append(
            Bucket(_utc(start), _utc(first), _utc(last), events, float(value), tuple(extra))
        )
    return users


def _episodes(buckets: Sequence[Bucket], flagged: Callable[[Bucket], bool], step: timedelta) -> list[list[Bucket]]:
    """Runs of flagged buckets that follow each other without a gap (buckets are in time order)."""
    runs: list[list[Bucket]] = []
    for bucket in buckets:
        if not flagged(bucket):
            continue
        if runs and bucket.start - runs[-1][-1].start == step:
            runs[-1].append(bucket)
        else:
            runs.append([bucket])
    return runs


def _baseline_details(baseline: Baseline, kind: str) -> dict[str, Any]:
    return {"median": baseline.median, "scale": round(baseline.scale, 2), "points": baseline.n, "from": kind}


def _megabytes(n: float) -> str:
    return f"{n / 1_000_000:,.1f} MB" if n >= 100_000 else f"{n / 1_000:,.0f} KB"


# ---- request bursts ----

def detect_bursts(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[Finding]:
    users = _per_user_buckets(con, """
        SELECT username, time_bucket(INTERVAL '1 minute', ts)::TIMESTAMP AS minute,
               min(ts)::TIMESTAMP, max(ts)::TIMESTAMP, count(*), count(*)
        FROM read_parquet(?) WHERE username IS NOT NULL
        GROUP BY username, minute ORDER BY username, minute
    """, parquet)
    population = [b.value for buckets in users.values() for b in buckets]

    findings = []
    for username, buckets in users.items():
        baseline, source = choose_baseline([b.value for b in buckets], population, BURST_MIN_POINTS, BURST_FLOOR)
        flagged = lambda b: is_anomalous(b.value, baseline, BURST_MIN_PER_MINUTE)  # noqa: E731
        for run in _episodes(buckets, flagged, timedelta(minutes=1)):
            total, peak = sum(b.events for b in run), max(b.value for b in run)
            z = robust_z(peak, baseline)
            usual = "this user's" if source == "user" else "a typical user's"
            minutes = f"{len(run)} minute{'s' if len(run) > 1 else ''}"
            findings.append(Finding(
                username=username, window_start=run[0].first, window_end=run[-1].last,
                kind="request_burst", score=score_from_z(z), count=total,
                reason=(f"{total:,} requests in {minutes} (peak {peak:,.0f} per minute); "
                        f"{usual} usual active minute has {baseline.median:g}."),
                details={"peak_per_minute": peak, "minutes": len(run), "z": round(z, 1),
                         "baseline": _baseline_details(baseline, source)},
            ))
    return findings


# ---- large uploads ----

def detect_large_uploads(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[Finding]:
    # Per user-hour: total bytes sent, plus the destination that received most of them.
    users = _per_user_buckets(con, """
        WITH per_host AS (
            SELECT username, time_bucket(INTERVAL '1 hour', ts) AS hour, host,
                   any_value(category) AS category, min(ts) AS first, max(ts) AS last,
                   count(*) AS events, coalesce(sum(bytes_out), 0) AS sent
            FROM read_parquet(?) WHERE username IS NOT NULL
            GROUP BY username, hour, host
        )
        SELECT username, hour::TIMESTAMP, min(first)::TIMESTAMP, max(last)::TIMESTAMP,
               sum(events), sum(sent), arg_max(host, sent), arg_max(category, sent), max(sent)
        FROM per_host GROUP BY username, hour ORDER BY username, hour
    """, parquet)
    population = [b.value for buckets in users.values() for b in buckets]

    findings = []
    for username, buckets in users.items():
        baseline, source = choose_baseline([b.value for b in buckets], population, UPLOAD_MIN_POINTS, UPLOAD_FLOOR)
        flagged = lambda b: is_anomalous(b.value, baseline, UPLOAD_MIN_BYTES)  # noqa: E731
        for run in _episodes(buckets, flagged, timedelta(hours=1)):
            total = sum(b.value for b in run)
            peak = max(run, key=lambda b: b.value)
            top_host, top_category, top_sent = peak.extra
            share = top_sent / peak.value
            z = robust_z(peak.value, baseline)
            usual = "this user's" if source == "user" else "a typical user's"
            hours = f"{len(run)} hour{'s' if len(run) > 1 else ''}"
            findings.append(Finding(
                username=username, window_start=run[0].first, window_end=run[-1].last,
                kind="large_upload", score=score_from_z(z), count=sum(b.events for b in run),
                reason=(f"Sent {_megabytes(total)} in {hours}, {share:.0%} of the peak hour to "
                        f"{top_host} ({top_category or 'uncategorized'}); "
                        f"{usual} usual hour is {_megabytes(baseline.median)}."),
                # Destination context for correlation (step 19): is this company storage or not?
                details={"bytes_out": int(total), "peak_hour_bytes": int(peak.value), "hours": len(run),
                         "top_host": top_host, "top_category": top_category, "top_host_share": round(share, 3),
                         "z": round(z, 1), "baseline": _baseline_details(baseline, source)},
            ))
    return findings


# ---- off-hours activity ----

def _typical_span(buckets: Sequence[Bucket], tz: tzinfo) -> tuple[int, int] | None:
    """(earliest, latest) local hour of day the user is usually active in, or None if unknown.
    An hour counts as typical when the user was active in it on at least 2 different days;
    with only ~5 working days, single hours are patchy, so we use the whole span, not a set."""
    days_per_hour: dict[int, set] = {}
    days = set()
    for b in buckets:
        local = b.start.astimezone(tz)
        days.add(local.date())
        days_per_hour.setdefault(local.hour, set()).add(local.date())
    if len(days) < OFF_HOURS_MIN_DAYS:
        return None
    typical = [h for h, d in days_per_hour.items() if len(d) >= TYPICAL_HOUR_MIN_DAYS]
    return (min(typical), max(typical)) if typical else None


def detect_off_hours(con: duckdb.DuckDBPyConnection, parquet: Path, log_tz: tzinfo = UTC) -> list[Finding]:
    """Hours are judged in the log's timezone (a user's working day is local).
    Known limit: a span is a range within one calendar day, so night shifts across midnight
    look like 'active all day' and are never flagged (conservative, not noisy)."""
    users = _per_user_buckets(con, """
        SELECT username, time_bucket(INTERVAL '1 hour', ts)::TIMESTAMP AS hour,
               min(ts)::TIMESTAMP, max(ts)::TIMESTAMP, count(*), count(*)
        FROM read_parquet(?) WHERE username IS NOT NULL
        GROUP BY username, hour ORDER BY username, hour
    """, parquet)
    spans = {username: _typical_span(buckets, log_tz) for username, buckets in users.items()}
    known = sorted(s for s in spans.values() if s is not None)
    if not known:
        return []  # nobody has enough history (tiny file): no basis for "unusual hours"
    # Users without enough history are compared with the median user's working span.
    population = (sorted(s[0] for s in known)[len(known) // 2], sorted(s[1] for s in known)[len(known) // 2])

    findings = []
    for username, buckets in users.items():
        span, source = (spans[username], "user") if spans[username] else (population, "population")
        start, end = span

        def outside(b: Bucket) -> bool:
            hour = b.start.astimezone(log_tz).hour
            return hour < start - OFF_HOURS_TOLERANCE or hour > end + OFF_HOURS_TOLERANCE

        for run in _episodes(buckets, outside, timedelta(hours=1)):
            total = sum(b.events for b in run)
            if total < OFF_HOURS_MIN_EVENTS:
                continue
            first, last = run[0].first.astimezone(log_tz), run[-1].last.astimezone(log_tz)
            weekend = any(b.start.astimezone(log_tz).weekday() >= 5 for b in run)
            score = OFF_HOURS_BASE_SCORE + 0.1 * weekend + 0.1 * (total >= OFF_HOURS_BUSY_EVENTS)
            usual = "this user is" if source == "user" else "users in this file are"
            zone = first.tzname()
            findings.append(Finding(
                username=username, window_start=run[0].first, window_end=run[-1].last,
                kind="off_hours", score=round(score, 2), count=total,
                reason=(f"Active {first:%a %H:%M}–{last:%H:%M} {zone} ({total:,} requests); "
                        f"{usual} usually active {start:02d}:00–{end + 1:02d}:00 {zone}."),
                details={"usual_start_hour": start, "usual_end_hour": end + 1, "weekend": weekend,
                         "timezone": str(log_tz), "from": source},
            ))
    return findings


def detect_behavior(con: duckdb.DuckDBPyConnection, parquet: Path, log_tz: tzinfo = UTC) -> list[Finding]:
    return detect_bursts(con, parquet) + detect_large_uploads(con, parquet) + detect_off_hours(con, parquet, log_tz)
