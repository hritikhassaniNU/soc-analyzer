"""Beaconing: a machine calling home on a timer (malware checking in with its command server).

Two questions per (user, destination) pair:
1. Is the timing machine-like? Most gaps between requests are within +/-10% of the typical
   (median) gap. Humans browse in irregular bursts; timers don't.
   Why not the textbook coefficient of variation (std/mean of the gaps)? One overnight gap
   (16 h among 60 s gaps) explodes the mean and std, so a multi-day beacon would look irregular.
   The share of gaps near the median ignores a few odd gaps.
2. Is the destination rare in this organization? Regularity alone can't separate a beacon from
   legitimate polling: the Teams heartbeat (every ~120 s) is as regular as the planted beacon.
   The difference is that ~everyone talks to Teams, while only the infected laptop talks to its
   command server. Known limit: a beacon hidden in a popular service (e.g. a C2 channel over a
   cloud drive) is missed; a niche polling app used by one or two people is flagged.
"""

import statistics
from datetime import UTC
from pathlib import Path

import duckdb

from app.detection.findings import Finding, describe_duration

MIN_REQUESTS = 20
NEAR_MEDIAN = 0.10            # a gap is "on schedule" within +/-10% of the median gap
MIN_REGULAR_SHARE = 0.80      # >= 80% of gaps on schedule
MIN_MEDIAN_GAP_S = 10         # faster than this is a burst, not a heartbeat
MIN_DURATION_S = 3600         # beacons persist; a short regular run is noise
MAX_HOST_USERS = 2            # "rare destination": used by <= max(2, 5% of users)
MAX_HOST_USER_SHARE = 0.05
BASE_SCORE = 0.7              # heuristic: +0.1 if >= 95% on schedule, +0.1 if it lasts >= 4 h
VERY_REGULAR_SHARE = 0.95
LONG_DURATION_S = 4 * 3600


def regularity(timestamps: list[float]) -> tuple[float, float]:
    """(median gap in seconds, share of gaps within +/-10% of it) for sorted epoch seconds."""
    gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
    median = statistics.median(gaps)
    on_schedule = sum(abs(gap - median) <= NEAR_MEDIAN * median for gap in gaps)
    return median, on_schedule / len(gaps)


def detect_beaconing(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[Finding]:
    path = str(parquet)
    (total_users,) = con.execute(
        "SELECT count(DISTINCT username) FROM read_parquet(?)", [path]
    ).fetchone()
    max_users = max(MAX_HOST_USERS, int(MAX_HOST_USER_SHARE * total_users))
    # Only pairs whose destination is rare: few pairs, so their timestamp lists stay small.
    rows = con.execute("""
        WITH rare_hosts AS (
            SELECT host, count(DISTINCT username) AS users FROM read_parquet(?)
            WHERE host IS NOT NULL AND username IS NOT NULL
            GROUP BY host HAVING count(DISTINCT username) <= ?
        )
        SELECT e.username, e.host, any_value(r.users), list(epoch(e.ts) ORDER BY e.ts),
               min(e.ts)::TIMESTAMP, max(e.ts)::TIMESTAMP
        FROM read_parquet(?) AS e JOIN rare_hosts AS r USING (host)
        WHERE e.username IS NOT NULL
        GROUP BY e.username, e.host HAVING count(*) >= ?
        ORDER BY e.username, e.host
    """, [path, max_users, path, MIN_REQUESTS]).fetchall()

    findings = []
    for username, host, host_users, timestamps, first, last in rows:
        median_gap, share = regularity(timestamps)
        duration = timestamps[-1] - timestamps[0]
        if median_gap < MIN_MEDIAN_GAP_S or share < MIN_REGULAR_SHARE or duration < MIN_DURATION_S:
            continue
        score = BASE_SCORE + 0.1 * (share >= VERY_REGULAR_SHARE) + 0.1 * (duration >= LONG_DURATION_S)
        who = "only this user" if host_users == 1 else f"only {host_users} users"
        findings.append(Finding(
            username=username, window_start=first.replace(tzinfo=UTC), window_end=last.replace(tzinfo=UTC),  # naive UTC
            kind="beaconing", score=round(score, 2), count=len(timestamps),
            reason=(f"{len(timestamps):,} requests to {host} every ~{median_gap:.0f} s for "
                    f"{describe_duration(duration)} ({share:.0%} on schedule); "
                    f"{who} in this file contacted it."),
            details={"host": host, "median_gap_s": round(median_gap, 1), "regular_share": round(share, 3),
                     "duration_s": round(duration), "host_users": host_users},
        ))
    return findings
