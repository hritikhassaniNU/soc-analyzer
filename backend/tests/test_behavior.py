import io
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from app.detection.behavior import (
    detect_bursts,
    detect_large_uploads,
    detect_off_hours,
)
from app.detection.statistical import detect_statistical
from app.generator import Generator, GeneratorConfig
from app.parsing.csv_parser import CsvParser
from app.parsing.event import ZscalerEvent
from app.pipeline.aggregates import duckdb_connection
from tests.test_aggregates import write_parquet

MONDAY = datetime(2026, 9, 21, tzinfo=UTC)
BASE = ZscalerEvent(
    line_no=1, ts=MONDAY, username="alice", client_ip="10.0.0.1", url="example.com/", host="example.com",
    action="Allowed", risk_score=5, bytes_out=1_000, bytes_in=5_000, category="Business",
)


def workweek(username: str = "alice", start_hour: int = 9, end_hour: int = 17) -> list[ZscalerEvent]:
    """Mon-Fri, 3 requests at the start of every working hour: a steady, boring baseline."""
    events = []
    for day in range(5):
        for hour in range(start_hour, end_hour + 1):
            for second in (0, 20, 40):
                ts = MONDAY + timedelta(days=day, hours=hour, seconds=second)
                events.append(replace(BASE, username=username, ts=ts))
    return events


def run(tmp_path, events, detector, *args):
    events = [replace(e, line_no=i) for i, e in enumerate(events, start=1)]
    path = tmp_path / "events.parquet"
    write_parquet(path, events)
    return detector(duckdb_connection(), path, *args)


# ---- request bursts ----

def test_burst_is_one_finding_with_exact_window(tmp_path):
    start = MONDAY + timedelta(days=2, hours=11, minutes=30)  # away from the baseline's minutes
    burst = [replace(BASE, ts=start + timedelta(seconds=i * 0.2)) for i in range(600)]  # 2 minutes

    [finding] = run(tmp_path, workweek() + burst, detect_bursts)

    assert finding.kind == "request_burst" and finding.username == "alice"
    assert finding.count == 600 and finding.details["minutes"] == 2
    assert finding.window_start == start and finding.window_end == burst[-1].ts
    assert finding.score > 0.9
    assert "600 requests in 2 minutes (peak 300 per minute)" in finding.reason


def test_unusual_but_human_speed_is_not_a_burst(tmp_path):
    start = MONDAY + timedelta(days=2, hours=11, minutes=30)
    busy = [replace(BASE, ts=start + timedelta(seconds=i)) for i in range(40)]  # 40/min: high z, < 60

    assert run(tmp_path, workweek() + busy, detect_bursts) == []


def test_new_user_is_compared_with_everyone(tmp_path):
    start = MONDAY + timedelta(days=2, hours=11)
    newcomer = [replace(BASE, username="newbie", ts=start + timedelta(seconds=i * 0.5)) for i in range(100)]

    [finding] = run(tmp_path, workweek() + newcomer, detect_bursts)

    assert finding.username == "newbie"
    assert finding.details["baseline"]["from"] == "population"
    assert "a typical user's usual active minute" in finding.reason


# ---- large uploads ----

def test_large_upload_names_the_destination(tmp_path):
    at = MONDAY + timedelta(days=6, hours=2, minutes=47)
    upload = [replace(BASE, ts=at + timedelta(minutes=i), host="mega.nz", category="File Sharing",
                      method="POST", bytes_out=100_000_000) for i in range(4)]

    [finding] = run(tmp_path, workweek() + upload, detect_large_uploads)

    assert finding.kind == "large_upload" and finding.count == 4
    assert finding.details["bytes_out"] == 400_000_000
    assert finding.details["top_host"] == "mega.nz" and finding.details["top_host_share"] == 1.0
    assert finding.score == 0.99
    assert "Sent 400.0 MB in 1 hour, 100% of the peak hour to mega.nz (File Sharing)" in finding.reason


@pytest.mark.parametrize(("megabytes", "flagged"), [(30, False), (60, True)])
def test_upload_must_be_big_enough_to_matter(tmp_path, megabytes, flagged):
    at = MONDAY + timedelta(days=2, hours=10, minutes=30)
    upload = replace(BASE, ts=at, host="drive.google.com", method="POST", bytes_out=megabytes * 1_000_000)

    assert bool(run(tmp_path, [*workweek(), upload], detect_large_uploads)) is flagged


def test_bigger_uploads_rank_higher(tmp_path):
    def score(megabytes):
        upload = replace(BASE, ts=MONDAY + timedelta(days=2, hours=10, minutes=30), bytes_out=megabytes * 1_000_000)
        return run(tmp_path, [*workweek(), upload], detect_large_uploads)[0].score

    assert score(60) < score(150) < score(400)  # the 5 MB spread floor keeps them apart


# ---- off-hours ----

def test_sunday_night_activity_is_off_hours(tmp_path):
    sunday_night = MONDAY + timedelta(days=6, hours=2, minutes=40)
    night = [replace(BASE, ts=sunday_night + timedelta(minutes=i)) for i in range(20)]

    [finding] = run(tmp_path, workweek() + night, detect_off_hours)

    assert finding.kind == "off_hours" and finding.count == 20
    assert finding.window_start == sunday_night and finding.window_end == night[-1].ts
    assert finding.score == 0.7  # 0.6 + weekend
    assert finding.reason == ("Active Sun 02:40–02:59 UTC (20 requests); "
                              "this user is usually active 09:00–18:00 UTC.")


def test_tolerance_and_minimum_size(tmp_path):
    evening = MONDAY + timedelta(days=1, hours=19)  # 2 h after the usual 17:xx: within tolerance
    late = MONDAY + timedelta(days=2, hours=21)     # 4 h after: off-hours, but only 5 requests
    events = workweek() + [replace(BASE, ts=evening + timedelta(minutes=i)) for i in range(30)] + [
        replace(BASE, ts=late + timedelta(minutes=i)) for i in range(5)]

    assert run(tmp_path, events, detect_off_hours) == []


def test_consecutive_off_hours_merge_and_busy_episodes_score_higher(tmp_path):
    start = MONDAY + timedelta(days=1, hours=20)
    beacon = [replace(BASE, ts=start + timedelta(minutes=i)) for i in range(120)]  # 20:00-21:59

    [finding] = run(tmp_path, workweek() + beacon, detect_off_hours)

    assert finding.count == 120 and finding.score == 0.7  # weekday 0.6 + busy 0.1


def test_evening_worker_is_normal_for_themselves(tmp_path):
    assert run(tmp_path, workweek("eve", start_hour=13, end_hour=21), detect_off_hours) == []


def test_hours_are_judged_in_the_log_timezone(tmp_path):
    # Same UTC data; in New York (UTC-4) the 02:40 UTC Sunday activity is Saturday 22:40 local.
    sunday_night = MONDAY + timedelta(days=6, hours=2, minutes=40)
    night = [replace(BASE, ts=sunday_night + timedelta(minutes=i)) for i in range(20)]

    [finding] = run(tmp_path, workweek() + night, detect_off_hours, ZoneInfo("America/New_York"))

    assert finding.reason == ("Active Sat 22:40–22:59 EDT (20 requests); "
                              "this user is usually active 05:00–14:00 EDT.")


def test_too_little_history_finds_nothing(tmp_path):
    two_days = [e for e in workweek() if e.ts < MONDAY + timedelta(days=2)]
    night = [replace(BASE, ts=MONDAY + timedelta(hours=2, minutes=i)) for i in range(20)]

    assert run(tmp_path, two_days + night, detect_off_hours) == []


# ---- the generated week, checked against its answer key ----

def generated(tmp_path, **config):
    out = io.StringIO()
    generator = Generator(GeneratorConfig(**config))
    generator.write(out)
    out.seek(0)
    path = tmp_path / "generated.parquet"
    write_parquet(path, list(CsvParser(UTC).parse(out)))
    return detect_statistical(duckdb_connection(), path), generator  # all statistical detectors


def overlaps(finding, plant) -> bool:
    return (finding.username == plant.username
            and finding.window_start <= datetime.fromisoformat(plant.end)
            and finding.window_end >= datetime.fromisoformat(plant.start))


@pytest.mark.parametrize("seed", [42, 7])
def test_planted_attacks_are_found(tmp_path, seed):
    findings, generator = generated(tmp_path, seed=seed)
    plants = {p.kind: p for p in generator.plants}

    for kind in ("request_burst", "large_upload", "off_hours"):
        assert any(f.kind == kind and overlaps(f, plants[kind]) for f in findings), kind
    exfil = next(f for f in findings if f.kind == "large_upload" and f.username == "jdoe")
    assert exfil.details["top_host"] == "mega.nz" and exfil.score == 0.99


@pytest.mark.parametrize("seed", [42, 7])
def test_clean_week_has_no_bursts_or_off_hours(tmp_path, seed):
    findings, generator = generated(tmp_path, seed=seed, clean=True)

    assert [f for f in findings if f.kind != "large_upload"] == []
    # Known, documented limit: legitimate 50-150 MB uploads to company storage ARE statistically
    # unusual. Telling them apart needs context (destination, time, client): correlation, step 19.
    legit = next(b for b in generator.benign.values() if b.kind == "legit_large_upload")
    for finding in findings:
        assert finding.username in legit.username.split(",")
        assert finding.details["top_host"] in {"drive.google.com", "acme.sharepoint.com"}
        assert finding.score < 0.99  # ranked below a 400 MB exfiltration
