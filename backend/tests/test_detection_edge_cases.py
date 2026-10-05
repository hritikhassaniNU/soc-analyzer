"""Detection on odd, tiny or degenerate files: it must never crash an upload, and it should stay
quiet when there is no basis for "unusual". Two known small-file limits are pinned here on
purpose, so the behavior is deliberate and visible (also documented in the README)."""

import io
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from app.detection.run import detect
from app.generator import Generator, GeneratorConfig
from app.models import Anomaly, Incident, Upload
from app.pipeline.aggregates import duckdb_connection
from app.pipeline.analyze import analyze
from tests.test_aggregates import write_parquet
from tests.test_behavior import BASE

T = datetime(2026, 9, 22, 10, tzinfo=UTC)
SAMPLES = Path(__file__).resolve().parents[2] / "samples"
GOOD = ("analyst", "correct-horse-1")


def run_detect(tmp_path, events, log_tz=UTC):
    events = [replace(e, line_no=i) for i, e in enumerate(events, start=1)]
    path = tmp_path / "edge.parquet"
    write_parquet(path, events)
    return detect(duckdb_connection(), path, log_tz)


QUIET = {
    "one event": [BASE],
    "one user, three events": [replace(BASE, ts=T + timedelta(minutes=i)) for i in range(3)],
    "500 identical timestamps": [replace(BASE, ts=T)] * 500,
    "no host in any URL": [replace(BASE, ts=T + timedelta(minutes=i), url="", host=None) for i in range(30)],
    "zero bytes everywhere": [replace(BASE, ts=T + timedelta(minutes=i), bytes_out=0, bytes_in=0,
                                      username=f"u{i % 5}") for i in range(300)],
}


@pytest.mark.parametrize("events", QUIET.values(), ids=QUIET.keys())
def test_no_basis_for_unusual_means_no_findings(tmp_path, events):
    # Also a half-hour timezone (Kolkata, +5:30): hour buckets must not break.
    detection = run_detect(tmp_path, events, ZoneInfo("Asia/Kolkata"))

    assert detection.findings == [] and detection.incidents == []


def test_threats_alone_still_become_incidents(tmp_path):
    hits = [replace(BASE, ts=T + timedelta(seconds=i), username=f"u{i % 3}", action="Blocked",
                    threat="Trojan.X") for i in range(30)]

    detection = run_detect(tmp_path, hits)

    assert sorted((i.username, i.priority) for i in detection.incidents) == [
        ("u0", "high"), ("u1", "high"), ("u2", "high")]


def night_shift(username="nora", host="example.com"):
    """Mon-Fri 22:00-06:00 UTC, three requests an hour: someone who always works nights."""
    return [replace(BASE, username=username, host=host,
                    ts=datetime(2026, 9, 21 + day, 22, tzinfo=UTC) + timedelta(hours=h, minutes=m))
            for day in range(5) for h in range(8) for m in (0, 20, 40)]


def crowd(host="example.com", users=30):
    return [replace(BASE, username=f"user{i}", host=host, ts=T + timedelta(minutes=i)) for i in range(users)]


def test_a_night_shift_is_never_unusual_hours(tmp_path):
    detection = run_detect(tmp_path, night_shift() + crowd())

    assert [f.kind for _, f in detection.findings] == []  # with a population: nothing at all


def test_known_limit_lone_user_regular_traffic_looks_like_beaconing(tmp_path):
    # In a file with ONE user every destination is "rare", so perfectly regular traffic (here a
    # request every 20 minutes) passes the beaconing test. Real browsing is never this regular,
    # but a tiny file with a polling app would trigger it. The prevalence check needs a population.
    detection = run_detect(tmp_path, night_shift())

    assert [f.kind for _, f in detection.findings] == ["beaconing"]


def test_known_limit_no_history_no_baseline(tmp_path):
    # The only event in the file is a 900 MB upload: the baseline IS the upload, so z = 0.
    # With other users in the file, the population baseline catches it (next test).
    alone = run_detect(tmp_path, [replace(BASE, host="mega.nz", bytes_out=900_000_000)])
    assert alone.findings == []


def test_a_newcomer_upload_is_caught_by_the_population_baseline(tmp_path):
    others = [replace(BASE, username=f"user{u}", ts=T + timedelta(hours=h)) for u in range(10) for h in range(12)]
    newcomer = replace(BASE, username="newbie", host="mega.nz", bytes_out=900_000_000)

    detection = run_detect(tmp_path, [*others, newcomer])

    [(source, finding)] = detection.findings
    assert (finding.kind, finding.username, finding.details["baseline"]["from"]) == (
        "large_upload", "newbie", "population")


# ---- end to end through upload -> analyze() -> database ----

def upload_file(client, content: bytes, **form) -> int:
    response = client.post("/api/uploads", files={"file": ("proxy.log", content, "text/plain")}, data=form)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def assert_consistent(db, upload_id):
    """Every finding belongs to an incident, and every incident has evidence."""
    anomalies = list(db.scalars(select(Anomaly).where(Anomaly.upload_id == upload_id)))
    incidents = list(db.scalars(select(Incident).where(Incident.upload_id == upload_id)))
    assert {a.incident_id for a in anomalies} == {i.id for i in incidents}
    return anomalies, incidents


def test_file_with_bad_lines_and_html_analyzes_cleanly(client, analyst, storage, db_session):
    client.post("/api/login", auth=GOOD)
    upload_id = upload_file(client, (SAMPLES / "edge_cases" / "bad_lines_with_html.csv").read_bytes())

    analyze(upload_id, storage)

    db_session.expire_all()
    upload = db_session.get(Upload, upload_id)
    assert upload.bad_line_count > 0 and upload.line_count > upload.bad_line_count
    assert_consistent(db_session, upload_id)


def test_log_timezone_shifts_working_hours_end_to_end(client, analyst, storage, db_session):
    # The same generated week, declared as New York time: clock times are read as local (EDT).
    # jdoe's 02:40 Sunday activity is still night in New York, so it is still unusual hours.
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9)).write(out)
    client.post("/api/login", auth=GOOD)
    upload_id = upload_file(client, out.getvalue().encode(), log_timezone="America/New_York")

    analyze(upload_id, storage)

    anomalies, incidents = assert_consistent(db_session, upload_id)
    night = [a for a in anomalies if a.kind == "off_hours" and a.username == "jdoe" and "Sun 02:40" in a.reason]
    assert night and "EDT" in night[0].reason
    assert night[0].window_start == datetime(2026, 9, 27, 6, 40, tzinfo=UTC)  # 02:40 EDT = 06:40 UTC
    assert max(incidents, key=lambda i: i.priority_score).username == "jdoe"
