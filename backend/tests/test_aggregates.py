import io
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from app.generator import Generator, GeneratorConfig
from app.parsing.csv_parser import CsvParser
from app.parsing.event import ZscalerEvent
from app.pipeline.aggregates import choose_bucket, compute_aggregates, duckdb_connection
from app.pipeline.pass1 import PARQUET_SCHEMA, _values

T0 = datetime(2026, 9, 22, 9, 0, tzinfo=UTC)
BASE = ZscalerEvent(
    line_no=1, ts=T0, username="alice", client_ip="10.0.0.1", url="example.com/", host="example.com",
    action="Allowed", risk_score=5, bytes_out=1_000, bytes_in=5_000, category="Business",
)


def write_parquet(path, events: list[ZscalerEvent]) -> None:
    rows = [_values(e) for e in events]  # same row building as pass 1 (incl. rules)
    columns = list(zip(*rows))
    pq.write_table(pa.Table.from_arrays(
        [pa.array(c, type=f.type) for c, f in zip(columns, PARQUET_SCHEMA)], schema=PARQUET_SCHEMA,
    ), path)


@pytest.fixture
def hand_built(tmp_path):
    """9 events where every expected number is easy to verify by eye."""
    events = [
        replace(BASE, line_no=1),
        replace(BASE, line_no=2, ts=T0 + timedelta(minutes=20)),
        replace(BASE, line_no=3, ts=T0 + timedelta(hours=1), username="bob", client_ip="10.0.0.2"),
        replace(BASE, line_no=4, ts=T0 + timedelta(hours=1), username="bob", client_ip="10.0.0.2",
                action="Blocked", category="Gambling", host="bet.example", bytes_in=0),
        replace(BASE, line_no=5, ts=T0 + timedelta(hours=2), username="jdoe", client_ip="10.0.0.3",
                host="mega.nz", category="File Sharing", method="POST", bytes_out=400_000_000,
                user_agent="python-requests/2.32.3"),
        replace(BASE, line_no=6, ts=T0 + timedelta(hours=2), username="carol", client_ip="10.0.0.4",
                action="Blocked", threat="Trojan.X", host="bad.ru", category="Malware", bytes_in=0),
        replace(BASE, line_no=7, ts=T0 + timedelta(hours=3), username="alice"),
        replace(BASE, line_no=8, ts=T0 + timedelta(hours=3), username="alice"),
        replace(BASE, line_no=9, ts=T0 + timedelta(hours=5), username="dave", client_ip="10.0.0.5"),
    ]
    path = tmp_path / "events.parquet"
    write_parquet(path, events)
    return path


def test_summary_stats_are_exact(hand_built):
    stats = compute_aggregates(hand_built)["stats"]

    assert stats["total_events"] == 9
    assert (stats["allowed"], stats["blocked"]) == (7, 2)
    assert (stats["unique_users"], stats["unique_client_ips"]) == (5, 5)
    assert stats["unique_hosts"] == 4  # example.com, bet.example, mega.nz, bad.ru
    assert stats["bytes_out"] == 8 * 1_000 + 400_000_000
    assert stats["threat_events"] == 1
    assert stats["rule_hits"] == {"scripted_client": 1, "zscaler_threat": 1}
    assert stats["flagged_events"] == 2
    assert stats["first_event"] == T0.isoformat()
    assert stats["last_event"] == (T0 + timedelta(hours=5)).isoformat()


def test_top_lists(hand_built):
    top = compute_aggregates(hand_built)["top"]

    assert top["users_by_requests"][0] == {"name": "alice", "value": 4}
    assert top["users_by_bytes_out"][0] == {"name": "jdoe", "value": 400_000_000}  # exfil stands out
    assert top["blocked_categories"] == [{"name": "Gambling", "value": 1}, {"name": "Malware", "value": 1}]
    assert top["threats"] == [{"name": "Trojan.X", "value": 1}]


def test_timeline_buckets_are_utc_and_add_up(hand_built):
    timeline = compute_aggregates(hand_built)["timeline"]
    points = timeline["points"]

    assert timeline["bucket"] == "5 minutes"  # 5 h range (<= 12 h)
    assert len(points) == 61  # 09:00 .. 14:00 every 5 min, INCLUDING empty buckets
    assert sum(p["total"] for p in points) == 9
    assert sum(p["blocked"] for p in points) == 2
    assert all(p["t"].endswith("+00:00") for p in points)  # UTC, not the machine's local zone


@pytest.mark.parametrize(
    ("span", "bucket"),
    [(timedelta(minutes=90), "1 minute"), (timedelta(hours=5), "5 minutes"),
     (timedelta(hours=30), "15 minutes"), (timedelta(days=7), "1 hour"), (timedelta(days=60), "1 day")],
)
def test_bucket_size_adapts_to_range(span, bucket):
    assert choose_bucket(T0, T0 + span) == bucket


def test_connection_is_bounded_and_utc():
    con = duckdb_connection()
    settings = dict(con.execute(
        "SELECT name, value FROM duckdb_settings() WHERE name IN ('threads', 'TimeZone', 'memory_limit')"
    ).fetchall())

    assert settings["threads"] == "2"
    assert settings["TimeZone"] == "UTC"
    assert settings["memory_limit"].endswith(("GiB", "GB", "MiB"))


def test_generated_week_numbers_match_the_parser(tmp_path):
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=10, seed=4)).write(out)
    events = list(CsvParser(UTC).parse(out.getvalue().splitlines(keepends=True)))
    path = tmp_path / "week.parquet"
    write_parquet(path, events)

    result = compute_aggregates(path)

    assert result["stats"]["total_events"] == len(events)
    assert result["stats"]["blocked"] == sum(e.action == "Blocked" for e in events)
    assert result["timeline"]["bucket"] == "1 hour"
    points = result["timeline"]["points"]
    first = datetime.fromisoformat(result["stats"]["first_event"]).replace(minute=0, second=0)
    last = datetime.fromisoformat(result["stats"]["last_event"]).replace(minute=0, second=0)
    assert len(points) == (last - first) // timedelta(hours=1) + 1  # one point per hour, no gaps
    assert any(p["total"] == 0 for p in points)  # quiet hours (nights) are present as zeros
    assert result["top"]["users_by_bytes_out"][0]["name"] == "jdoe"  # the exfiltration
