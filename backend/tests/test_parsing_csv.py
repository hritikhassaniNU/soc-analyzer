import csv
import io
import time
from datetime import UTC, datetime

import pytest

from app.parsing.csv_parser import (
    EARLY_STOP_LINES,
    MAX_BAD_SAMPLES,
    CsvParser,
    NotZscalerLogError,
)
from app.parsing.fields import CSV_COLUMNS, LEGACY_WIDTH
from app.parsing.timestamps import load_timezone

GOOD = {
    "time": "2026-09-28 03:12:44",
    "user": "JDoe",
    "department": "Finance",
    "location": "NYC-HQ",
    "client_ip": "10.1.4.22",
    "server_ip": "151.101.1.1",
    "protocol": "HTTPS",
    "method": "POST",
    "url": "mega.nz/upload?id=1,2",  # comma inside a field -> must be quoted
    "action": "Allowed",
    "url_category": "File Sharing",
    "app_name": "MEGA",
    "threat_name": "None",
    "malware_category": "",
    "risk_score": "45",
    "status_code": "200",
    "bytes_sent": "412000000",
    "bytes_received": "1200",
    "user_agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) "quoted"',  # commas-free but has quotes
    "file_type": "",
    "device": "LT-JDOE-01",
    "device_os": "Windows",
}


def to_csv(*rows: dict | list, header: list[str] | None = None) -> list[str]:
    """Write rows the way a real CSV writer would (quoting commas and quotes)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(header)
    for row in rows:
        writer.writerow([row[c] for c in CSV_COLUMNS] if isinstance(row, dict) else row)
    return buffer.getvalue().splitlines(keepends=True)


def parse(lines: list[str], tz: str = "UTC") -> tuple[list, CsvParser]:
    parser = CsvParser(load_timezone(tz))
    return list(parser.parse(lines)), parser


def with_(**overrides: str) -> dict:
    return {**GOOD, **overrides}


# ---- happy path ----


def test_parses_a_full_line():
    (event,), parser = parse(to_csv(GOOD))

    assert event.line_no == 1
    assert event.ts == datetime(2026, 9, 28, 3, 12, 44, tzinfo=UTC)
    assert event.username == "jdoe"  # lowercased
    assert event.url == "mega.nz/upload?id=1,2"  # comma survived quoting
    assert event.host == "mega.nz"
    assert event.action == "Allowed"
    assert event.threat is None  # "None" normalized
    assert event.malware_category is None  # empty -> None
    assert (event.risk_score, event.bytes_out, event.bytes_in, event.status_code) == (45, 412000000, 1200, 200)
    assert event.user_agent == 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) "quoted"'
    assert (event.device, event.device_os) == ("LT-JDOE-01", "Windows")
    assert parser.stats.good_lines == 1 and parser.stats.bad_lines == 0


def test_action_is_case_insensitive_and_threat_kept():
    (event,), _ = parse(to_csv(with_(action="BLOCKED", threat_name="Trojan.GenericKD")))

    assert event.action == "Blocked"
    assert event.threat == "Trojan.GenericKD"


def test_nss_timestamps_and_log_timezone():
    (event,), _ = parse(to_csv(with_(time="Wed Jul 01 03:00:00 2026")), tz="America/New_York")

    assert event.ts == datetime(2026, 7, 1, 7, 0, 0, tzinfo=UTC)  # 03:00 EDT = 07:00 UTC


# ---- header handling ----


def test_header_row_is_detected_and_skipped():
    events, parser = parse(to_csv(GOOD, header=list(CSV_COLUMNS)))

    assert len(events) == 1
    assert parser.stats.header_detected
    assert parser.stats.total_lines == 1  # header not counted
    assert events[0].line_no == 2  # physical line number in the file


def test_reordered_columns_are_mapped_by_header_name():
    reordered = list(reversed(CSV_COLUMNS))
    row = [GOOD[c] for c in reordered]

    (event,), _ = parse(to_csv(row, header=reordered))

    assert event.username == "jdoe" and event.host == "mega.nz" and event.risk_score == 45


def test_header_missing_required_column_rejects_file():
    header = [c for c in CSV_COLUMNS if c != "risk_score"]

    with pytest.raises(NotZscalerLogError, match="risk_score"):
        parse(to_csv(header=header))


# ---- bad lines ----


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (with_(user=""), "Missing required field 'user'"),
        (with_(time="yesterday"), "Not an ISO timestamp"),  # format already detected as ISO from line 1
        (with_(risk_score="high"), "not a number"),
        (with_(risk_score="101"), "out of range"),
        (with_(bytes_sent="-5"), "out of range"),
        (with_(action="Maybe"), "must be Allowed or Blocked"),
        (["too", "few", "columns"], "Expected 20 or 22 columns"),
    ],
)
def test_bad_line_is_counted_with_reason_and_parsing_continues(row, reason):
    events, parser = parse(to_csv(GOOD, row, GOOD))  # bad line in the middle

    assert len(events) == 2  # good lines before AND after still parsed
    assert parser.stats.bad_lines == 1
    sample = parser.stats.bad_samples[0]
    assert sample.line_no == 2
    assert reason in sample.reason


def test_blank_lines_are_ignored():
    events, parser = parse(["\n", *to_csv(GOOD), "   \n", "\n"])

    assert len(events) == 1
    assert parser.stats.total_lines == 1 and parser.stats.bad_lines == 0


def test_bad_samples_are_capped_and_raw_is_truncated():
    bad = with_(risk_score="x", url="a" * 1000)
    events, parser = parse(to_csv(*([GOOD] * 30), *([bad] * 25)))

    assert parser.stats.bad_lines == 25
    assert len(parser.stats.bad_samples) == MAX_BAD_SAMPLES
    assert all(len(s.raw) <= 300 for s in parser.stats.bad_samples)


def test_more_than_half_bad_rejects_file():
    with pytest.raises(NotZscalerLogError, match="more than 50%"):
        parse(to_csv(GOOD, with_(user=""), with_(user="")))


def test_non_zscaler_file_stops_early_without_reading_everything():
    def binary_junk():
        for i in range(10_000_000):  # would take ages if fully read
            yield f"\x89PNG garbage line {i}\n"

    parser = CsvParser(load_timezone("UTC"))
    with pytest.raises(NotZscalerLogError, match="first 1000 lines"):
        list(parser.parse(binary_junk()))
    assert parser.stats.total_lines == EARLY_STOP_LINES


def test_empty_file_is_rejected():
    with pytest.raises(NotZscalerLogError, match="no log lines"):
        parse(["\n", "\n"])


def test_oversized_field_is_a_bad_line_not_a_crash():
    giant = with_(user_agent="x" * 200_000)  # beyond csv's 128 KB field limit
    events, parser = parse(to_csv(GOOD, giant, GOOD))

    assert len(events) == 2
    assert "CSV error" in parser.stats.bad_samples[0].reason


# ---- performance smoke check ----


def test_parses_100k_lines_reasonably_fast():
    lines = to_csv(GOOD) * 100_000

    start = time.perf_counter()
    events, _ = parse(lines)
    elapsed = time.perf_counter() - start

    assert len(events) == 100_000
    print(f"\n100k lines in {elapsed:.2f}s -> ~{elapsed * 30:.0f}s per 3M lines")
    assert elapsed < 10  # generous ceiling; real number is printed above


def test_header_with_nss_style_names_in_any_order():
    header = "login,datetime,cip,url,action,pagerisk,reqsize,respsize\n"
    row = "JDoe,2026-09-28 03:12:44,10.0.0.5,mega.nz/upload,Allowed,30,400000000,1200\n"
    parser = CsvParser(load_timezone("UTC"))

    [event] = list(parser.parse([header, row]))

    assert parser.stats.header_detected
    assert (event.username, event.client_ip, event.host, event.bytes_out) == ("jdoe", "10.0.0.5", "mega.nz", 400_000_000)


def test_headerless_file_from_before_the_device_columns_still_parses():
    old = [GOOD[c] for c in CSV_COLUMNS[:LEGACY_WIDTH]]  # the original 20-column layout

    events, parser = parse(to_csv(old, GOOD))

    assert parser.stats.bad_lines == 0
    assert (events[0].device, events[0].device_os) == (None, None)
    assert events[1].device == "LT-JDOE-01"


def test_empty_device_is_none():
    (event,), _ = parse(to_csv(with_(device="", device_os="")))
    assert (event.device, event.device_os) == (None, None)


def test_device_fields_by_nss_names():
    header = "login,datetime,cip,url,action,pagerisk,reqsize,respsize,devicehostname,deviceostype\n"
    row = "JDoe,2026-09-28 03:12:44,10.0.0.5,mega.nz/upload,Allowed,30,400,1200,LT-JDOE-02,macOS\n"

    [event] = list(CsvParser(load_timezone("UTC")).parse([header, row]))

    assert (event.device, event.device_os) == ("LT-JDOE-02", "macOS")
