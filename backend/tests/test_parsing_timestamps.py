from datetime import UTC, datetime

import pytest

from app.parsing.timestamps import (
    TimestampError,
    detect_timestamp_format,
    load_timezone,
    parse_iso,
    parse_nss,
)

NY = load_timezone("America/New_York")


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-28 03:12:44", utc(2026, 9, 28, 3, 12, 44)),        # space separator
        ("2026-09-28T03:12:44", utc(2026, 9, 28, 3, 12, 44)),        # T separator
        ("2026-09-28T03:12:44Z", utc(2026, 9, 28, 3, 12, 44)),       # explicit UTC
        ("2026-09-28T05:12:44+02:00", utc(2026, 9, 28, 3, 12, 44)),  # explicit offset
    ],
)
def test_iso_formats_to_utc(value, expected):
    result = parse_iso(value, UTC)

    assert result == expected
    assert result.tzinfo is UTC


def test_nss_format_to_utc():
    assert parse_nss("Mon Jun 20 15:29:11 2022", UTC) == utc(2022, 6, 20, 15, 29, 11)


def test_naive_time_uses_log_timezone_in_summer_and_winter():
    # New York is UTC-4 in summer (EDT) and UTC-5 in winter (EST).
    assert parse_iso("2026-07-01 03:00:00", NY) == utc(2026, 7, 1, 7, 0, 0)
    assert parse_iso("2026-01-15 03:00:00", NY) == utc(2026, 1, 15, 8, 0, 0)
    assert parse_nss("Wed Jul 01 03:00:00 2026", NY) == utc(2026, 7, 1, 7, 0, 0)


def test_explicit_offset_ignores_log_timezone():
    assert parse_iso("2026-07-01T03:00:00Z", NY) == utc(2026, 7, 1, 3, 0, 0)


@pytest.mark.parametrize(
    "value",
    ["not-a-date", "2026-02-30 10:00:00", "2026-09-28", ""],  # garbage, Feb 30, date only, empty
)
def test_bad_iso_raises(value):
    with pytest.raises(TimestampError):
        parse_iso(value, UTC)


@pytest.mark.parametrize(
    "value",
    ["Mon Feb 30 10:00:00 2026", "Mon Jun 20 25:00:00 2022", "Foo Jun 20 15:29:11 2022", "Mon Jun 20 2022"],
)
def test_bad_nss_raises(value):
    with pytest.raises(TimestampError):
        parse_nss(value, UTC)


@pytest.mark.parametrize("name", ["Not/AZone", "../../etc/passwd", ""])
def test_unknown_timezone_raises(name):
    with pytest.raises(TimestampError):
        load_timezone(name)


def test_detects_format_from_a_sample():
    assert detect_timestamp_format("2026-09-28 03:12:44") is parse_iso
    assert detect_timestamp_format("Mon Jun 20 15:29:11 2022") is parse_nss
    with pytest.raises(TimestampError):
        detect_timestamp_format("yesterday at noon")
