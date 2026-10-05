"""Timestamp parsing for log lines: every result is a timezone-aware UTC datetime.

- Formats: ISO 8601 ("2026-09-28 03:12:44", "...T...Z", "...+02:00") and Zscaler NSS's
  default ("Mon Jun 20 15:29:11 2022").
- Timestamps without a timezone are read in the upload's `log_timezone`, then converted to UTC.
  Explicit offsets win. For DST-ambiguous local times Python's default applies (fold=0: the
  first occurrence); this affects at most one hour per year.
- The format is detected ONCE per file (detect_timestamp_format) and its fast parser is reused
  for every line; strptime is avoided (slow and locale-dependent).
"""

from collections.abc import Callable
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TimestampError(ValueError):
    """A timestamp or timezone could not be understood."""


TimestampParser = Callable[[str, tzinfo], datetime]

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_WEEKDAYS = frozenset({"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"})


def load_timezone(name: str) -> ZoneInfo:
    """IANA timezone like 'UTC' or 'America/New_York'; TimestampError if unknown."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:  # ValueError: e.g. '../etc' style names
        raise TimestampError(f"Unknown timezone '{name}'") from exc


def _to_utc(dt: datetime, log_tz: tzinfo) -> datetime:
    if dt.tzinfo is None:  # naive: interpret in the log's timezone
        dt = dt.replace(tzinfo=log_tz)
    return dt.astimezone(UTC)


def parse_iso(value: str, log_tz: tzinfo) -> datetime:
    """ISO 8601 date AND time (fromisoformat is implemented in C, ~0.3 µs per call)."""
    if ":" not in value:  # fromisoformat accepts a bare date; a log line needs a time
        raise TimestampError(f"Not an ISO timestamp with a time: '{value}'")
    try:
        return _to_utc(datetime.fromisoformat(value), log_tz)
    except ValueError as exc:
        raise TimestampError(f"Not an ISO timestamp: '{value}'") from exc


def parse_nss(value: str, log_tz: tzinfo) -> datetime:
    """Zscaler NSS default 'Mon Jun 20 15:29:11 2022', split by hand (no strptime)."""
    parts = value.split()
    if len(parts) != 5 or parts[0] not in _WEEKDAYS or parts[1] not in _MONTHS:
        raise TimestampError(f"Not an NSS timestamp: '{value}'")
    _, month, day, clock, year = parts
    try:
        hour, minute, second = (int(x) for x in clock.split(":"))
        dt = datetime(int(year), _MONTHS[month], int(day), hour, minute, second)  # validates Feb 30 etc.
    except ValueError as exc:
        raise TimestampError(f"Not an NSS timestamp: '{value}'") from exc
    return _to_utc(dt, log_tz)


def detect_timestamp_format(sample: str) -> TimestampParser:
    """Pick the parser for a file from one sample timestamp (the first data line)."""
    for parser in (parse_iso, parse_nss):
        try:
            parser(sample, UTC)
            return parser
        except TimestampError:
            continue
    raise TimestampError(f"Unrecognized timestamp format: '{sample}'")
