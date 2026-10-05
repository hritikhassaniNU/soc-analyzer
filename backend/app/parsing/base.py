"""What every log format shares: field validation, bad-line accounting, and when to give up.

A format-specific parser (CSV, JSON lines) only turns one record into named fields; this base turns
named fields into a ZscalerEvent with the same rules for every format, so they can't drift apart.

One bad line never stops the parse: it is counted and sampled. The whole file is rejected
(NotZscalerLogError) only if it clearly isn't a supported log: the first 1,000 data lines are all
bad, or more than half of all lines are bad.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import tzinfo

from app.parsing.event import Action, ZscalerEvent, derive_host
from app.parsing.timestamps import TimestampError, TimestampParser, detect_timestamp_format

MAX_BAD_SAMPLES = 20
SAMPLE_MAX_CHARS = 300
EARLY_STOP_LINES = 1_000
MAX_BAD_RATIO = 0.5

_ACTIONS: dict[str, Action] = {"allowed": "Allowed", "blocked": "Blocked"}
_NO_THREAT = frozenset({"", "none", "na", "n/a", "-"})

Getter = Callable[[str], "str | None"]  # field name -> cleaned value (None if empty/absent)


class NotZscalerLogError(ValueError):
    """The file as a whole doesn't look like a supported Zscaler web log."""


class LineError(ValueError):
    """One line is unusable; the message becomes the bad-line reason."""


@dataclass
class BadLine:
    line_no: int
    reason: str
    raw: str  # truncated; shown escaped in the UI (it may contain attacker-controlled text)


@dataclass
class ParseStats:
    total_lines: int = 0  # non-blank data lines (header excluded)
    good_lines: int = 0
    bad_lines: int = 0
    header_detected: bool = False
    bad_samples: list[BadLine] = field(default_factory=list)

    @property
    def bad_ratio(self) -> float:
        return self.bad_lines / self.total_lines if self.total_lines else 0.0


class LineParser:
    FORMAT_NAME = "log"  # used in messages

    def __init__(self, log_tz: tzinfo) -> None:
        self.log_tz = log_tz
        self.stats = ParseStats()
        self._parse_ts: TimestampParser | None = None  # detected once per file

    # ---- for subclasses ----

    def _accept(self, fields: Callable[[], Getter], line_no: int, raw: str) -> ZscalerEvent | None:
        """Count one data line; return its event, or record it as bad and return None.
        `fields` builds the getter and may itself raise LineError (e.g. invalid JSON)."""
        self.stats.total_lines += 1
        try:
            event = self._event(fields(), line_no)
        except LineError as exc:
            self._record_bad(line_no, str(exc), raw)
            event = None
        else:
            self.stats.good_lines += 1
        if self.stats.total_lines == EARLY_STOP_LINES and self.stats.good_lines == 0:
            raise NotZscalerLogError(
                f"The first {EARLY_STOP_LINES} lines are all invalid: this doesn't look like "
                f"a Zscaler web log in the expected {self.FORMAT_NAME} layout"
            )
        return event

    def _finish(self) -> None:
        if self.stats.total_lines == 0:
            raise NotZscalerLogError("The file contains no log lines")
        if self.stats.bad_ratio > MAX_BAD_RATIO:
            raise NotZscalerLogError(
                f"{self.stats.bad_lines} of {self.stats.total_lines} lines are invalid "
                f"(more than {MAX_BAD_RATIO:.0%})"
            )

    def _record_bad(self, line_no: int, reason: str, raw: str) -> None:
        self.stats.bad_lines += 1
        if len(self.stats.bad_samples) < MAX_BAD_SAMPLES:
            self.stats.bad_samples.append(
                BadLine(line_no=line_no, reason=reason, raw=raw.rstrip("\r\n")[:SAMPLE_MAX_CHARS])
            )

    # ---- shared validation: named fields -> event ----

    def _event(self, get: Getter, line_no: int) -> ZscalerEvent:
        def required(name: str) -> str:
            value = get(name)
            if value is None:
                raise LineError(f"Missing required field '{name}'")
            return value

        def integer(name: str, value: str, low: int | None = None, high: int | None = None) -> int:
            try:
                number = int(value)
            except ValueError:
                raise LineError(f"Field '{name}' is not a number: '{value[:40]}'") from None
            if (low is not None and number < low) or (high is not None and number > high):
                raise LineError(f"Field '{name}' out of range: {number}")
            return number

        time_value = required("time")
        try:
            if self._parse_ts is None:
                self._parse_ts = detect_timestamp_format(time_value)
            ts = self._parse_ts(time_value, self.log_tz)
        except TimestampError as exc:
            raise LineError(str(exc)) from None

        action = _ACTIONS.get(required("action").lower())
        if action is None:
            raise LineError(f"Field 'action' must be Allowed or Blocked: '{get('action')}'")

        threat = get("threat_name")
        if threat is not None and threat.lower() in _NO_THREAT:
            threat = None

        status = get("status_code")
        url = required("url")
        return ZscalerEvent(
            line_no=line_no,
            ts=ts,
            username=required("user").lower(),
            client_ip=required("client_ip"),
            url=url,
            host=derive_host(url),
            action=action,
            risk_score=integer("risk_score", required("risk_score"), 0, 100),
            bytes_out=integer("bytes_sent", required("bytes_sent"), 0),
            bytes_in=integer("bytes_received", required("bytes_received"), 0),
            department=get("department"),
            location=get("location"),
            server_ip=get("server_ip"),
            protocol=get("protocol"),
            method=get("method"),
            category=get("url_category"),
            app_name=get("app_name"),
            threat=threat,
            malware_category=get("malware_category"),
            status_code=integer("status_code", status) if status is not None else None,
            user_agent=get("user_agent"),
            file_type=get("file_type"),
            device=get("device"),
            device_os=get("device_os"),
        )
