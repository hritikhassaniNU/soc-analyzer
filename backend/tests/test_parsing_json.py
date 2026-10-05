import csv
import io
import json
from datetime import UTC, datetime

import pytest

from app.parsing.base import NotZscalerLogError
from app.parsing.csv_parser import CsvParser
from app.parsing.json_parser import JsonLinesParser
from app.parsing.timestamps import load_timezone
from tests.test_parsing_csv import GOOD  # the same record as the CSV tests use

UTC_TZ = load_timezone("UTC")


def parse(lines, tz=UTC_TZ):
    parser = JsonLinesParser(tz)
    return list(parser.parse(lines)), parser.stats


def line(**overrides) -> str:
    return json.dumps({**GOOD, **overrides}) + "\n"


def test_a_json_line_gives_the_same_event_as_the_csv_line():
    out = io.StringIO()
    csv.writer(out).writerow(GOOD.values())  # proper quoting (the user agent contains quotes)
    csv_line = out.getvalue()
    [from_csv] = list(CsvParser(UTC_TZ).parse([csv_line]))

    [from_json], stats = parse([line()])

    assert from_json == from_csv  # same validation, same result
    assert (stats.total_lines, stats.good_lines) == (1, 1)


def test_numbers_may_be_numbers_and_unknown_keys_are_ignored():
    [event], _ = parse([line(risk_score=85, bytes_sent=512.0, bytes_received=2048, extra={"x": 1})])

    assert (event.risk_score, event.bytes_out, event.bytes_in) == (85, 512, 2048)


def test_nss_style_keys_and_the_splunk_envelope():
    nss = {"datetime": "Mon Sep 28 03:12:44 2026", "login": "JDoe", "ClientIP": "10.0.0.5",
           "url": "mega.nz/upload", "action": "Allowed", "pagerisk": 30, "requestsize": 400000000,
           "responsesize": 1200, "useragent": "python-requests/2.32.3", "urlcategory": "File Sharing",
           "devicehostname": "LT-JDOE-01", "deviceostype": "Windows"}
    record = json.dumps({"sourcetype": "zscalernss-web", "event": nss}) + "\n"

    [event], _ = parse([record])

    assert event.ts == datetime(2026, 9, 28, 3, 12, 44, tzinfo=UTC)
    assert (event.username, event.client_ip, event.host) == ("jdoe", "10.0.0.5", "mega.nz")
    assert (event.bytes_out, event.user_agent, event.category) == (400_000_000, "python-requests/2.32.3", "File Sharing")
    assert (event.device, event.device_os) == ("LT-JDOE-01", "Windows")


@pytest.mark.parametrize(("raw", "reason"), [
    ("{not json\n", "Not valid JSON"),
    ('["a", "list"]\n', "Each line must be a JSON object"),
    (json.dumps({**GOOD, "user": {"name": "x"}}) + "\n", "Field 'user' must be a string or number"),
    (json.dumps({**GOOD, "risk_score": True}) + "\n", "not true/false"),
    (json.dumps({k: v for k, v in GOOD.items() if k != "url"}) + "\n", "Missing required field 'url'"),
])
def test_bad_lines_are_counted_with_a_reason(raw, reason):
    events, stats = parse([line(), raw, line()])

    assert len(events) == 2 and stats.bad_lines == 1
    assert reason in stats.bad_samples[0].reason and stats.bad_samples[0].line_no == 2


def test_blank_lines_are_ignored_and_line_numbers_stay_physical():
    events, stats = parse([line(), "\n", "   \n", line()])

    assert [e.line_no for e in events] == [1, 4] and stats.total_lines == 2


def test_mostly_invalid_file_is_rejected_like_csv():
    with pytest.raises(NotZscalerLogError, match="lines are invalid"):
        parse([line(), "nope\n", "nope\n"])
