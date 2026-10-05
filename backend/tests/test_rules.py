import io
import time
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from app.detection.rules import (
    apply_rules,
    executable_download,
    high_risk_allowed,
    scripted_client,
    zscaler_threat,
)
from app.generator import Generator, GeneratorConfig
from app.parsing.csv_parser import CsvParser
from app.parsing.event import ZscalerEvent

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0"

NORMAL = ZscalerEvent(
    line_no=1, ts=datetime(2026, 9, 22, 10, 0, tzinfo=UTC), username="jdoe", client_ip="10.1.0.2",
    url="www.nytimes.com/news/latest", host="www.nytimes.com", action="Allowed", risk_score=10,
    bytes_out=900, bytes_in=80_000, category="News and Media", user_agent=BROWSER,
)


def test_normal_browsing_fires_nothing():
    assert apply_rules(NORMAL) == []


# ---- zscaler_threat ----

def test_threat_allowed_scores_higher_than_blocked():
    allowed = zscaler_threat(replace(NORMAL, threat="Trojan.GenericKD.71345"))
    blocked = zscaler_threat(replace(NORMAL, threat="Trojan.GenericKD.71345", action="Blocked"))

    assert (allowed.score, blocked.score) == (0.99, 0.90)
    assert blocked.reason == "Zscaler detected Trojan.GenericKD.71345 (blocked)"


# ---- high_risk_allowed ----

@pytest.mark.parametrize(("risk", "fires"), [(74, False), (75, True), (100, True)])
def test_high_risk_threshold(risk, fires):
    hit = high_risk_allowed(replace(NORMAL, risk_score=risk))

    assert (hit is not None) == fires
    if fires:
        assert hit.score == risk / 100


def test_high_risk_but_blocked_does_not_fire():
    assert high_risk_allowed(replace(NORMAL, risk_score=95, action="Blocked")) is None


def test_mid_risk_ad_page_lookalike_does_not_fire():
    assert high_risk_allowed(replace(NORMAL, risk_score=55, host="ads.adnetwork-cdn.com")) is None


# ---- scripted_client ----

@pytest.mark.parametrize(
    "agent",
    ["python-requests/2.32.3", "curl/8.9.1", "Wget/1.21.4", "Go-http-client/1.1",
     "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1"],
)
def test_scripted_clients_fire(agent):
    hit = scripted_client(replace(NORMAL, user_agent=agent))

    assert hit is not None and hit.score == 0.6


@pytest.mark.parametrize("agent", [BROWSER, "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)", None, ""])
def test_browsers_and_missing_agents_do_not_fire(agent):
    assert scripted_client(replace(NORMAL, user_agent=agent)) is None


def test_dev_curl_lookalike_fires_with_low_score():
    """Correct at the rule level (one line can't know intent); correlation ranks it later."""
    hit = scripted_client(replace(NORMAL, user_agent="curl/8.9.1", host="github.com"))

    assert hit.score == 0.6


# ---- executable_download ----

def test_executable_from_file_sharing_scores_high():
    hit = executable_download(replace(NORMAL, file_type="exe", host="files.anonshare.io", category="File Sharing"))

    assert hit.score == 0.8
    assert hit.reason == "Executable (exe) downloaded from files.anonshare.io (File Sharing)"


def test_software_update_lookalike_is_ranked_down_not_hidden():
    hit = executable_download(
        replace(NORMAL, file_type="msi", host="update.microsoft.com", category="Software Updates")
    )

    assert hit is not None and hit.score == 0.2


@pytest.mark.parametrize("file_type", ["pdf", "zip", None, ""])
def test_non_executables_do_not_fire(file_type):
    assert executable_download(replace(NORMAL, file_type=file_type)) is None


# ---- against the generator's answer key ----

@pytest.fixture(scope="module")
def generated():
    out = io.StringIO()
    generator = Generator(GeneratorConfig(days=7, users=10, seed=11))
    generator.write(out)
    events = {e.line_no: e for e in CsvParser(UTC).parse(out.getvalue().splitlines(keepends=True))}
    return events, generator


@pytest.mark.parametrize(
    ("kind", "rule"),
    [("zscaler_threat", "zscaler_threat"), ("high_risk_allowed", "high_risk_allowed"),
     ("executable_download", "executable_download"), ("large_upload", "scripted_client")],
)
def test_planted_attacks_trigger_their_rule(generated, kind, rule):
    events, generator = generated
    plant = next(p for p in generator.plants if p.kind == kind)

    for line_no in plant.line_nos:
        assert rule in {h.rule for h in apply_rules(events[line_no])}, f"{kind} line {line_no}"


def test_rules_are_quiet_on_normal_traffic(generated):
    events, generator = generated
    flagged = {n for p in [*generator.plants, *generator.benign.values()] for n in p.line_nos}
    noisy = [e for n, e in events.items() if n not in flagged and apply_rules(e)]

    assert noisy == []  # ordinary browsing never fires a rule


def test_rules_are_cheap_per_line(generated):
    events, _ = generated
    sample = list(events.values())
    start = time.perf_counter()
    for event in sample:
        apply_rules(event)
    per_line_us = (time.perf_counter() - start) / len(sample) * 1e6

    print(f"\nrules: {per_line_us:.2f} µs per line -> ~{per_line_us * 3:.1f} s per 3M lines")
    assert per_line_us < 20
