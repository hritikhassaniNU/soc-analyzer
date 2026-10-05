import statistics
from dataclasses import replace
from datetime import timedelta

import pytest

from app.detection.beaconing import detect_beaconing, regularity
from app.detection.rare_domains import detect_rare_domains, looks_random, name_label
from tests.test_behavior import BASE, MONDAY, generated, overlaps, run

TUESDAY_2PM = MONDAY + timedelta(days=1, hours=14)


def heartbeat(username: str, host: str, every_s: float, count: int, start=TUESDAY_2PM, jitter=(0,)):
    return [replace(BASE, username=username, host=host, url=f"{host}/ping",
                    ts=start + timedelta(seconds=i * every_s + jitter[i % len(jitter)]))
            for i in range(count)]


def crowd(host: str, users: int):
    """`users` different people visiting `host` once each (makes the host popular)."""
    return [replace(BASE, username=f"user{i}", host=host, ts=MONDAY + timedelta(hours=10, minutes=i))
            for i in range(users)]


# ---- regularity ----

def test_one_overnight_gap_does_not_hide_a_beacon():
    day1 = [i * 60.0 for i in range(240)]
    day2 = [day1[-1] + 16 * 3600 + i * 60.0 for i in range(240)]  # resumes the next morning
    gaps = [b - a for a, b in zip(day1 + day2, (day1 + day2)[1:])]

    assert statistics.stdev(gaps) / statistics.mean(gaps) > 10  # textbook CV: "irregular"
    assert regularity(day1 + day2) == (60.0, pytest.approx(478 / 479))  # median view: a timer


# ---- beaconing ----

def test_regular_traffic_to_a_rare_host_is_beaconing(tmp_path):
    beacon = heartbeat("jdoe", "cdn-update-check.xyz", 60, 480, jitter=(0, 0, 1, 0, 0, -1))  # gaps 59-61 s

    [finding] = run(tmp_path, beacon + crowd("example.com", 30), detect_beaconing)

    assert finding.kind == "beaconing" and finding.username == "jdoe" and finding.count == 480
    assert (finding.window_start, finding.window_end) == (beacon[0].ts, beacon[-1].ts)
    assert finding.score == 0.9  # 0.7 + very regular + long
    assert finding.reason == ("480 requests to cdn-update-check.xyz every ~60 s for 7 h 59 min "
                              "(100% on schedule); only this user in this file contacted it.")


def test_regular_polling_of_a_popular_service_is_not_beaconing(tmp_path):
    teams = heartbeat("alice", "teams.microsoft.com", 120, 120, jitter=(-5, 3, 5, -2))

    assert run(tmp_path, teams + crowd("teams.microsoft.com", 30), detect_beaconing) == []


@pytest.mark.parametrize(("every_s", "count", "why"), [
    (0.2, 600, "a burst, not a heartbeat"),
    (60, 30, "regular but only 30 minutes"),
])
def test_too_fast_or_too_short_is_not_beaconing(tmp_path, every_s, count, why):
    events = heartbeat("jdoe", "rare.example", every_s, count) + crowd("example.com", 30)

    assert run(tmp_path, events, detect_beaconing) == [], why


def test_human_browsing_is_irregular(tmp_path):
    browsing = heartbeat("jdoe", "rare.example", 30, 200, jitter=(1, 25, 4, 60, 13, 2, 41))

    assert run(tmp_path, browsing + crowd("example.com", 30), detect_beaconing) == []


# ---- rare, random-looking domains ----

@pytest.mark.parametrize(("label", "expected"), [
    ("g9hvq1kn5cnt", True), ("68370j7p0hqm", True), ("ila54h25q6em", True),
    ("office365", False),    # digits at the end
    ("1password", False),    # digit at the start
    ("win10tools", False),   # 2 digits, normal vowels
    ("brightsmart", False),  # few vowels, but no digits
    ("k8s", False),          # too short
    ("xn--bcher-kva", False),  # internationalized name
])
def test_looks_random(label, expected):
    assert looks_random(label) is expected


@pytest.mark.parametrize(("host", "label"), [
    ("g9hvq1kn5cnt.top", "g9hvq1kn5cnt"), ("files.Example.com.", "example"), ("localhost", "localhost"),
])
def test_name_label(host, label):
    assert name_label(host) == label


def test_random_domains_close_together_are_one_finding(tmp_path):
    names = ["g9hvq1kn5cnt.top", "ila54h25q6em.top", "68370j7p0hqm.top"]
    visits = [replace(BASE, username="rpatel", host=h, ts=TUESDAY_2PM + timedelta(minutes=2 * i))
              for i, h in enumerate(names)]

    [finding] = run(tmp_path, visits + crowd("example.com", 5), detect_rare_domains)

    assert finding.kind == "rare_domain" and finding.username == "rpatel" and finding.count == 3
    assert finding.score == 0.8 and finding.details["domains"] == names
    assert finding.reason == ("3 random-looking domains seen only by this user within 4 minutes: "
                              "g9hvq1kn5cnt.top, ila54h25q6em.top, 68370j7p0hqm.top.")


def test_far_apart_visits_are_separate_findings(tmp_path):
    visits = [replace(BASE, username="rpatel", host="g9hvq1kn5cnt.top", ts=TUESDAY_2PM),
              replace(BASE, username="rpatel", host="ila54h25q6em.top", ts=TUESDAY_2PM + timedelta(hours=3))]

    findings = run(tmp_path, visits, detect_rare_domains)

    assert [f.score for f in findings] == [0.6, 0.6]
    assert findings[0].reason == "1 random-looking domain seen only by this user: g9hvq1kn5cnt.top."


def test_random_name_seen_by_two_users_is_not_rare(tmp_path):
    shared = [replace(BASE, username=u, host="g9hvq1kn5cnt.top", ts=TUESDAY_2PM) for u in ("a", "b")]

    assert run(tmp_path, shared, detect_rare_domains) == []


# ---- the generated week, checked against its answer key ----

@pytest.mark.parametrize("seed", [42, 7])
def test_planted_beacon_and_dga_domains_are_found(tmp_path, seed):
    findings, generator = generated(tmp_path, seed=seed)
    plants = {p.kind: p for p in generator.plants}

    for kind in ("beaconing", "rare_domain"):
        matches = [f for f in findings if f.kind == kind]
        assert len(matches) == 1 and overlaps(matches[0], plants[kind]), kind


@pytest.mark.parametrize("seed", [42, 7])
def test_teams_polling_and_long_tail_are_quiet_on_a_clean_week(tmp_path, seed):
    findings, _ = generated(tmp_path, seed=seed, clean=True)

    assert [f for f in findings if f.kind in ("beaconing", "rare_domain")] == []


def test_statistical_layer_runs_all_five_detectors(tmp_path):
    findings, _ = generated(tmp_path, seed=42)  # generated() calls detect_statistical

    assert {f.kind for f in findings} == {
        "request_burst", "large_upload", "off_hours", "beaconing", "rare_domain"}
