from datetime import timedelta

import pytest

from app.detection.correlate import correlate, parse_hosts, priority_label
from app.detection.findings import Finding
from app.detection.rule_groups import group_rule_hits
from app.evaluate import AI_ONLY_KINDS
from app.pipeline.aggregates import duckdb_connection
from tests.test_behavior import MONDAY, generated, overlaps

TUESDAY = MONDAY + timedelta(days=1, hours=14)
APPROVED = parse_hosts("acme.sharepoint.com, Drive.Google.com")


def finding(kind, score, at=TUESDAY, username="jdoe", minutes=1, **details) -> Finding:
    return Finding(username=username, window_start=at, window_end=at + timedelta(minutes=minutes),
                   kind=kind, score=score, reason="r", count=1, details=details)


def test_the_compromised_user_story_is_one_critical_incident():
    story = [
        finding("executable_download", 0.8),
        finding("scripted_client", 0.6),
        finding("beaconing", 0.9, at=TUESDAY + timedelta(minutes=1), minutes=480),
        finding("off_hours", 0.7, at=TUESDAY + timedelta(hours=6), minutes=125),
    ]

    [incident] = correlate(story)

    # 0.9 (beaconing) + 0.1 x executable (0.72) + 0.1 x unusual hours (0.42); automated traffic
    # (0.6 x 0.6 = 0.36) is below the 0.4 minimum: attached as evidence, no bonus.
    assert incident.priority_score == 1.0 and incident.priority == "critical"
    assert incident.title == "Command & control, executable download, unusual hours"
    assert incident.categories == ["command_and_control", "executable_download",
                                   "unusual_hours", "automated_traffic"]
    assert sorted(incident.members) == [0, 1, 2, 3]
    assert (incident.start, incident.end) == (TUESDAY, TUESDAY + timedelta(hours=6, minutes=125))  # off-hours ends last


def test_severity_keeps_a_burst_alone_at_medium():
    [incident] = correlate([finding("request_burst", 0.99, username="bsmith")])

    assert incident.priority_score == pytest.approx(0.594) and incident.priority == "medium"


@pytest.mark.parametrize(("host", "priority"), [
    ("mega.nz", "critical"),             # 0.99: not approved
    ("drive.google.com", "low"),         # 0.99 x 0.4 = 0.40
    ("eu.drive.google.com", "low"),      # subdomains of approved hosts count too
    ("drive.google.com.evil.io", "critical"),  # but not look-alike suffixes
])
def test_uploads_to_approved_storage_are_down_ranked(host, priority):
    [incident] = correlate([finding("large_upload", 0.99, top_host=host)], APPROVED)

    assert incident.priority == priority


def test_weak_evidence_is_attached_but_does_not_raise_priority():
    windows_update = finding("executable_download", 0.2, username="rpatel")
    dga = finding("rare_domain", 0.8, at=TUESDAY + timedelta(hours=23), username="rpatel")

    [incident] = correlate([windows_update, dga])

    assert incident.priority_score == pytest.approx(0.8)
    assert incident.title == "Command & control"  # not "..., executable download"
    assert len(incident.members) == 2


def test_two_findings_of_one_category_do_not_corroborate_each_other():
    nights = [finding("off_hours", 0.7), finding("off_hours", 0.7, at=TUESDAY + timedelta(hours=3))]

    [incident] = correlate(nights)

    assert incident.priority_score == pytest.approx(0.42) and incident.priority == "low"


def test_findings_chain_within_24_hours_per_user():
    findings = [
        finding("off_hours", 0.7),
        finding("off_hours", 0.7, at=TUESDAY + timedelta(hours=23)),  # chains to the first
        finding("off_hours", 0.7, at=TUESDAY + timedelta(days=4)),    # 4 days later: new incident
        finding("off_hours", 0.7, username="alice"),                  # other user: never merged
    ]

    incidents = correlate(findings)

    assert sorted(len(i.members) for i in incidents) == [1, 1, 2]
    assert sorted(m for i in incidents for m in i.members) == [0, 1, 2, 3]  # each exactly once


def test_incidents_are_listed_worst_first():
    findings = [finding("off_hours", 0.7, username="a"), finding("zscaler_threat", 0.9, username="b"),
                finding("request_burst", 0.99, username="c")]

    assert [i.username for i in correlate(findings)] == ["b", "c", "a"]


@pytest.mark.parametrize(("score", "label"), [
    (1.0, "critical"), (0.95, "critical"), (0.949, "high"), (0.75, "high"),
    (0.45, "medium"), (0.449, "low"), (0.0, "low"),
])
def test_priority_cutoffs(score, label):
    assert priority_label(score) == label


def test_parse_hosts():
    assert parse_hosts(" a.com, B.com ,,") == frozenset({"a.com", "b.com"})
    assert parse_hosts("") == frozenset()


# ---- the generated week, end to end through rules + statistics + correlation ----

def ranked(tmp_path, **config):
    stat_findings, generator = generated(tmp_path, **config)
    findings = group_rule_hits(duckdb_connection(), tmp_path / "generated.parquet") + stat_findings
    return findings, correlate(findings, parse_hosts("acme.sharepoint.com,drive.google.com")), generator


@pytest.mark.parametrize("seed", [42, 7])
def test_attacks_rank_on_top(tmp_path, seed):
    findings, incidents, generator = ranked(tmp_path, seed=seed)

    assert [(i.priority, i.username) for i in incidents[:2]] == [("critical", "jdoe")] * 2
    assert {i.username for i in incidents if i.priority == "high"} == {"amiller", "kchen", "rpatel"}
    assert [i.username for i in incidents if i.priority == "medium"] == ["bsmith"]
    # Every planted attack is evidence inside a medium-or-higher incident (AI-only plants need the
    # AI classifier, tested in test_ai_domains.py).
    for plant in (p for p in generator.plants if p.kind not in AI_ONLY_KINDS):
        assert any(i.priority != "low" and any(overlaps(findings[m], plant) for m in i.members)
                   for i in incidents), plant.kind


@pytest.mark.parametrize("seed", [42, 7])
def test_clean_week_has_only_low_incidents(tmp_path, seed):
    _, incidents, _ = ranked(tmp_path, seed=seed, clean=True)

    assert incidents and {i.priority for i in incidents} == {"low"}
