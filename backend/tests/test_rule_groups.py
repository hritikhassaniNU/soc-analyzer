from dataclasses import replace
from datetime import timedelta

import pytest

from app.detection.rule_groups import BATCH_ROWS, group_rule_hits
from app.pipeline.aggregates import duckdb_connection
from tests.test_behavior import BASE, MONDAY, generated, overlaps, run

T = MONDAY + timedelta(days=2, hours=10, minutes=15)
THREAT = replace(BASE, username="amiller", host="free-invoice-download.ru", action="Blocked",
                 threat="Trojan.GenericKD.71345", risk_score=95)
CURL = replace(BASE, username="pwilson", host="github.com", user_agent="curl/8.9.1")


def test_hits_close_together_are_one_finding(tmp_path):
    hits = [replace(THREAT, ts=T + timedelta(seconds=20 * i)) for i in range(3)]

    [finding] = run(tmp_path, [BASE, *hits], group_rule_hits)  # BASE: an unflagged line

    assert finding.kind == "zscaler_threat" and finding.username == "amiller"
    assert (finding.window_start, finding.window_end, finding.count) == (hits[0].ts, hits[-1].ts, 3)
    assert finding.score == pytest.approx(0.90)  # blocked
    assert finding.reason == "Zscaler detected Trojan.GenericKD.71345 (blocked) (3 times within 40 seconds)."
    assert finding.details["hosts"] == {"free-invoice-download.ru": 3}
    assert finding.details["sample_line_nos"] == [2, 3, 4]


def test_a_gap_over_one_hour_starts_a_new_finding(tmp_path):
    hits = [replace(CURL, ts=T), replace(CURL, ts=T + timedelta(minutes=59)),
            replace(CURL, ts=T + timedelta(minutes=59 + 61))]

    findings = run(tmp_path, hits, group_rule_hits)

    assert [f.count for f in findings] == [2, 1]


def test_each_rule_keeps_its_own_score(tmp_path):
    # One line, two rules: executable (0.8) + scripted client (0.6). The line's max is 0.8.
    download = replace(BASE, username="jdoe", ts=T, host="files.anonshare.io", category="File Sharing",
                       file_type="exe", user_agent="python-requests/2.32.3")

    findings = {f.kind: f.score for f in run(tmp_path, [download], group_rule_hits)}

    assert findings == {"executable_download": pytest.approx(0.8), "scripted_client": pytest.approx(0.6)}


def test_users_and_rules_are_grouped_separately(tmp_path):
    hits = [replace(CURL, ts=T), replace(CURL, username="alice", ts=T + timedelta(seconds=5)),
            replace(THREAT, username="alice", ts=T + timedelta(seconds=10))]

    findings = run(tmp_path, hits, group_rule_hits)

    assert sorted((f.username, f.kind) for f in findings) == [
        ("alice", "scripted_client"), ("alice", "zscaler_threat"), ("pwilson", "scripted_client")]


def test_more_flagged_lines_than_one_batch(tmp_path):
    hits = [replace(CURL, ts=T + timedelta(seconds=i)) for i in range(BATCH_ROWS + 5)]

    [finding] = run(tmp_path, hits, group_rule_hits)

    assert finding.count == BATCH_ROWS + 5


def test_no_flagged_lines_no_findings(tmp_path):
    assert run(tmp_path, [BASE], group_rule_hits) == []


@pytest.mark.parametrize("seed", [42, 7])
def test_planted_rule_attacks_become_findings(tmp_path, seed):
    _, generator = generated(tmp_path, seed=seed)
    path = tmp_path / "generated.parquet"  # written by generated()
    findings = group_rule_hits(duckdb_connection(), path)
    plants = {p.kind: p for p in generator.plants}

    for kind in ("zscaler_threat", "high_risk_allowed", "executable_download"):
        assert any(f.kind == kind and overlaps(f, plants[kind]) for f in findings), kind
    # Benign look-alikes stay low: Windows updates 0.2, the developer's curl 0.6.
    assert all(f.score <= 0.6 for f in findings if f.username not in {"jdoe", "amiller", "kchen"})
