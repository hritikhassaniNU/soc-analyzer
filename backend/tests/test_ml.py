from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.detection.correlate import IncidentDraft
from app.detection.findings import Finding
from app.detection.ml import detect_outliers
from app.detection.run import _attach_ml
from app.pipeline.aggregates import duckdb_connection
from tests.test_aggregates import write_parquet
from tests.test_behavior import BASE, MONDAY

ODD_HOUR = MONDAY + timedelta(days=2, hours=11)


def office(users=8):
    """Mon-Fri 09-17, every user: 4 ordinary GETs per hour to two common sites."""
    return [replace(BASE, username=f"user{u}", host=("example.com", "news.example")[k % 2],
                    ts=MONDAY + timedelta(days=d, hours=h, minutes=10 * k))
            for u in range(users) for d in range(5) for h in range(9, 18) for k in range(4)]


def outliers(tmp_path, events):
    events = [replace(e, line_no=i) for i, e in enumerate(events, start=1)]
    path = tmp_path / "ml.parquet"
    write_parquet(path, events)
    return detect_outliers(duckdb_connection(), path)


def odd_combination():
    """One hour where user0 is unusual on SEVERAL measures at once: blocked, risky, POST-heavy."""
    return [replace(BASE, username="user0", ts=ODD_HOUR + timedelta(minutes=50 + i), host="odd.example",
                    action="Blocked", method="POST", risk_score=90) for i in range(4)]


def test_an_unusual_combination_is_reported_with_its_reasons(tmp_path):
    [finding] = outliers(tmp_path, office() + odd_combination())

    assert (finding.kind, finding.username) == ("behavioral_outlier", "user0")
    assert finding.window_start.date() == ODD_HOUR.date()
    assert finding.reason.startswith("Unusual combination for this user in this hour: ")
    assert "blocked requests (usually 0%)" in finding.reason
    assert len(finding.details["features"]) >= 2 and finding.details["isolation_score"] >= 0.6


def test_one_extreme_measure_alone_is_left_to_the_statistical_detectors(tmp_path):
    # Many more requests than usual, everything else ordinary (tiny requests, so the hour's total
    # bytes stay at the usual ~4 KB / 20 KB): a single-measure extreme, the burst detector's job.
    busy = [replace(BASE, username="user0", host="example.com", ts=ODD_HOUR + timedelta(seconds=20 * i),
                    bytes_out=27, bytes_in=133) for i in range(150)]

    assert outliers(tmp_path, office() + busy) == []


def test_too_few_user_hours_means_no_ml(tmp_path):
    assert outliers(tmp_path, office(users=1)[:40] + odd_combination()) == []


def test_results_are_reproducible(tmp_path):
    events = office() + odd_combination()

    assert outliers(tmp_path, events) == outliers(tmp_path, events)  # fixed random_state


# ---- ML is corroborating evidence only ----

T = datetime(2026, 9, 23, 10, tzinfo=UTC)


def finding(kind, username="amiller", at=T, minutes=1, score=0.9) -> Finding:
    return Finding(username=username, window_start=at, window_end=at + timedelta(minutes=minutes),
                   kind=kind, score=score, reason="r", count=1)


def incident(username="amiller") -> IncidentDraft:
    return IncidentDraft(username=username, start=T, end=T + timedelta(minutes=1), title="Known threat",
                         priority_score=0.9, priority="high", categories=["known_threat"], members=[0])


def test_ml_joins_an_overlapping_incident_without_changing_it():
    detection = _attach_ml([("rule", finding("zscaler_threat"))], [incident()],
                           [finding("behavioral_outlier", minutes=59, score=0.77)])

    [joined] = detection.incidents
    assert [source for source, _ in detection.findings] == ["rule", "ml"]
    assert joined.members == [0, 1]
    assert (joined.priority_score, joined.priority, joined.title) == (0.9, "high", "Known threat")
    assert joined.categories == ["known_threat", "behavioral_outlier"]


@pytest.mark.parametrize("outlier", [
    finding("behavioral_outlier", username="someone_else"),         # no incident for this user
    finding("behavioral_outlier", at=T + timedelta(hours=3)),        # same user, another time
])
def test_ml_without_an_incident_is_dropped(outlier):
    detection = _attach_ml([("rule", finding("zscaler_threat"))], [incident()], [outlier])

    assert [source for source, _ in detection.findings] == ["rule"]
    assert detection.incidents[0].members == [0]
