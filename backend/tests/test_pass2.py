import io

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.db import engine
from app.generator import Generator, GeneratorConfig
from app.models import Anomaly, Incident, Upload, UploadSummary, events_partition_name
from app.pipeline.analyze import analyze

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def sample() -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9)).write(out)
    return out.getvalue().encode()


@pytest.fixture
def analyzed(client, analyst, sample, storage):
    client.post("/api/login", auth=GOOD)
    response = client.post("/api/uploads", files={"file": ("proxy.log", sample, "text/plain")})
    upload_id = response.json()["id"]
    analyze(upload_id, storage)
    return upload_id


def anomaly_rows(db, upload_id: int) -> list[Anomaly]:
    db.expire_all()
    return list(db.scalars(select(Anomaly).where(Anomaly.upload_id == upload_id).order_by(Anomaly.id)))


def summary_rows(db, upload_id: int) -> list[UploadSummary]:
    db.expire_all()
    return list(db.scalars(select(UploadSummary).where(UploadSummary.upload_id == upload_id)))


def test_summary_matches_the_stored_events(analyzed, db_session):
    (summary,) = summary_rows(db_session, analyzed)
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT count(*) FROM {events_partition_name(analyzed)}")).scalar()

    assert summary.stats["total_events"] == rows
    assert sum(p["total"] for p in summary.timeline["points"]) == rows
    assert summary.timeline["bucket"] == "1 hour"
    assert summary.top_n["users_by_bytes_out"][0]["name"] == "jdoe"
    assert summary.narrative["source"] == "template"  # written by the summary stage (no key in tests)
    assert db_session.get(Upload, analyzed).progress == 99  # pass 2 = 95, then the summary stage


def test_reanalysis_replaces_the_summary(analyzed, storage, db_session):
    (first,) = summary_rows(db_session, analyzed)

    analyze(analyzed, storage)

    rows = summary_rows(db_session, analyzed)
    assert len(rows) == 1  # upsert: no duplicate, no error
    assert rows[0].computed_at >= first.computed_at
    assert rows[0].stats == first.stats  # same input, same numbers


def test_deleting_the_upload_deletes_its_summary(analyzed, client, db_session):
    assert client.delete(f"/api/uploads/{analyzed}").status_code == 204

    assert db_session.scalar(select(func.count()).select_from(UploadSummary)) == 0


def test_behavioral_findings_are_stored_as_anomalies(analyzed, db_session):
    found = {(a.kind, a.username) for a in anomaly_rows(db_session, analyzed)}

    assert {("request_burst", "bsmith"), ("large_upload", "jdoe"), ("off_hours", "jdoe"),
            ("beaconing", "jdoe"), ("rare_domain", "rpatel"),
            ("zscaler_threat", "amiller"), ("executable_download", "jdoe")} <= found
    # (With 8 users jdoe also does a legit SharePoint upload: pick the exfiltration by destination.)
    jdoe_upload = next(a for a in anomaly_rows(db_session, analyzed)
                       if (a.kind, a.username) == ("large_upload", "jdoe") and a.details["top_host"] == "mega.nz")
    assert jdoe_upload.source == "stat"
    assert jdoe_upload.score == pytest.approx(0.99)  # REAL column: compare approximately
    assert jdoe_upload.reason.startswith("Sent ")
    assert jdoe_upload.window_start.tzinfo is not None  # timestamptz round trip


def test_reanalysis_replaces_all_findings_without_duplicates(analyzed, storage, db_session):
    def snapshot():
        return sorted((a.source, a.kind, a.username, a.window_start, a.score)
                      for a in anomaly_rows(db_session, analyzed))

    before = snapshot()

    analyze(analyzed, storage)

    assert snapshot() == before  # rule, stat and ml rows all replaced, none duplicated


def test_deleting_the_upload_deletes_its_anomalies(analyzed, client, db_session):
    assert anomaly_rows(db_session, analyzed)

    assert client.delete(f"/api/uploads/{analyzed}").status_code == 204

    assert db_session.scalar(select(func.count()).select_from(Anomaly)) == 0


def incident(upload_id: int, at, **overrides) -> Incident:
    values = {"upload_id": upload_id, "username": "jdoe", "start_ts": at, "end_ts": at, "title": "t",
              "priority_score": 0.5, "priority": "medium", "categories": ["timing"]}
    return Incident(**{**values, **overrides})


def test_deleting_an_incident_keeps_its_evidence(analyzed, db_session):
    anomaly = anomaly_rows(db_session, analyzed)[0]
    case = incident(analyzed, anomaly.window_start)
    db_session.add(case)
    db_session.flush()
    anomaly.incident_id = case.id
    db_session.commit()

    db_session.delete(case)
    db_session.commit()

    db_session.refresh(anomaly)
    assert anomaly.incident_id is None  # ON DELETE SET NULL: the anomaly itself survives


@pytest.mark.parametrize("bad", [{"priority": "urgent"}, {"priority_score": 1.5}])
def test_incident_constraints(analyzed, db_session, bad):
    at = anomaly_rows(db_session, analyzed)[0].window_start
    db_session.add(incident(analyzed, at, **bad))

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_the_upload_deletes_its_incidents(analyzed, client, db_session):
    db_session.add(incident(analyzed, anomaly_rows(db_session, analyzed)[0].window_start))
    db_session.commit()

    assert client.delete(f"/api/uploads/{analyzed}").status_code == 204

    assert db_session.scalar(select(func.count()).select_from(Incident)) == 0


def test_findings_are_correlated_into_incidents(analyzed, db_session):
    incidents = list(db_session.scalars(
        select(Incident).where(Incident.upload_id == analyzed).order_by(Incident.priority_score.desc())))
    anomalies = anomaly_rows(db_session, analyzed)

    assert incidents[0].username == "jdoe" and incidents[0].priority == "critical"
    assert all(a.incident_id is not None for a in anomalies)  # every finding is in an incident
    assert {a.incident_id for a in anomalies} == {i.id for i in incidents}  # and no empty incidents


def test_reanalysis_rebuilds_incidents_without_duplicates(analyzed, storage, db_session):
    def snapshot():
        db_session.expire_all()
        return sorted((i.username, i.start_ts, i.priority, i.title) for i in
                      db_session.scalars(select(Incident).where(Incident.upload_id == analyzed)))

    before = snapshot()

    analyze(analyzed, storage)

    assert snapshot() == before
