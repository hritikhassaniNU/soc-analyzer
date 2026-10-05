import pytest
from sqlalchemy import text

from app.db import engine
from app.detection import beaconing, behavior, catalog, rules
from app.detection.correlate import CATEGORY_OF_KIND
from app.models import Upload
from tests.test_dashboard_api import upload_and_analyze, week

GOOD = ("analyst", "correct-horse-1")


# ---- the catalog (no database) ----


def test_every_finding_kind_has_one_catalog_entry():
    kinds = [d.kind for d in catalog.DETECTORS]
    assert sorted(kinds) == sorted(CATEGORY_OF_KIND) and len(kinds) == len(set(kinds)) == 11
    assert {r.__name__ for r in rules.RULES} == {d.kind for d in catalog.DETECTORS if d.layer == "rule"}


def test_thresholds_come_from_the_detector_code():
    text_of = {d.kind: " ".join(d.logic) for d in catalog.DETECTORS}
    assert f"≥ {rules.HIGH_RISK_THRESHOLD}" in text_of["high_risk_allowed"]
    assert f"≥ {behavior.UPLOAD_MIN_BYTES // 1_000_000} MB" in text_of["large_upload"]
    assert f"≥ {beaconing.MIN_REQUESTS} requests" in text_of["beaconing"]


def test_mitre_links_and_honest_tags():
    techniques = {t.id: t for d in catalog.DETECTORS for t in d.techniques}
    assert techniques["T1071.001"].url == "https://attack.mitre.org/techniques/T1071/001/"
    assert techniques["T1189"].approximate and techniques["T1059"].approximate  # loose fits are labeled
    assert not techniques["T1105"].approximate and techniques["T1078"].supports
    assert catalog.BY_KIND["zscaler_threat"].techniques == []  # no single technique: no guess


# ---- the API and the pipeline (database) ----


@pytest.fixture(scope="module")
def csv_week():
    return week()


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


@pytest.mark.integration
def test_catalog_shows_hits_scoring_and_coverage(logged_in, storage, csv_week):
    upload_and_analyze(logged_in, storage, csv_week, "w.csv")

    body = logged_in.get("/api/rules").json()

    detectors = {d["kind"]: d for d in body["detectors"]}
    assert all(d["enabled"] and d["changed_by"] is None for d in detectors.values())
    assert detectors["beaconing"]["hits"] >= 1 and detectors["beaconing"]["cases"] >= 1
    assert detectors["beaconing"]["last_seen"] is not None
    assert detectors["large_upload"]["weight"] == 1.0 and detectors["scripted_client"]["weight"] == 0.6
    assert body["scoring"]["corroboration_min"] == 0.4 and body["scoring"]["chain_hours"] == 24
    assert [c["priority"] for c in body["scoring"]["cutoffs"]] == ["critical", "high", "medium"]
    assert len(body["tactics"]) == 14 and body["blind_spots"]

    # "View cases": the investigations queue filtered to cases with a beaconing finding.
    cases = logged_in.get("/api/investigations", params={"detector": "beaconing"}).json()
    assert len(cases) == detectors["beaconing"]["cases"]


@pytest.mark.integration
def test_switching_off_applies_to_new_scans_only_and_is_recorded(logged_in, storage, csv_week, db_session):
    first = upload_and_analyze(logged_in, storage, csv_week, "before.csv")

    off = logged_in.put("/api/rules/beaconing", json={"enabled": False}).json()
    logged_in.put("/api/rules/scripted_client", json={"enabled": False})
    logged_in.put("/api/rules/behavioral_outlier", json={"enabled": False})
    second = upload_and_analyze(logged_in, storage, csv_week, "after.csv")

    assert (off["enabled"], off["changed_by"]) == (False, "analyst") and off["changed_at"]
    with engine.connect() as conn:
        def kinds(upload_id):
            return set(conn.execute(text("SELECT DISTINCT kind FROM anomalies WHERE upload_id = :u"),
                                    {"u": upload_id}).scalars())
        tagged = conn.execute(text("SELECT count(*) FROM events WHERE upload_id = :u AND 'scripted_client' = ANY(rule_hits)"),
                              {"u": second}).scalar()
        before, after = kinds(first), kinds(second)

    assert {"beaconing", "scripted_client"} <= before  # the earlier scan keeps its results
    assert not after & {"beaconing", "scripted_client", "behavioral_outlier"}
    assert tagged == 0  # switched-off rules don't tag event lines either
    db_session.expire_all()
    assert db_session.get(Upload, second).disabled_detectors == ["beaconing", "behavioral_outlier", "scripted_client"]
    assert db_session.get(Upload, first).disabled_detectors == []
    detail = logged_in.get(f"/api/uploads/{second}").json()
    assert detail["disabled_detectors"] == ["beaconing", "behavioral_outlier", "scripted_client"]

    back_on = logged_in.put("/api/rules/beaconing", json={"enabled": True}).json()
    assert back_on["enabled"] and back_on["changed_by"] == "analyst"


@pytest.mark.integration
def test_unknown_detector_and_login(logged_in, client):
    assert logged_in.put("/api/rules/nope", json={"enabled": False}).status_code == 404
    assert logged_in.put("/api/rules/beaconing", json={"enabled": "maybe"}).status_code == 422
    client.post("/api/logout")
    assert client.get("/api/rules").status_code == 401
    assert client.put("/api/rules/beaconing", json={"enabled": False}).status_code == 401


@pytest.mark.integration
def test_rescanning_a_week_replaces_its_cases_and_keeps_analyst_work(logged_in, storage, csv_week):
    upload_and_analyze(logged_in, storage, csv_week, "w.csv")
    beacon = logged_in.get("/api/investigations", params={"detector": "beaconing"}).json()
    assert beacon
    logged_in.post(f"/api/investigations/{beacon[0]['id']}/notes", json={"text": "checked the beacon host"})
    total = len(logged_in.get("/api/investigations").json())

    logged_in.put("/api/rules/beaconing", json={"enabled": False})
    upload_and_analyze(logged_in, storage, csv_week, "again.csv")  # same week, newest scan wins
    without = logged_in.get("/api/investigations").json()

    assert not logged_in.get("/api/investigations", params={"detector": "beaconing"}).json()
    assert beacon[0]["id"] not in [i["id"] for i in without]  # its incident is gone from the newest scan
    assert len(without) <= total  # replaced, not added next to the old ones

    logged_in.put("/api/rules/beaconing", json={"enabled": True})
    upload_and_analyze(logged_in, storage, csv_week, "third.csv")
    back = logged_in.get(f"/api/investigations/{beacon[0]['id']}").json()  # same identity -> same case

    assert back["number"] == beacon[0]["number"] and back["notes"][0]["text"] == "checked the beacon host"
    assert len(logged_in.get("/api/investigations").json()) == total
