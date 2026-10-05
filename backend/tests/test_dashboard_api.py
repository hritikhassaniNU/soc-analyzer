import io

import pytest

from sqlalchemy import update

from app.db import SessionLocal
from app.generator import Generator, GeneratorConfig
from app.models import Upload
from app.pipeline.analyze import analyze

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


def week(**config) -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9, **config)).write(out)
    return out.getvalue().encode()


@pytest.fixture(scope="module")
def weeks():
    return {"csv": week(), "json": week(log_format="json"), "clean": week(clean=True)}


def upload_and_analyze(client, storage, content: bytes, name: str) -> int:
    upload_id = client.post("/api/uploads", files={"file": (name, content, "text/plain")}).json()["id"]
    analyze(upload_id, storage)
    with SessionLocal() as db:  # what the worker does after analyze(): only 'done' uploads count
        db.execute(update(Upload).where(Upload.id == upload_id).values(status="done", progress=100))
        db.commit()
    return upload_id


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def test_an_empty_company_is_all_zeros(logged_in):
    body = logged_in.get("/api/dashboard").json()

    assert body["kpis"] == {"incidents": 0, "critical": 0, "affected_users": 0, "flagged_events": 0,
                            "blocked_events": 0, "events": 0, "datasets": 0, "uploads": 0,
                            "findings": 0, "findings_high": 0, "open_cases": 0, "unassigned_urgent": 0,
                            "high_risk_users": 0, "high_risk_ips": 0, "events_last_period": 0,
                            "events_previous_period": None, "period_days": 7}
    assert body["datasets"] == []
    assert body["severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert body["users_at_risk"] == body["top_incidents"] == body["timeline"] == body["top_entities"] == []


def test_copies_of_the_same_logs_are_counted_once(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    once = logged_in.get("/api/dashboard").json()

    # The same week again: once more as CSV, once as JSON lines (a different file fingerprint).
    upload_and_analyze(logged_in, storage, weeks["csv"], "w-again.csv")
    upload_and_analyze(logged_in, storage, weeks["json"], "w.jsonl")
    three = logged_in.get("/api/dashboard").json()

    assert (once["kpis"]["uploads"], three["kpis"]["uploads"]) == (1, 3)
    assert {**three["kpis"], "uploads": 1} == once["kpis"]  # datasets 1, same incidents and events
    for key in ("severity", "categories", "timeline", "top_entities"):
        assert three[key] == once[key], key

    def ranking(body):  # the representing upload may differ (newest copy); the ranking may not
        return [{k: v for k, v in u.items() if k != "upload_id"} for u in body["users_at_risk"]]

    assert ranking(three) == ranking(once)


def test_users_at_risk_and_breakdowns(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    upload_and_analyze(logged_in, storage, weeks["clean"], "clean.csv")  # a different dataset: adds up

    body = logged_in.get("/api/dashboard").json()

    top = body["users_at_risk"][0]
    assert (top["username"], top["priority"], top["priority_score"]) == ("jdoe", "critical", 1.0)
    assert top["incidents"] >= 2 and top["findings"] >= top["incidents"]
    # Both of jdoe's stories, not just the tie-break winner: Tuesday's C2 and Sunday's upload.
    assert set(top["reason"].lower().split(", ")) == {"command & control", "large upload"}
    assert len(body["users_at_risk"]) <= 4
    scores = [u["priority_score"] for u in body["users_at_risk"]]
    assert scores == sorted(scores, reverse=True)
    assert body["kpis"]["datasets"] == 2 and body["kpis"]["critical"] == body["severity"]["critical"] == 2
    assert sum(body["severity"].values()) == body["kpis"]["incidents"]
    medium_plus = body["severity"]["critical"] + body["severity"]["high"] + body["severity"]["medium"]
    assert sum(c["incidents"] for c in body["categories"]) == medium_plus
    assert body["top_incidents"][0]["username"] == "jdoe" and len(body["top_incidents"]) == 5
    assert all(i["case_id"] >= 1001 for i in body["top_incidents"])  # each opens its investigation
    entities = body["top_entities"]
    assert len(entities) == 5 and all(sum(e["type"] == t for e in entities) <= 2 for t in ("user", "ip", "domain"))
    assert [e["risk"] for e in entities] == sorted((e["risk"] for e in entities), reverse=True)
    assert {"type": "user", "name": "jdoe", "risk": 100} == {k: entities[0][k] for k in ("type", "name", "risk")}
    assert (entities[1]["type"], entities[1]["detail"]) == ("ip", "used by jdoe")  # tie: user before IP
    jdoe_ip = next(e for e in entities if e["type"] == "ip")
    assert jdoe_ip["risk"] == 100 and jdoe_ip["detail"] == "used by jdoe"
    assert {"type", "name", "risk", "alerts", "detail"} == set(entities[0])
    days = [d["day"] for d in body["timeline"]]
    assert days == sorted(days) and len(days) == len(set(days))  # one row per day, gap-filled


def test_requires_login(client):
    assert client.get("/api/dashboard").status_code == 401



def test_domains_say_why_they_are_suspicious(logged_in, storage, weeks, monkeypatch):
    from app.api import dashboard

    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    monkeypatch.setattr(dashboard, "PER_TYPE", 50)  # see every entity, not just the top 5
    monkeypatch.setattr(dashboard, "TOP_ENTITIES", 50)

    entities = logged_in.get("/api/dashboard").json()["top_entities"]

    reasons = {e["name"]: e["detail"] for e in entities if e["type"] == "domain"}
    assert reasons["cdn-update-check.xyz"] == "beacon destination"
    assert reasons["mega.nz"] == "large-upload destination"
    assert reasons["free-invoice-download.ru"] == "known threat"
    assert reasons["files.anonshare.io"] == "executable download source"


def test_users_at_risk_leave_the_card_once_their_cases_are_resolved(logged_in, storage, weeks):
    from sqlalchemy import text

    from app.db import engine

    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    before = logged_in.get("/api/dashboard").json()
    assert before["users_at_risk"][0]["username"] == "jdoe"

    with engine.begin() as conn:
        conn.execute(text("UPDATE cases SET status = 'resolved', verdict = 'true_positive' WHERE username = 'jdoe'"))
    board = logged_in.get("/api/dashboard").json()

    assert "jdoe" not in [u["username"] for u in board["users_at_risk"]]  # same rule as the Users page
    assert next(u for u in logged_in.get("/api/users").json() if u["username"] == "jdoe")["risk"] is None
    assert board["severity"] == before["severity"]  # the company picture (history) is unchanged


def test_overview_tiles_match_the_lists_they_open(logged_in, storage, weeks):
    from sqlalchemy import text

    from app.db import engine

    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    k = logged_in.get("/api/dashboard").json()["kpis"]

    # Anomalies = the findings behind the Detection Rules hit counts.
    rules = logged_in.get("/api/rules").json()["detectors"]
    assert k["findings"] == sum(d["hits"] for d in rules) and 0 < k["findings_high"] <= k["findings"]
    # Open investigations = the "unresolved" queue; critical = the severity filter.
    assert k["open_cases"] == len(logged_in.get("/api/investigations", params={"status": "unresolved"}).json())
    assert k["critical"] == len(logged_in.get("/api/investigations", params={"severity": "critical"}).json())
    # High-risk users = users whose worst unresolved case is critical/high.
    users = logged_in.get("/api/users").json()
    assert k["high_risk_users"] == sum(u["priority"] in ("critical", "high") for u in users) >= 1
    assert k["high_risk_ips"] >= 1 and k["unassigned_urgent"] >= 1
    # One generated week: no previous period to compare with.
    assert k["period_days"] == 7 and k["events_previous_period"] is None and k["events_last_period"] == k["events"]

    with engine.begin() as conn:  # resolving and assigning change the tiles
        conn.execute(text("UPDATE cases SET status = 'resolved', verdict = 'benign' WHERE username = 'jdoe'"))
    after = logged_in.get("/api/dashboard").json()["kpis"]
    assert after["open_cases"] < k["open_cases"] and after["high_risk_users"] == k["high_risk_users"] - 1


def test_events_tile_breakdown_adds_up(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    upload_and_analyze(logged_in, storage, weeks["clean"], "clean.csv")

    board = logged_in.get("/api/dashboard").json()

    assert len(board["datasets"]) == board["kpis"]["datasets"] == 2
    assert sum(d["events"] for d in board["datasets"]) == board["kpis"]["events"]
    assert sum(d["flagged"] for d in board["datasets"]) == board["kpis"]["flagged_events"]
    assert sum(d["blocked"] for d in board["datasets"]) == board["kpis"]["blocked_events"]
