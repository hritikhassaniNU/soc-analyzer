import pytest
from sqlalchemy import func, select, text

from app.db import engine
from app.models import Case
from tests.test_dashboard_api import upload_and_analyze, week

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def weeks():
    return {"csv": week(), "json": week(log_format="json")}


@pytest.fixture
def logged_in(client, analyst):
    client.post("/api/login", auth=GOOD)
    return client


def test_each_unique_incident_is_one_case_with_a_stable_number(logged_in, storage, weeks, db_session):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    first = logged_in.get("/api/investigations").json()

    upload_and_analyze(logged_in, storage, weeks["json"], "w.jsonl")  # the same week again
    again = logged_in.get("/api/investigations").json()

    assert [i["number"] for i in again] == [i["number"] for i in first]  # numbers kept, no new cases
    assert db_session.scalar(select(func.count()).select_from(Case)) == len(first)
    assert all(i["number"] == f"INC-{i['id']}" and i["id"] >= 1001 for i in first)


def test_the_queue_is_worst_first_with_readable_names_and_entities(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")

    items = logged_in.get("/api/investigations").json()

    risks = [i["risk"] for i in items]
    assert risks == sorted(risks, reverse=True)
    top = items[0]
    assert (top["priority"], top["risk"], top["status"]) == ("critical", 100, "open")
    assert top["name"] in ("Possible data exfiltration", "Possible command & control")
    assert top["entities"][0] == {"type": "user", "name": "jdoe"}
    assert {e["type"] for e in top["entities"]} == {"user", "ip", "domain"}
    assert top["signals"] == len(top["title"].split(", ")) and top["alerts"] >= top["signals"]


def test_filters_and_search(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    items = logged_in.get("/api/investigations").json()
    with engine.begin() as conn:
        conn.execute(text("UPDATE cases SET status = 'resolved' WHERE id = :id"), {"id": items[0]["id"]})

    critical = logged_in.get("/api/investigations", params={"severity": "critical"}).json()
    resolved = logged_in.get("/api/investigations", params={"status": "resolved"}).json()
    by_domain = logged_in.get("/api/investigations", params={"q": "CDN-UPDATE"}).json()
    by_number = logged_in.get("/api/investigations", params={"q": items[1]["number"].lower()}).json()

    assert critical and {i["priority"] for i in critical} == {"critical"}
    assert [i["id"] for i in resolved] == [items[0]["id"]]
    assert by_domain and all(i["entities"][0]["name"] == "jdoe" for i in by_domain)
    assert [i["id"] for i in by_number] == [items[1]["id"]]
    assert logged_in.get("/api/investigations", params={"status": "closed"}).status_code == 422


def test_case_detail_has_everything_the_tabs_need(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    beacon_case = next(i for i in logged_in.get("/api/investigations").json() if i["name"] == "Possible command & control"
                       and i["entities"][0]["name"] == "jdoe")

    d = logged_in.get(f"/api/investigations/{beacon_case['id']}").json()

    assert d["why_flagged"].startswith("jdoe") and d["narrative_source"] == "template"
    assert d["next_steps"] and 1 <= len(d["next_questions"]) <= 3
    # D135: no AI verdict without Claude; default searches built from the evidence.
    assert d["ai_assessment"] is None
    assert [s["id"] for s in d["searches"]] == ["flagged", "host1", "everyone_host1"]
    assert d["searches"][0]["username"] == "jdoe" and d["searches"][0]["anomalous"] is True
    assert d["searches"][2]["username"] is None and d["searches"][2]["host"] == d["searches"][1]["host"]
    parts = d["risk_breakdown"]
    counted = sum(p["counted"] for p in parts)
    assert parts[0]["counted"] and d["risk"] == min(100, parts[0]["weight"] + 10 * (counted - 1))  # D40, capped
    assert [p["weight"] for p in parts] == sorted((p["weight"] for p in parts), reverse=True)
    assert {s["label"] for s in d["detection_signals"]} == {p["label"] for p in parts}
    times = [e["window_start"] for e in d["evidence"]]
    assert times == sorted(times) and len(d["evidence"]) == d["alerts"]
    assert {"Beaconing", "Executable download"} <= {e["name"] for e in d["evidence"]}
    domains = {e["name"]: e["detail"] for e in d["related_entities"] if e["type"] == "domain"}
    assert domains["cdn-update-check.xyz"] == "beacon destination"
    assert all(e["type"] != "device" for e in d["related_entities"])  # jdoe has no Client Connector here


def test_device_is_an_entity_when_the_log_has_one(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    case = next(i for i in logged_in.get("/api/investigations").json() if i["entities"][0]["name"] != "jdoe")
    user = case["entities"][0]["name"]

    d = logged_in.get(f"/api/investigations/{case['id']}").json()

    chips = [e for e in case["entities"] if e["type"] == "device"]
    assert chips == [{"type": "device", "name": f"LT-{user.upper()}-01"}]
    [device] = [e for e in d["related_entities"] if e["type"] == "device"]
    assert device["name"] == chips[0]["name"]
    assert device["detail"].split(" · ")[0] in ("Windows", "macOS")
    assert f"used by {user}" in device["detail"] and device["detail"].endswith("events in window")
    assert [e["type"] for e in d["related_entities"]][:2] == ["user", "device"]


def test_unknown_case_is_404_and_login_is_required(logged_in, client):
    assert logged_in.get("/api/investigations/999999").status_code == 404
    logged_in.post("/api/logout")
    assert client.get("/api/investigations").status_code == 401


def test_signals_agree_with_the_header_and_approved_storage_is_named_calmly(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    items = logged_in.get("/api/investigations").json()

    for item in items:
        d = logged_in.get(f"/api/investigations/{item['id']}").json()
        assert sum(s["counted"] for s in d["detection_signals"]) == d["signals"]  # same number as the header
        user_card = d["related_entities"][0]["detail"]
        assert user_card.endswith(" 1 alert") if d["alerts"] == 1 else user_card.endswith(f" {d['alerts']} alerts")

    approved = [i for i in items if i["name"] == "Large upload to approved storage"]
    assert approved and all(i["priority"] == "low" for i in approved)
    assert all(e["name"] in ("acme.sharepoint.com", "drive.google.com")
               for i in approved for e in i["entities"] if e["type"] == "domain" and i["alerts"] == 1)
    assert any(i["name"] == "Possible data exfiltration" for i in items)  # jdoe's mega.nz keeps the alarm name


def test_resolved_cases_sort_after_unresolved(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    top = logged_in.get("/api/investigations").json()[0]
    with engine.begin() as conn:
        conn.execute(text("UPDATE cases SET status = 'resolved', verdict = 'benign' WHERE id = :id"), {"id": top["id"]})

    items = logged_in.get("/api/investigations").json()

    assert items[-1]["id"] == top["id"] and items[-1]["status"] == "resolved"
    open_risks = [i["risk"] for i in items if i["status"] != "resolved"]
    assert open_risks == sorted(open_risks, reverse=True)


def test_case_activity_strip_covers_the_window(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    beacon = next(i for i in logged_in.get("/api/investigations").json() if i["name"] == "Possible command & control")

    a = logged_in.get(f"/api/investigations/{beacon['id']}").json()["activity"]

    assert a["bucket_minutes"] in (15, 60) and a["points"]
    assert a["start"] < beacon["start_ts"] and a["end"] > beacon["end_ts"]  # padded on both sides
    times = [p["ts"] for p in a["points"]]
    assert times == sorted(times) and sum(p["flagged"] for p in a["points"]) > 0
    assert max(p["total"] for p in a["points"]) > 0
