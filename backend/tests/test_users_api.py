import pytest
from sqlalchemy import text

from app.db import engine
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


def resolve(case_ids, verdict="false_positive"):
    with engine.begin() as conn:
        conn.execute(text("UPDATE cases SET status = 'resolved', verdict = :v WHERE id = ANY(:ids)"),
                     {"v": verdict, "ids": list(case_ids)})


def test_list_is_riskiest_first_and_includes_quiet_users(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")

    users = logged_in.get("/api/users").json()

    assert users[0]["username"] == "jdoe" and users[0]["risk"] == 100 and users[0]["priority"] == "critical"
    risks = [u["risk"] for u in users if u["risk"] is not None]
    assert risks == sorted(risks, reverse=True)
    quiet = [u for u in users if u["cases"] == 0]
    assert quiet and all(u["risk"] is None and u["open_cases"] == 0 for u in quiet)  # everyone seen is listed
    assert [u["username"] for u in logged_in.get("/api/users", params={"q": "JDO"}).json()] == ["jdoe"]
    jdoe = users[0]
    assert jdoe["reason"] and "command & control" in jdoe["reason"].lower()  # why, strongest first
    assert all(u["reason"] is None for u in quiet)


def test_profile_has_history_cases_and_baseline(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")

    p = logged_in.get("/api/users/JDoe").json()  # case-insensitive, like the parser

    assert p["username"] == "jdoe" and p["datasets"] == 1 and p["events"] > 0
    assert p["first_seen"] <= p["last_seen"]
    assert p["ips"] and p["devices"] == []  # this generated week gives jdoe no Client Connector device
    assert p["risk"]["score"] == 100 and p["risk"]["case_id"] in [c["id"] for c in p["cases"]]
    assert p["verdicts"] == {"true_positive": 0, "false_positive": 0, "benign": 0, "unresolved": len(p["cases"])}
    starts = [c["start_ts"] for c in p["cases"]]
    assert starts == sorted(starts, reverse=True)
    assert sum(d["incidents"] for d in p["timeline"]) == len(p["cases"])
    b = p["baseline"]
    assert sum(b["hours_utc"]) == p["events"] and len(b["hours_utc"]) == 24
    assert b["active_days"] >= 5 and b["max_daily_bytes_out"] >= b["median_daily_bytes_out"] > 0
    assert 0 <= b["blocked_share"] <= 1 and b["top_domains"] and b["top_categories"]
    counts = [d["count"] for d in b["top_domains"]]
    assert counts == sorted(counts, reverse=True) and len(counts) <= 5


def test_a_reuploaded_week_is_counted_once(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    before = logged_in.get("/api/users/jdoe").json()

    upload_and_analyze(logged_in, storage, weeks["json"], "w.jsonl")  # same events, another format
    after = logged_in.get("/api/users/jdoe").json()

    assert (after["datasets"], after["events"], len(after["cases"])) == (1, before["events"], len(before["cases"]))


def test_resolved_cases_stop_counting_toward_risk(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    p = logged_in.get("/api/users/jdoe").json()
    worst = p["risk"]["case_id"]

    resolve([worst], "true_positive")
    after = logged_in.get("/api/users/jdoe").json()

    assert after["risk"]["case_id"] != worst
    assert after["verdicts"]["true_positive"] == 1 and after["verdicts"]["unresolved"] == len(p["cases"]) - 1

    resolve([c["id"] for c in p["cases"]])
    done = logged_in.get("/api/users/jdoe").json()
    assert done["risk"] == {"score": None, "priority": None, "case_id": None,
                            "explanation": f"All {len(p['cases'])} cases are resolved, so none counts toward current risk."}
    assert next(u for u in logged_in.get("/api/users").json() if u["username"] == "jdoe")["risk"] is None


def test_devices_and_unknown_users(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")

    amiller = logged_in.get("/api/users/amiller").json()

    assert [d["name"] for d in amiller["devices"]] == ["LT-AMILLER-01"] and amiller["devices"][0]["os"] == "macOS"
    assert logged_in.get("/api/users/nobody").status_code == 404


def test_login_required(client):
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/users/jdoe").status_code == 401


# ---- AI review of one user ----


def use_fake_claude(monkeypatch, answer):
    import functools

    from app.llm import client as llm_client
    from tests.test_llm_client import FakeClient

    fake = FakeClient(answer)
    monkeypatch.setattr("app.api.users.summarize", functools.partial(llm_client.summarize, client=fake))
    return fake


def test_user_review_template_then_ai_with_stand_ins_only(logged_in, storage, weeks, monkeypatch):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    assert logged_in.get("/api/users/jdoe/review").json() is None

    template = logged_in.post("/api/users/jdoe/review").json()  # no key in tests: the template
    assert template["source"] == "template" and template["stale"] is False and template["created_by"] == "analyst"

    with engine.begin() as conn:  # make the next POST a real new review (not a double click)
        conn.execute(text("UPDATE user_reviews SET created_at = created_at - interval '2 minutes'"))
    fake = use_fake_claude(monkeypatch, {"summary": "user_1 shows a compromise pattern.", "incidents": []})
    review = logged_in.post("/api/users/JDOE/review").json()

    assert (review["source"], review["summary"]) == ("ai", "jdoe shows a compromise pattern.")
    content = fake.calls[0]["messages"][0]["content"]
    assert "one user's activity across all analyzed logs" in content
    ips = [ip["name"] for ip in logged_in.get("/api/users/jdoe").json()["ips"]]
    assert ips and "jdoe" not in content and not any(ip in content for ip in ips)  # no real name, no real IP
    assert '"cases_unresolved"' in content and '"datasets": 1' in content
    assert logged_in.get("/api/users/jdoe/review").json()["id"] == review["id"]


def test_user_review_double_click_and_staleness(logged_in, storage, weeks, monkeypatch):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")
    fake = use_fake_claude(monkeypatch, {"summary": "Fine.", "incidents": []})

    first = logged_in.post("/api/users/jdoe/review").json()
    second = logged_in.post("/api/users/jdoe/review").json()
    assert first["id"] == second["id"] and len(fake.calls) == 1

    with engine.begin() as conn:  # jdoe's picture changed (simulated: one of jdoe's scores moved)
        conn.execute(text("UPDATE incidents SET priority_score = priority_score * 0.5 "
                          "WHERE id = (SELECT min(id) FROM incidents WHERE username = 'jdoe')"))
    assert logged_in.get("/api/users/jdoe/review").json()["stale"] is True
    assert logged_in.post("/api/users/nobody/review").status_code == 404


def test_profile_activity_chart_is_hourly_gap_filled_and_adds_up(logged_in, storage, weeks):
    upload_and_analyze(logged_in, storage, weeks["csv"], "w.csv")

    p = logged_in.get("/api/users/jdoe").json()
    a = p["activity"]

    assert a["bucket_hours"] == 1  # one generated week
    times = [pt["ts"] for pt in a["points"]]
    assert times == sorted(times) and len(times) == len(set(times))
    assert sum(pt["events"] for pt in a["points"]) == p["events"]  # every event in exactly one bucket
    assert any(pt["events"] == 0 for pt in a["points"])  # quiet hours are zeros, not gaps
    assert all(pt["blocked"] <= pt["events"] and pt["flagged"] <= pt["events"] for pt in a["points"])
    assert sum(pt["flagged"] for pt in a["points"]) > 0
    assert sorted(w["case_id"] for w in a["incidents"]) == sorted(c["id"] for c in p["cases"])
