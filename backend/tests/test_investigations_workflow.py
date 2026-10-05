import pytest

from app.models import User
from app.security import hash_password
from tests.test_dashboard_api import upload_and_analyze, week

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def csv_week():
    return week()


@pytest.fixture
def case(client, analyst, storage, csv_week, db_session):
    """Logged in as 'analyst' (+ a second analyst 'bwong' exists); returns the top case's detail."""
    db_session.add(User(username="bwong", password_hash=hash_password("another-pass-2")))
    db_session.commit()
    client.post("/api/login", auth=GOOD)
    upload_and_analyze(client, storage, csv_week, "w.csv")
    top = client.get("/api/investigations").json()[0]
    return client.get(f"/api/investigations/{top['id']}").json()


def patch(client, case, **change):
    return client.patch(f"/api/investigations/{case['id']}",
                        json={"expected_updated_at": case["updated_at"], **change})


def test_new_case_is_open_unowned_with_no_notes(case):
    assert (case["status"], case["owner"], case["verdict"], case["notes"]) == ("open", None, None, [])
    assert case["analysts"] == ["analyst", "bwong"]


def test_investigating_assigns_me_when_nobody_owns_it(client, case):
    d = patch(client, case, status="investigating").json()

    assert (d["status"], d["owner"]) == ("investigating", "analyst")
    assert d["updated_at"] > case["updated_at"]
    listed = client.get("/api/investigations", params={"status": "investigating"}).json()
    assert [i["id"] for i in listed] == [case["id"]] and listed[0]["owner"] == "analyst"


def test_investigating_keeps_an_existing_owner(client, case):
    d = patch(client, case, owner="bwong", status="investigating").json()
    assert d["owner"] == "bwong"


def test_resolve_needs_a_verdict(client, case):
    refused = patch(client, case, status="resolved")
    assert refused.status_code == 422 and "verdict" in refused.json()["detail"]
    assert client.get(f"/api/investigations/{case['id']}").json()["status"] == "open"  # nothing changed

    d = patch(client, case, status="resolved", verdict="false_positive").json()
    assert (d["status"], d["verdict"]) == ("resolved", "false_positive")

    reopened = patch(client, d, status="open").json()  # reopening keeps the old verdict visible
    assert (reopened["status"], reopened["verdict"]) == ("open", "false_positive")


def test_a_stale_update_is_refused_not_overwritten(client, case):
    first = patch(client, case, owner="bwong")
    assert first.status_code == 200

    stale = patch(client, case, owner="analyst")  # still sends the old updated_at

    assert stale.status_code == 409
    assert client.get(f"/api/investigations/{case['id']}").json()["owner"] == "bwong"


def test_owner_cant_be_cleared_while_investigating(client, case):
    d = patch(client, case, status="investigating").json()

    refused = patch(client, d, owner=None)

    assert refused.status_code == 422 and "needs an owner" in refused.json()["detail"]
    assert patch(client, d, status="open", owner=None).json()["owner"] is None  # open + unassign together: fine


def test_owner_can_be_cleared_and_must_exist(client, case):
    d = patch(client, case, owner="bwong").json()
    assert patch(client, d, owner=None).json()["owner"] is None
    d = client.get(f"/api/investigations/{case['id']}").json()
    assert patch(client, d, owner="nobody").status_code == 422
    assert patch(client, d, status="closed").status_code == 422
    assert patch(client, d, verdict="maybe").status_code == 422


def test_notes_are_appended_in_order_as_plain_text(client, case):
    url = f"/api/investigations/{case['id']}/notes"
    client.post(url, json={"text": "  Called the user; they deny the upload.  "})
    d = client.post(url, json={"text": "<b>Escalated</b> to IR"}).json()

    assert [(n["author"], n["text"]) for n in d["notes"]] == [
        ("analyst", "Called the user; they deny the upload."),  # trimmed
        ("analyst", "<b>Escalated</b> to IR"),  # stored as typed; the UI renders it as text
    ]
    assert d["updated_at"] > case["updated_at"]
    assert client.post(url, json={"text": "   "}).status_code == 422
    assert client.post(url, json={"text": "x" * 5001}).status_code == 422


def test_unknown_case_and_login_are_checked(client, case):
    assert client.patch("/api/investigations/1", json={"expected_updated_at": case["updated_at"]}).status_code == 404
    assert client.post("/api/investigations/1/notes", json={"text": "x"}).status_code == 404
    client.post("/api/logout")
    assert patch(client, case, status="investigating").status_code == 401
    assert client.post(f"/api/investigations/{case['id']}/notes", json={"text": "x"}).status_code == 401
