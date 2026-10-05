import pytest

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


def test_full_flow_login_me_logout_me(client, analyst):
    client.post("/api/login", auth=GOOD)
    assert client.get("/api/me").status_code == 200

    assert client.post("/api/logout").status_code == 204

    assert client.get("/api/me").status_code == 401


def test_logout_revokes_the_session_on_the_server(client, analyst):
    """Even a copy of the old token stops working: the session row is gone, not just the cookie."""
    stolen_copy = client.post("/api/login", auth=GOOD).cookies["session"]
    client.post("/api/logout")

    client.cookies.set("session", stolen_copy)  # attacker replays the copied cookie

    assert client.get("/api/me").status_code == 401


def test_logout_without_cookie_is_still_204(client):
    assert client.post("/api/logout").status_code == 204


def test_logout_clears_the_cookie(client, analyst):
    client.post("/api/login", auth=GOOD)

    response = client.post("/api/logout")

    set_cookie = response.headers["set-cookie"].lower()
    assert set_cookie.startswith("session=")
    assert "max-age=0" in set_cookie
