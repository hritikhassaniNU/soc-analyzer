import base64

import pytest

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


def test_correct_credentials_set_session_cookie(client, analyst):
    response = client.post("/api/login", auth=GOOD)

    assert response.status_code == 200
    assert response.json() == {"username": "analyst"}
    set_cookie = response.headers["set-cookie"].lower()
    assert set_cookie.startswith("session=")
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


def test_wrong_password_is_401_without_browser_popup_header(client, analyst):
    response = client.post("/api/login", auth=("analyst", "wrong-password"))

    assert response.status_code == 401
    assert "www-authenticate" not in response.headers  # would trigger the native popup
    assert "set-cookie" not in response.headers


def test_unknown_user_gets_identical_error(client, analyst):
    wrong_password = client.post("/api/login", auth=("analyst", "wrong-password"))
    unknown_user = client.post("/api/login", auth=("nobody", "whatever-123"))

    assert unknown_user.status_code == 401
    assert unknown_user.json() == wrong_password.json()  # no hint which usernames exist


def test_missing_credentials_is_401(client, analyst):
    response = client.post("/api/login")

    assert response.status_code == 401


def test_username_is_case_insensitive(client, analyst):
    response = client.post("/api/login", auth=("ANALYST", "correct-horse-1"))

    assert response.status_code == 200
    assert response.json() == {"username": "analyst"}


def test_each_login_issues_a_new_token(client, analyst):
    first = client.post("/api/login", auth=GOOD).cookies["session"]
    second = client.post("/api/login", auth=GOOD).cookies["session"]

    assert first != second


# ---- malformed / non-ASCII Basic headers (regressions found while building the login page) ----


def _basic(raw: bytes) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Basic %%%not-base64"},   # invalid base64
        _basic(b"analyst-without-colon"),           # no ':' separator
        _basic(b"analyst:\xff\xfe-not-utf8"),        # not valid UTF-8
        {"Authorization": "Bearer something"},      # wrong scheme
    ],
)
def test_malformed_header_is_our_401_without_popup_header(client, analyst, headers):
    response = client.post("/api/login", headers=headers)

    assert response.status_code == 401
    assert "www-authenticate" not in response.headers
    assert response.json() == {"detail": "Invalid username or password"}


def test_utf8_password_can_log_in(client, db_session):
    from app.models import User
    from app.security import hash_password

    db_session.add(User(username="zoe", password_hash=hash_password("café-pass-123")))
    db_session.commit()

    response = client.post("/api/login", headers=_basic("zoe:café-pass-123".encode("utf-8")))

    assert response.status_code == 200


def test_password_may_contain_colons(client, db_session):
    from app.models import User
    from app.security import hash_password

    db_session.add(User(username="max", password_hash=hash_password("a:b:c:d-123")))
    db_session.commit()

    response = client.post("/api/login", auth=("max", "a:b:c:d-123"))

    assert response.status_code == 200
