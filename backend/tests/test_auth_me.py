from datetime import UTC, datetime, timedelta

import pytest

from app.main import app
from app.sessions import create_session

pytestmark = pytest.mark.integration

# The only routes allowed without a session. Adding to this list should be a deliberate decision.
PUBLIC_ROUTES = {("GET", "/api/health"), ("POST", "/api/login"), ("POST", "/api/logout")}


def test_me_after_login_returns_username(client, analyst):
    client.post("/api/login", auth=("analyst", "correct-horse-1"))  # client keeps the cookie

    response = client.get("/api/me")

    assert response.status_code == 200
    assert response.json() == {"username": "analyst"}


def test_me_without_cookie_is_401(client, analyst):
    assert client.get("/api/me").status_code == 401


def test_me_with_garbage_cookie_is_401(client, analyst):
    client.cookies.set("session", "made-up-token")

    assert client.get("/api/me").status_code == 401


def test_me_with_expired_session_is_401(client, analyst, db_session):
    nine_hours_ago = datetime.now(UTC) - timedelta(hours=9)  # 8 h TTL, so already expired
    client.cookies.set("session", create_session(db_session, analyst, now=nine_hours_ago))

    assert client.get("/api/me").status_code == 401


def test_every_non_public_route_requires_a_session(client):
    """Fails if someone adds a route and forgets `user: CurrentUser`.

    Routes come from the OpenAPI schema: FastAPI's public list of every endpoint.
    """
    checked = 0
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            method = method.upper()
            if (method, path) in PUBLIC_ROUTES:
                continue
            url = path.replace("{", "").replace("}", "")  # crude fill for path params
            response = client.request(method, url)
            assert response.status_code == 401, f"{method} {path} is not protected"
            checked += 1
    assert checked >= 1  # guard: a coverage test that checks nothing must fail
