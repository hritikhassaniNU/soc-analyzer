import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web import CSP, IMMUTABLE, NO_CACHE, add_security_headers, mount_frontend


@pytest.fixture
def web_client(tmp_path):
    """A small app with one API route + the frontend mounted from a fake build."""
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    (tmp_path / "assets" / "index-abc123.js").write_text("console.log('app')")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    (tmp_path.parent / "secret.txt").write_text("outside the build folder")

    app = FastAPI()
    add_security_headers(app)

    @app.get("/api/ping")
    def ping() -> dict[str, str]:
        return {"pong": "yes"}

    mount_frontend(app, tmp_path)
    return TestClient(app)


def test_api_routes_still_win(web_client):
    assert web_client.get("/api/ping").json() == {"pong": "yes"}


def test_unknown_api_path_is_json_404_not_the_app(web_client):
    response = web_client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize("path", ["/", "/login", "/uploads/7", "/uploads/7?tab=events&username=jdoe"])
def test_client_side_routes_get_index_html_uncached(web_client, path):
    response = web_client.get(path)

    assert response.status_code == 200
    assert "<div id=root>" in response.text
    assert response.headers["cache-control"] == NO_CACHE


def test_hashed_assets_are_cached_for_a_year(web_client):
    response = web_client.get("/assets/index-abc123.js")

    assert response.text == "console.log('app')"
    assert response.headers["cache-control"] == IMMUTABLE


def test_root_files_are_served(web_client):
    assert web_client.get("/favicon.svg").text == "<svg/>"


def test_path_traversal_cannot_escape_the_build_folder(web_client):
    response = web_client.get("/..%2fsecret.txt")

    assert "outside the build folder" not in response.text


def test_security_headers_everywhere_except_docs(web_client):
    app_page = web_client.get("/uploads/7")
    api = web_client.get("/api/ping")

    for response in (app_page, api):
        assert response.headers["content-security-policy"] == CSP
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "same-origin"
    assert "content-security-policy" not in web_client.get("/docs").headers
