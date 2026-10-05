import io

import pytest
from sqlalchemy import select

from app.generator import Generator, GeneratorConfig
from app.models import Incident, Upload
from app.parsing.formats import detect_format
from app.pipeline.analyze import analyze

GOOD = ("analyst", "correct-horse-1")


@pytest.mark.parametrize(("text", "expected"), [
    ('{"time": "x"}\n', "json"),
    ('\n\n  {"time": "x"}\n', "json"),
    ('﻿{"time": "x"}\n', "json"),  # byte-order mark
    ("2026-09-21 08:00:00,jdoe,…\n", "csv"),
    ("time,user,url\n", "csv"),
    ('[{"time": "x"}]\n', "json"),  # a JSON array: rejected later, but with a JSON-specific hint
    ("", "csv"),
])
def test_detect_format(text, expected):
    assert detect_format(text) == expected


def week(log_format: str) -> bytes:
    out = io.StringIO()
    Generator(GeneratorConfig(days=7, users=8, seed=9, log_format=log_format)).write(out)
    return out.getvalue().encode()


@pytest.fixture(scope="module")
def json_week() -> bytes:
    return week("json")


@pytest.fixture(scope="module")
def csv_week() -> bytes:
    return week("csv")


def post(client, content: bytes, filename="proxy.jsonl", **form):
    return client.post("/api/uploads", files={"file": (filename, content, "text/plain")}, data=form)


@pytest.mark.integration
def test_json_is_detected_and_stored(client, analyst, json_week):
    client.post("/api/login", auth=GOOD)

    response = post(client, json_week)

    assert response.status_code == 201 and response.json()["format"] == "json"


@pytest.mark.integration
@pytest.mark.parametrize("filename", ["proxy.json", "proxy.ndjson", "proxy.log"])
def test_json_extensions(client, analyst, json_week, filename):
    client.post("/api/login", auth=GOOD)

    assert post(client, json_week, filename=filename).status_code == 201


@pytest.mark.integration
def test_override_that_contradicts_the_content_is_a_clear_400(client, analyst, json_week):
    client.post("/api/login", auth=GOOD)

    response = post(client, json_week, format="csv")

    assert response.status_code == 400
    assert response.json()["detail"].startswith("Doesn't look like a Zscaler CSV")


@pytest.mark.integration
def test_unknown_format_choice_is_rejected(client, analyst, json_week):
    client.post("/api/login", auth=GOOD)

    assert post(client, json_week, format="xml").status_code == 422


@pytest.mark.integration
def test_the_same_week_as_json_or_csv_gives_the_same_analysis(client, analyst, storage, db_session, json_week, csv_week):
    client.post("/api/login", auth=GOOD)
    ids = {fmt: post(client, content, filename=name).json()["id"]
           for fmt, content, name in (("json", json_week, "w.jsonl"), ("csv", csv_week, "w.csv"))}
    for upload_id in ids.values():
        analyze(upload_id, storage)

    def result(upload_id):
        upload = db_session.get(Upload, upload_id)
        incidents = db_session.scalars(select(Incident).where(Incident.upload_id == upload_id)).all()
        return (upload.line_count, upload.bad_line_count,
                sorted((i.username, i.priority, round(i.priority_score, 3), i.title, i.start_ts) for i in incidents))

    db_session.expire_all()
    assert db_session.get(Upload, ids["json"]).format == "json"
    assert result(ids["json"]) == result(ids["csv"])



@pytest.mark.integration
@pytest.mark.parametrize("content", [
    b'{\n  "seed": 42,\n  "plants": []\n}\n',            # pretty-printed document (e.g. an answer key)
    b'[{"time": "2026-09-21 08:00:00", "user": "x"}]\n',  # a JSON array
])
def test_a_single_json_document_gets_a_helpful_hint(client, analyst, content):
    client.post("/api/login", auth=GOOD)

    response = post(client, content, filename="zscaler_clean.truth.json")

    assert response.status_code == 400
    assert "This looks like a single JSON document" in response.json()["detail"]
    assert "one object per line" in response.json()["detail"]
