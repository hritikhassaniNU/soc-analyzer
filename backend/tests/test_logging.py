import io
import json
import logging

import pytest

from app.logging_config import JsonFormatter, TextFormatter, UploadIdFilter, job_context


@pytest.fixture
def capture():
    """A handler set up like setup_logging() does, writing into a string."""
    def make(formatter):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(UploadIdFilter())
        handler.setFormatter(formatter)
        logger = logging.getLogger("test.logging")
        logger.handlers[:] = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        return logger, stream
    yield make
    logging.getLogger("test.logging").handlers.clear()


def test_json_lines_use_cloud_logging_fields(capture):
    logger, stream = capture(JsonFormatter())

    with job_context(17):
        logger.warning("Claude summary failed (%s)", "APIConnectionError")

    entry = json.loads(stream.getvalue())
    assert entry["severity"] == "WARNING" and entry["logger"] == "test.logging"
    assert entry["message"] == "Claude summary failed (APIConnectionError)"
    assert entry["upload_id"] == 17 and entry["timestamp"].endswith("+00:00")


def test_the_upload_id_is_only_attached_during_the_job(capture):
    logger, stream = capture(JsonFormatter())

    with job_context(17):
        logger.info("inside")
    logger.info("outside")

    inside, outside = (json.loads(line) for line in stream.getvalue().splitlines())
    assert inside["upload_id"] == 17 and "upload_id" not in outside


def test_exceptions_are_kept_in_one_json_line(capture):
    logger, stream = capture(JsonFormatter())

    try:
        raise KeyError("boom")
    except KeyError:
        logger.exception("unexpected error")

    [line] = stream.getvalue().splitlines()  # the traceback doesn't break the one-line format
    assert "KeyError: 'boom'" in json.loads(line)["exception"]


def test_text_format_stays_readable(capture):
    logger, stream = capture(TextFormatter())

    with job_context(17):
        logger.info("upload 17: analysis started")

    assert stream.getvalue().rstrip().endswith("INFO test.logging: upload 17: analysis started [upload_id=17]")


def test_lines_from_other_modules_carry_the_id_too(capture):
    _, stream = capture(JsonFormatter())
    child = logging.getLogger("test.logging.llm_client")  # like app.llm.client: no handler of its own

    with job_context(17):
        child.warning("from another module")

    entry = json.loads(stream.getvalue())
    assert (entry["logger"], entry["upload_id"]) == ("test.logging.llm_client", 17)
