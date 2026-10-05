"""Logging for the worker: readable text by default, one JSON object per line with LOG_FORMAT=json.

The JSON field names (timestamp, severity, message) are the ones Google Cloud Logging reads, so on
GCP each line becomes a searchable entry. While a job runs, every log line (from any module: parser,
detectors, Claude client) carries the upload's id, set once by the worker with `job_context()`, so
"everything about upload 17" is one filter.
"""

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime

_upload_id: ContextVar[int | None] = ContextVar("upload_id", default=None)


@contextmanager
def job_context(upload_id: int) -> Iterator[None]:
    """Attach `upload_id` to every log line written inside this block."""
    token = _upload_id.set(upload_id)
    try:
        yield
    finally:
        _upload_id.reset(token)


class UploadIdFilter(logging.Filter):
    """Copies the current job's upload id onto each record (None outside a job)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.upload_id = _upload_id.get()
        return True


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        upload_id = getattr(record, "upload_id", None)
        return text if upload_id is None else f"{text} [upload_id={upload_id}]"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if (upload_id := getattr(record, "upload_id", None)) is not None:
            entry["upload_id"] = upload_id
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(log_format: str = "text", level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    # On the HANDLER, not a logger: logger filters don't see records propagated from child loggers.
    handler.addFilter(UploadIdFilter())
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
