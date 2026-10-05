"""Streaming parser for JSON-lines Zscaler web logs: one JSON object per line.

Keys are our field names (fields.py) or common NSS aliases ("login", "reqsize", ...), matched
case-insensitively; unknown keys are ignored. A record nested under "event" (Zscaler's common
JSON feed for Splunk: {"sourcetype": ..., "event": {...}}) is unwrapped. Values may be strings
or numbers; anything else (objects, lists, true/false) makes that line bad.
Validation and bad-line rules are shared with CSV (base.py).
"""

import json
from collections.abc import Iterable, Iterator
from typing import Any

from app.parsing.base import LineError, LineParser
from app.parsing.event import ZscalerEvent
from app.parsing.fields import canonical_name


class JsonLinesParser(LineParser):
    FORMAT_NAME = "JSON lines"

    def parse(self, lines: Iterable[str]) -> Iterator[ZscalerEvent]:
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue  # blank line: ignored, not counted
            event = self._accept(lambda line=line: _fields(line), line_no, line)
            if event is not None:
                yield event
        self._finish()


def _fields(line: str):
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise LineError(f"Not valid JSON: {exc.msg}") from None
    if not isinstance(record, dict):
        raise LineError("Each line must be a JSON object")
    nested = record.get("event")
    if isinstance(nested, dict) and not any(canonical_name(k) == "time" for k in record):
        record = nested  # {"sourcetype": "zscalernss-web", "event": {...}}

    values: dict[str, str | None] = {}
    for key, value in record.items():
        name = canonical_name(str(key))
        if name is not None and name not in values:  # first occurrence wins
            values[name] = _text(name, value)

    def get(name: str) -> str | None:
        return values.get(name)

    return get


def _text(name: str, value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):  # bool is an int subclass: reject explicitly
        raise LineError(f"Field '{name}' must be a string or number, not true/false")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)  # 512.0 -> "512"
    if isinstance(value, str):
        return value.strip() or None
    raise LineError(f"Field '{name}' must be a string or number")
