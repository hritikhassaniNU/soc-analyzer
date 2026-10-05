"""Streaming parser for our Zscaler web log CSV layout (see fields.py).

Usage:
    parser = CsvParser(log_tz)
    for event in parser.parse(lines):   # generator: memory stays flat for any file size
        ...
    parser.stats                        # line counts + up to 20 bad-line samples

This module only splits CSV records into named fields (with an optional header, in any column
order, using our names or common NSS aliases); validation and bad-line rules live in base.py.
"""

import csv
from collections.abc import Iterable, Iterator

from app.parsing.base import (  # noqa: F401  (re-exported: other modules import them from here)
    EARLY_STOP_LINES,
    MAX_BAD_RATIO,
    MAX_BAD_SAMPLES,
    BadLine,
    LineError,
    LineParser,
    NotZscalerLogError,
    ParseStats,
)
from app.parsing.event import ZscalerEvent
from app.parsing.fields import CSV_COLUMNS, LEGACY_WIDTH, REQUIRED_COLUMNS, canonical_name

_DEFAULT_INDEX = {name: i for i, name in enumerate(CSV_COLUMNS)}


class CsvParser(LineParser):
    FORMAT_NAME = "CSV"

    def __init__(self, log_tz) -> None:
        super().__init__(log_tz)
        self._index: dict[str, int] | None = None  # column name -> position (set from first row)
        self._widths = {len(CSV_COLUMNS), LEGACY_WIDTH}  # headerless: with or without the device columns

    def parse(self, lines: Iterable[str]) -> Iterator[ZscalerEvent]:
        last_raw = ""

        def remember(source: Iterable[str]) -> Iterator[str]:
            nonlocal last_raw  # keep the raw text of the current line for bad-line samples
            for line in source:
                last_raw = line
                yield line

        reader = csv.reader(remember(lines))
        while True:
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:  # e.g. a giant field; the reader continues with the next line
                self._record_bad(reader.line_num, f"CSV error: {exc}", last_raw)
                continue

            if not row or all(not cell.strip() for cell in row):
                continue  # blank line: ignored, not counted

            if self._index is None:
                self._index = self._header_index(row)
                if self._index is not None:
                    self.stats.header_detected = True
                    self._widths = {len(row)}
                    continue
                self._index = _DEFAULT_INDEX

            event = self._accept(lambda row=row: self._fields(row), reader.line_num, last_raw)
            if event is not None:
                yield event
        self._finish()

    # ---- helpers ----

    def _header_index(self, row: list[str]) -> dict[str, int] | None:
        """If `row` is a header, map field name -> position (any order; NSS aliases accepted)."""
        names = [canonical_name(cell) for cell in row]
        if "time" not in names or "user" not in names:
            return None  # not a header: a data row
        missing = REQUIRED_COLUMNS - set(names)
        if missing:
            raise NotZscalerLogError(f"Header is missing required columns: {', '.join(sorted(missing))}")
        index: dict[str, int] = {}
        for position, name in enumerate(names):
            if name is not None and name not in index:  # first occurrence wins
                index[name] = position
        return index

    def _fields(self, row: list[str]):
        if len(row) not in self._widths:
            expected = " or ".join(str(w) for w in sorted(self._widths))
            raise LineError(f"Expected {expected} columns, got {len(row)}")
        index = self._index
        assert index is not None

        def get(name: str) -> str | None:
            position = index.get(name)
            value = row[position].strip() if position is not None and position < len(row) else ""
            return value or None

        return get
