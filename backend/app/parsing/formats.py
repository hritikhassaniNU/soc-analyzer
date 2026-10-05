"""Which parser reads a file: detected from its content, or chosen by the analyst."""

from datetime import tzinfo
from typing import Literal

from app.parsing.base import LineParser
from app.parsing.csv_parser import CsvParser
from app.parsing.json_parser import JsonLinesParser

LogFormat = Literal["csv", "json"]
FormatChoice = Literal["auto", "csv", "json"]


def detect_format(text: str) -> LogFormat:
    """JSON if the first non-blank line starts with '{' or '[' (after a byte-order mark), else CSV.
    ('[' is never valid JSON lines, but routing a JSON array to the JSON parser gives the analyst a
    JSON-specific error with a hint, instead of a confusing CSV column-count error.)"""
    for line in text.splitlines():
        stripped = line.lstrip("﻿ \t")
        if stripped:
            return "json" if stripped.startswith(("{", "[")) else "csv"
    return "csv"


def parser_for(log_format: LogFormat, log_tz: tzinfo) -> LineParser:
    return JsonLinesParser(log_tz) if log_format == "json" else CsvParser(log_tz)
