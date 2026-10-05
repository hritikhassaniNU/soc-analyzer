"""Quick content check on the first bytes of an upload: is this plausibly a supported Zscaler log?

Runs in the upload request (fast feedback, an immediate 400) before the file is queued. It decides
the format (detected, or the analyst's choice) and reuses the real parser for it, so the sniff and
the worker can never disagree about what a valid line looks like. The full parse happens in the worker.
"""

from datetime import tzinfo

from app.parsing.base import NotZscalerLogError
from app.parsing.compression import decompress_head, is_gzip
from app.parsing.formats import FormatChoice, LogFormat, detect_format, parser_for

SNIFF_BYTES = 64 * 1024
SNIFF_MAX_LINES = 50


class SniffError(ValueError):
    """The upload clearly isn't a supported log; the message is shown to the analyst."""


_FORMAT_NAMES = {"csv": "Zscaler CSV", "json": "Zscaler JSON-lines log"}


def _json_document_hint(log_format: LogFormat, text: str) -> str:
    """A pretty-printed JSON document or a JSON array starts with a lone "{" or "[" line: say so
    instead of leaving only the parser's low-level message."""
    first = next((line.strip().lstrip("\ufeff") for line in text.splitlines() if line.strip()), "")
    if log_format == "json" and (first in ("{", "[") or first.startswith("[")):
        return (". This looks like a single JSON document (pretty-printed or an array); "
                "upload JSON lines: one object per line")
    return ""


def sniff_upload(head: bytes, log_tz: tzinfo, choice: FormatChoice = "auto") -> LogFormat:
    """The file's format; raise SniffError if the first bytes don't look like it."""
    if is_gzip(head):  # look inside: the first ~64 KB of the decompressed content
        try:
            head = decompress_head(head, SNIFF_BYTES)
        except ValueError as exc:
            raise SniffError(str(exc)) from None
    if not head.strip():
        raise SniffError("The file is empty")
    if b"\x00" in head:
        raise SniffError("This looks like a binary file, not a text log")

    text = head.decode("utf-8", errors="replace")
    if len(head) == SNIFF_BYTES and "\n" in text:
        text = text[: text.rfind("\n") + 1]  # drop a possibly cut-off last line
    log_format: LogFormat = detect_format(text) if choice == "auto" else choice
    parser = parser_for(log_format, log_tz)
    lines = text.splitlines(keepends=True)[:SNIFF_MAX_LINES]
    file_error: NotZscalerLogError | None = None
    try:
        for _ in parser.parse(lines):
            pass
    except NotZscalerLogError as exc:
        file_error = exc  # e.g. header missing columns, or most sampled lines are bad

    if parser.stats.good_lines == 0:
        # Prefer the most concrete reason: the first bad line, if there is one.
        if parser.stats.bad_samples:
            first = parser.stats.bad_samples[0]
            raise SniffError(f"Doesn't look like a {_FORMAT_NAMES[log_format]}: line {first.line_no}: "
                             f"{first.reason}{_json_document_hint(log_format, text)}")
        raise SniffError(f"Doesn't look like a {_FORMAT_NAMES[log_format]}: {file_error}")
    return log_format
