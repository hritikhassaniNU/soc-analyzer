"""gzip support: recognized by content (the two "magic" bytes 1f 8b), not by file name, and always
streamed (never unpacked to disk).

Zip bombs: a few MB of gzip can expand to many GB. The upload limit only sees the compressed size,
so the decompressed stream is capped too (setting MAX_UNCOMPRESSED_MB); beyond it the analysis
fails with a clear message instead of filling the disk or running for hours.
"""

import io
import zlib
from typing import BinaryIO

from app.parsing.base import NotZscalerLogError

GZIP_MAGIC = b"\x1f\x8b"


def is_gzip(head: bytes) -> bool:
    return head[:2] == GZIP_MAGIC


def decompress_head(head: bytes, max_bytes: int) -> bytes:
    """Up to max_bytes of decompressed data from the START of a gzip file (the upload sniff only
    has the first compressed bytes; a cut-off stream is fine). ValueError if it isn't valid gzip."""
    try:
        return zlib.decompressobj(wbits=16 + zlib.MAX_WBITS).decompress(head, max_bytes)
    except zlib.error as exc:
        raise ValueError(f"The file looks gzip-compressed but can't be read: {exc}") from None


class LimitedDecompressedReader(io.RawIOBase):
    """Reads a decompressing stream, stops at `limit` bytes, and turns gzip errors into a message
    for the analyst (NotZscalerLogError) instead of an 'unexpected error'."""

    def __init__(self, inner: BinaryIO, limit: int) -> None:
        self.inner = inner
        self.limit = limit
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        try:
            data = self.inner.read(len(buffer))
        except (OSError, EOFError, zlib.error) as exc:  # BadGzipFile is an OSError; truncated → EOFError
            raise NotZscalerLogError(f"The gzip file is damaged or incomplete ({exc})") from None
        self.bytes_read += len(data)
        if self.bytes_read > self.limit:
            raise NotZscalerLogError(
                f"The file expands to more than {self.limit // (1024 * 1024):,} MB when decompressed "
                "(limit MAX_UNCOMPRESSED_MB); split it or raise the limit"
            )
        buffer[: len(data)] = data
        return len(data)
