"""File storage behind a small interface: local disk now, Google Cloud Storage at deploy time.

Callers use string KEYS like "uploads/42/raw.log", never file paths, and always stream
(a 500 MB upload is never held in memory). Swapping LocalStorage for a GCS implementation
needs no changes in the code that uses storage.
"""

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO, Protocol

from app.config import get_settings


class StorageError(Exception):
    """Invalid key, or the object doesn't exist."""


class Storage(Protocol):
    """What any storage backend must provide (structural typing: no inheritance needed)."""

    def open_write(self, key: str) -> AbstractContextManager[BinaryIO]:
        """Stream bytes to `key`. Atomic: the key only appears if the whole write succeeded."""
        ...

    def open_read(self, key: str) -> BinaryIO:
        """Stream bytes from `key`. Raises StorageError if it doesn't exist."""
        ...

    def delete_prefix(self, prefix: str) -> None:
        """Delete everything under `prefix` (e.g. all files of one upload). No error if absent."""
        ...

    def local_copy(self, key: str) -> AbstractContextManager[Path]:
        """A local file path for `key`, for tools that need a path (DuckDB). Local storage
        yields the real file; a cloud backend would download to a temp file and delete it after."""
        ...


class LocalStorage:
    """Storage on the local filesystem (a Docker volume in Compose)."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # Defense in depth: keys come from our own code, but never allow escaping the root.
        if not key or key.startswith("/") or "\\" in key:
            raise StorageError(f"Invalid storage key: {key!r}")
        path = (self.root / key).resolve()
        if path == self.root or not path.is_relative_to(self.root):
            raise StorageError(f"Storage key escapes the storage root: {key!r}")
        return path

    @contextmanager
    def open_write(self, key: str) -> Iterator[BinaryIO]:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Temp file in the SAME directory: os.replace is then an atomic rename on one filesystem.
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=f"-{path.name}")
        try:
            with os.fdopen(fd, "wb") as file:
                yield file
                file.flush()
                os.fsync(file.fileno())  # bytes are on disk before the file becomes visible
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)  # failed write: leave nothing behind
            raise

    def open_read(self, key: str) -> BinaryIO:
        path = self._path(key)
        if not path.is_file():
            raise StorageError(f"Not found: {key}")
        return path.open("rb")

    @contextmanager
    def local_copy(self, key: str) -> Iterator[Path]:
        path = self._path(key)
        if not path.is_file():
            raise StorageError(f"Not found: {key}")
        yield path  # already on local disk: no copy needed

    def delete_prefix(self, prefix: str) -> None:
        path = self._path(prefix)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)


@lru_cache
def get_storage() -> Storage:
    """FastAPI dependency / worker helper. Tests override it with a temporary directory."""
    return LocalStorage(get_settings().storage_dir)
