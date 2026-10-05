import pytest

from app.storage import LocalStorage, StorageError


@pytest.fixture
def storage(tmp_path):
    return LocalStorage(tmp_path / "store")


def test_write_then_read_round_trip(storage):
    with storage.open_write("uploads/1/raw.log") as file:
        file.write(b"line one\n")
        file.write(b"line two\n")

    with storage.open_read("uploads/1/raw.log") as file:
        assert file.read() == b"line one\nline two\n"


def test_large_data_streams_in_chunks(storage):
    chunk = b"x" * 1_000_000
    with storage.open_write("uploads/2/raw.log") as file:
        for _ in range(20):  # 20 MB written chunk by chunk, never held as one object
            file.write(chunk)

    with storage.open_read("uploads/2/raw.log") as file:
        total = sum(len(block) for block in iter(lambda: file.read(1 << 20), b""))
    assert total == 20_000_000


def test_failed_write_leaves_nothing_behind(storage):
    with pytest.raises(RuntimeError):
        with storage.open_write("uploads/3/raw.log") as file:
            file.write(b"half of the upload")
            raise RuntimeError("client disconnected")

    with pytest.raises(StorageError):
        storage.open_read("uploads/3/raw.log")
    leftovers = list((storage.root / "uploads" / "3").iterdir())
    assert leftovers == []  # no temp file either


def test_overwrite_is_atomic_replace(storage):
    for content in (b"old", b"new"):
        with storage.open_write("uploads/4/raw.log") as file:
            file.write(content)

    with storage.open_read("uploads/4/raw.log") as file:
        assert file.read() == b"new"


@pytest.mark.parametrize("key", ["../outside.txt", "uploads/../../etc/passwd", "/etc/passwd", "", "a\\b"])
def test_keys_cannot_escape_the_root(storage, key):
    with pytest.raises(StorageError):
        with storage.open_write(key):
            pass


def test_delete_prefix_removes_one_upload_only(storage):
    for key in ("uploads/5/raw.log", "uploads/5/events.parquet", "uploads/6/raw.log"):
        with storage.open_write(key) as file:
            file.write(b"data")

    storage.delete_prefix("uploads/5")

    with pytest.raises(StorageError):
        storage.open_read("uploads/5/raw.log")
    with storage.open_read("uploads/6/raw.log") as file:
        assert file.read() == b"data"
    storage.delete_prefix("uploads/does-not-exist")  # no error


def test_reading_missing_key_is_a_clear_error(storage):
    with pytest.raises(StorageError, match="Not found"):
        storage.open_read("uploads/99/raw.log")


def test_local_copy_yields_a_readable_path(storage):
    with storage.open_write("uploads/7/events.parquet") as file:
        file.write(b"PAR1")

    with storage.local_copy("uploads/7/events.parquet") as path:
        assert path.read_bytes() == b"PAR1"

    with pytest.raises(StorageError):
        with storage.local_copy("uploads/7/missing.parquet"):
            pass
