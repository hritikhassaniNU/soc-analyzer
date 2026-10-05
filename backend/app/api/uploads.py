"""Upload routes. The upload request only validates, stores and queues; it never analyzes."""

import hashlib
import uuid
from datetime import datetime
from pathlib import PurePath
from typing import Annotated, BinaryIO

from fastapi import APIRouter, Depends, Form, HTTPException, Response, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.auth import CurrentUser
from app.config import get_settings
from app.db import get_db
from app.models import Upload, User, events_partition_name
from app.parsing.formats import FormatChoice
from app.parsing.sniff import SNIFF_BYTES, SniffError, sniff_upload
from app.parsing.timestamps import TimestampError, load_timezone
from app.storage import Storage, get_storage

router = APIRouter(prefix="/api/uploads", tags=["uploads"])

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson"}


def _allowed_name(filename: str) -> bool:
    """events.csv, events.jsonl.gz… (compression itself is detected from the content)."""
    suffixes = [s.lower() for s in PurePath(filename).suffixes]
    if suffixes and suffixes[-1] == ".gz":
        suffixes = suffixes[:-1]
    return bool(suffixes) and suffixes[-1] in ALLOWED_EXTENSIONS  # convenience check; the content sniff is the real one
COPY_CHUNK = 1024 * 1024
LIST_LIMIT = 1000  # newest first; the UI pages it 25 at a time


class UploadOut(BaseModel):
    id: int
    filename: str
    format: str
    log_timezone: str
    status: str
    progress: int
    size_bytes: int
    sha256: str
    uploaded_by: str | None
    created_at: datetime
    # Small result fields so the list can show them without one request per row.
    error: str | None
    line_count: int | None
    bad_line_count: int | None

    @classmethod
    def from_row(cls, upload: Upload, uploader: str | None) -> "UploadOut":
        return cls(
            id=upload.id, filename=upload.filename, format=upload.format,
            log_timezone=upload.log_timezone, status=upload.status, progress=upload.progress,
            size_bytes=upload.size_bytes, sha256=upload.sha256, uploaded_by=uploader,
            created_at=upload.created_at, error=upload.error, line_count=upload.line_count,
            bad_line_count=upload.bad_line_count,
        )


class UploadCreated(UploadOut):
    # Earlier uploads with the same SHA-256 (the exact same bytes). Uploading again is allowed
    # (e.g. after a detection change); the UI only warns. Cases stay deduplicated either way.
    previous_uploads: int


class BadLineOut(BaseModel):
    line_no: int
    reason: str
    raw: str  # attacker-controlled log text: the UI must render it escaped


class UploadDetail(UploadOut):
    """UploadOut plus the larger fields, only for a single upload."""

    bad_line_samples: list[BadLineOut]  # up to 20 raw lines of attacker-controlled text
    completed_at: datetime | None
    disabled_detectors: list[str]  # switched off when this upload was scanned (Detection Rules)

    @classmethod
    def from_row(cls, upload: Upload, uploader: str | None) -> "UploadDetail":
        return cls(
            **UploadOut.from_row(upload, uploader).model_dump(),
            bad_line_samples=[BadLineOut(**s) for s in upload.bad_line_samples],
            completed_at=upload.completed_at,
            disabled_detectors=upload.disabled_detectors,
        )


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


def _copy_to_storage(source: BinaryIO, storage: Storage, key: str, max_bytes: int) -> tuple[str, int]:
    """Stream `source` to storage in 1 MB chunks, hashing and counting on the way."""
    digest = hashlib.sha256()
    size = 0
    with storage.open_write(key) as target:  # atomic: an exception below leaves nothing stored
        while chunk := source.read(COPY_CHUNK):
            size += len(chunk)
            if size > max_bytes:  # second line of defense (no Content-Length header)
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"File is larger than {max_bytes // (1024 * 1024)} MB",
                )
            digest.update(chunk)
            target.write(chunk)
    return digest.hexdigest(), size


@router.post("", status_code=status.HTTP_201_CREATED)
def create_upload(
    user: CurrentUser,
    response: Response,
    file: UploadFile,
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[Storage, Depends(get_storage)],
    log_timezone: Annotated[str, Form()] = "UTC",
    format_choice: Annotated[FormatChoice, Form(alias="format")] = "auto",  # auto-detect, or csv/json
) -> UploadCreated:
    # Plain `def`: copying + hashing a big file is blocking work, run in the thread pool.
    filename = PurePath(file.filename or "upload.log").name[:255]  # display only, never a path
    if not _allowed_name(filename):
        raise _bad_request(f"Unsupported file type; allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}, "
                           "optionally gzip-compressed (.gz)")
    try:
        tz = load_timezone(log_timezone)
    except TimestampError as exc:
        raise _bad_request(str(exc)) from None

    try:
        log_format = sniff_upload(file.file.read(SNIFF_BYTES), tz, format_choice)  # fast feedback, nothing stored yet
    except SniffError as exc:
        raise _bad_request(str(exc)) from None
    file.file.seek(0)

    # File first, row second: a 'queued' row never exists without its file.
    prefix = f"uploads/{uuid.uuid4().hex}"
    raw_key = f"{prefix}/raw.log"
    max_bytes = get_settings().max_upload_mb * 1024 * 1024
    sha256, size = _copy_to_storage(file.file, storage, raw_key, max_bytes)

    try:
        upload = Upload(
            filename=filename, format=log_format, log_timezone=log_timezone, uploaded_by=user.id,
            size_bytes=size, sha256=sha256, raw_key=raw_key,
        )
        db.add(upload)
        db.commit()
        db.refresh(upload)  # load server defaults (status, progress, created_at)
    except BaseException:
        storage.delete_prefix(prefix)  # no orphaned file if the insert fails
        raise

    previous = db.scalar(select(func.count()).select_from(Upload)
                         .where(Upload.sha256 == sha256, Upload.id != upload.id))
    response.headers["Location"] = f"/api/uploads/{upload.id}"
    return UploadCreated(**UploadOut.from_row(upload, user.username).model_dump(), previous_uploads=previous or 0)


def _with_uploader():
    # LEFT JOIN: uploads outlive their uploader's account (uploaded_by may be NULL).
    return select(Upload, User.username).outerjoin(User, Upload.uploaded_by == User.id)


@router.get("")
def list_uploads(user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> list[UploadOut]:
    """Newest first. Summary fields only (no bad-line samples)."""
    rows = db.execute(
        _with_uploader().order_by(Upload.created_at.desc(), Upload.id.desc()).limit(LIST_LIMIT)
    ).all()
    return [UploadOut.from_row(upload, username) for upload, username in rows]


@router.get("/{upload_id}")
def get_upload(
    upload_id: int, user: CurrentUser, db: Annotated[Session, Depends(get_db)]
) -> UploadDetail:
    """One upload with status, progress and parse results. The status page polls this."""
    row = db.execute(_with_uploader().where(Upload.id == upload_id)).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload not found")
    return UploadDetail.from_row(*row)


@router.delete("/{upload_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_upload(
    upload_id: int,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> None:
    # FOR UPDATE locks the row until commit, so the worker (which claims with
    # FOR UPDATE SKIP LOCKED) can't start processing it between our check and the delete.
    upload = db.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if upload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload not found")
    if upload.status == "processing":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This upload is being analyzed; delete it after it finishes",
        )
    prefix = upload.raw_key.rsplit("/", 1)[0]  # "uploads/<uuid>": raw file + derived files
    # Drop the events partition (instant) instead of letting the FK cascade delete
    # millions of rows one by one. Same transaction as the row delete. lock_timeout: if
    # someone is still reading this upload's events, answer 409 instead of hanging.
    try:
        db.execute(text("SET LOCAL lock_timeout = '5s'"))
        db.execute(text(f"DROP TABLE IF EXISTS {events_partition_name(upload_id)}"))
    except OperationalError:  # lock_not_available
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This upload is busy (being read); try deleting again in a moment",
        ) from None
    # Row first, files second: a failure in between leaves harmless orphan files,
    # never a row pointing at missing files.
    db.delete(upload)
    db.commit()
    storage.delete_prefix(prefix)
