"""The whole analysis job for one upload. A plain function: the worker calls it, and so do tests.

Status changes (queued/processing/done/failed) belong to the worker, not to this function.
Both passes are idempotent, so a retry simply runs the job again.
"""

from sqlalchemy import select, update

from app.db import SessionLocal
from app.models import DetectorSetting, Upload
from app.pipeline.pass1 import run_pass1
from app.pipeline.narrate import run_narrative
from app.pipeline.pass2 import run_pass2
from app.storage import Storage, get_storage


def snapshot_disabled_detectors(upload_id: int) -> list[str]:
    """Record which detectors are switched off right now on the upload, so both passes use the same
    set and the result stays explainable after the settings change (new scans only)."""
    with SessionLocal() as db:
        disabled = sorted(db.scalars(select(DetectorSetting.kind).where(DetectorSetting.enabled.is_(False))))
        db.execute(update(Upload).where(Upload.id == upload_id).values(disabled_detectors=disabled))
        db.commit()
    return disabled


def analyze(upload_id: int, storage: Storage | None = None) -> None:
    storage = storage or get_storage()
    snapshot_disabled_detectors(upload_id)  # detectors switched off by analysts (Detection Rules page)
    run_pass1(upload_id, storage)  # parse + rules -> Postgres + Parquet   (progress 0-70)
    run_pass2(upload_id, storage)  # aggregates, detectors, incidents   (progress 70-95)
    run_narrative(upload_id)       # Claude or template summary; never fails the job (99)
    # The worker marks the upload done (100) after this returns.
