"""Last stage of an analysis: the written summary (Claude, or the template without a key).

Runs after pass 2. It must never fail an analysis that already succeeded: any error here is
logged and the upload still finishes as done (the UI then shows no summary panel).
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.llm.client import MessagesClient, summarize
from app.llm.payload import FindingInput, IncidentInput
from app.models import Anomaly, Incident, Upload, UploadSummary

log = logging.getLogger(__name__)

PROGRESS_AFTER_NARRATIVE = 99  # the worker sets 100 when it marks the upload done


def _inputs(db: Session, upload_id: int) -> list[IncidentInput]:
    incidents = db.scalars(select(Incident).where(Incident.upload_id == upload_id)).all()
    findings: dict[int, list[FindingInput]] = {i.id: [] for i in incidents}
    for a in db.scalars(select(Anomaly).where(Anomaly.upload_id == upload_id, Anomaly.incident_id.is_not(None))):
        findings[a.incident_id].append(FindingInput(a.kind, a.source, a.score, a.window_start, a.window_end, a.reason,
                                                    a.details or {}))
    return [IncidentInput(i.id, i.username, i.priority, i.priority_score, i.title, i.start_ts, i.end_ts, findings[i.id])
            for i in incidents]


def run_narrative(
    upload_id: int, session_factory: Callable[[], Session] = SessionLocal, client: MessagesClient | None = None,
) -> None:
    try:
        settings = get_settings()
        with session_factory() as db:
            stats = db.get(UploadSummary, upload_id).stats
            incidents = _inputs(db, upload_id)
        # The API call happens outside any DB transaction (it can take up to ~a minute).
        narrative = summarize(stats, incidents, api_key=settings.anthropic_api_key,
                              model=settings.anthropic_model, timeout=settings.llm_timeout_seconds, client=client,
                              triage=True)
        document: dict[str, Any] = {
            "source": narrative.source, "model": narrative.model, "summary": narrative.summary,
            "generated_at": datetime.now(UTC).isoformat(),
            "incidents": {str(id): {"narrative": n.narrative, "next_steps": n.next_steps,
                                    "next_questions": n.next_questions,
                                    "assessment": n.assessment, "searches": n.searches,  # D135
                                    "source": n.source}  # D137: per incident
                          for id, n in narrative.incidents.items()},
        }
        with session_factory() as db:
            db.execute(update(UploadSummary).where(UploadSummary.upload_id == upload_id).values(narrative=document))
            for incident_id, n in narrative.incidents.items():
                db.execute(update(Incident).where(Incident.id == incident_id).values(narrative=n.narrative))
            db.execute(update(Upload).where(Upload.id == upload_id)
                       .values(progress=PROGRESS_AFTER_NARRATIVE, locked_at=func.now()))  # heartbeat
            db.commit()
        log.info("upload %s: %s summary written", upload_id, narrative.source)
    except Exception:
        log.exception("upload %s: summary failed; the analysis itself is complete", upload_id)
