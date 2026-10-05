"""Pass 2: whole-file analysis on the Parquet snapshot (DuckDB): dashboard aggregates and the
findings stored as anomalies: grouped rule hits (source=rule), the statistical detectors
(source=stat), ML outliers (source=ml, evidence only) and the AI domain classifier (source=ai, only
with an API key), correlated into ranked incidents.
The summary narrative comes later.

Idempotent: the summary is upserted and this pass's anomalies are replaced, so re-analysis never
duplicates anything. Summary and anomalies are written in ONE transaction: a reader never sees
a new summary next to old (or half-written) anomalies.
"""

from collections.abc import Callable
from dataclasses import asdict

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.detection.ai_domains import Classifier, DomainCandidate, DomainVerdictInput
from app.detection.correlate import parse_hosts
from app.detection.run import detect
from app.llm.client import MessagesClient
from app.llm.domains import classify_domains
from app.models import Anomaly, Case, DomainVerdict, Incident, Upload, UploadSummary
from app.parsing.timestamps import load_timezone
from app.pipeline.aggregates import compute_aggregates, duckdb_connection
from app.storage import Storage

PROGRESS_AFTER_PASS2 = 95
OWN_SOURCES = ("rule", "stat", "ml", "ai")  # anomaly sources this pass creates (and replaces)


def cached_domain_classifier(
    session_factory: Callable[[], Session], client: MessagesClient | None = None,
) -> Classifier | None:
    """The AI domain classifier (D136) behind the domain_verdicts cache: only hosts never classified
    before are sent to Claude, and every new answer is stored. None without an API key (and no test
    client): the AI detector then doesn't run."""
    settings = get_settings()
    if not settings.anthropic_api_key and client is None:
        return None

    def classify(candidates: list[DomainCandidate]) -> dict[str, DomainVerdictInput]:
        hosts = [c.host for c in candidates]
        with session_factory() as db:
            known = {v.host: DomainVerdictInput(v.label, v.confidence, v.reason, v.model)
                     for v in db.scalars(select(DomainVerdict).where(DomainVerdict.host.in_(hosts)))}
        new = classify_domains([c for c in candidates if c.host not in known], api_key=settings.anthropic_api_key,
                               model=settings.anthropic_model, timeout=settings.llm_review_timeout_seconds, client=client)
        if new:
            with session_factory() as db:
                db.execute(insert(DomainVerdict).values([
                    {"host": host, "label": v.label, "confidence": v.confidence, "reason": v.reason, "model": v.model}
                    for host, v in new.items()
                ]).on_conflict_do_nothing(index_elements=[DomainVerdict.host]))  # a parallel scan got there first
                db.commit()
        return known | new

    return classify


def run_pass2(
    upload_id: int, storage: Storage, session_factory: Callable[[], Session] = SessionLocal,
    client: MessagesClient | None = None,
) -> None:
    with session_factory() as db:
        upload = db.get(Upload, upload_id)
        parquet_key, log_tz = upload.parquet_key, load_timezone(upload.log_timezone)  # set by pass 1
        disabled = frozenset(upload.disabled_detectors)  # the same snapshot pass 1 used
    if parquet_key is None:
        raise RuntimeError(f"Upload {upload_id} has no Parquet file; run pass 1 first")

    with storage.local_copy(parquet_key) as parquet_path:
        con = duckdb_connection()  # one connection (memory/thread limits) for both steps
        result = compute_aggregates(parquet_path, con)
        detection = detect(con, parquet_path, log_tz, parse_hosts(get_settings().approved_upload_hosts), disabled,
                           classify_domains=cached_domain_classifier(session_factory, client))
    tagged, drafts = detection.findings, detection.incidents

    with session_factory() as db:
        # Upsert: one summary per upload; re-analysis replaces it (no duplicate-key error).
        values = {"upload_id": upload_id, "stats": result["stats"],
                  "timeline": result["timeline"], "top_n": result["top"]}
        statement = insert(UploadSummary).values(**values)
        db.execute(statement.on_conflict_do_update(
            index_elements=[UploadSummary.upload_id],
            set_={**{k: statement.excluded[k] for k in ("stats", "timeline", "top_n")},
                  "computed_at": statement.excluded.computed_at,
                  "narrative": None},  # re-analysis: the old summary described old incidents
        ))
        # Replace everything this pass produces (findings of every source, and incidents).
        db.execute(delete(Incident).where(Incident.upload_id == upload_id))
        db.execute(delete(Anomaly).where(Anomaly.upload_id == upload_id, Anomaly.source.in_(OWN_SOURCES)))
        incidents = [
            Incident(upload_id=upload_id, username=d.username, start_ts=d.start, end_ts=d.end,
                     title=d.title, priority_score=d.priority_score, priority=d.priority,
                     categories=d.categories)
            for d in drafts
        ]
        db.add_all(incidents)
        db.flush()  # assigns incident ids
        if drafts:  # each unique incident is a case; a re-upload finds its existing case (number kept)
            db.execute(insert(Case).values([
                {"username": d.username, "start_ts": d.start, "end_ts": d.end, "title": d.title} for d in drafts
            ]).on_conflict_do_nothing(index_elements=[Case.username, Case.start_ts, Case.end_ts, Case.title]))
        incident_of = {member: incident.id for d, incident in zip(drafts, incidents) for member in d.members}
        rows = [{**asdict(finding), "upload_id": upload_id, "source": source, "incident_id": incident_of[i]}
                for i, (source, finding) in enumerate(tagged)]
        if rows:
            db.execute(insert(Anomaly), rows)
        db.execute(update(Upload).where(Upload.id == upload_id)
                   .values(progress=PROGRESS_AFTER_PASS2, locked_at=func.now()))  # progress = heartbeat
        db.commit()
