"""ORM models (tables). Every model subclasses app.db.Base; Alembic imports this module."""

from datetime import datetime

from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, REAL
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    """A SOC analyst who can log in. Seeded from env, no sign-up."""

    __tablename__ = "users"

    # IDENTITY (SQL-standard auto-numbering), not legacy SERIAL.
    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    # Stored lowercase so login is case-insensitive; unique in the DB (not just in app code).
    username: Mapped[str] = mapped_column(String(64), unique=True)
    # bcrypt hash only, never the plain password.
    password_hash: Mapped[str] = mapped_column(String(255))
    # timestamptz, filled by Postgres: an absolute moment in time (we work in UTC).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserSession(Base):
    """A logged-in browser session. Named UserSession to avoid clashing with SQLAlchemy's Session."""

    __tablename__ = "sessions"

    # SHA-256 (hex) of the random cookie token. The raw token is never stored,
    # so a leaked database can't be used to hijack sessions.
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Deleting a user deletes their sessions. Indexed: Postgres doesn't auto-index FKs.
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Absolute expiry (created + 8 h), never extended, so a stolen cookie dies on time.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


UPLOAD_STATUSES = ("queued", "processing", "done", "failed")
LOG_FORMATS = ("csv", "json")


class Upload(Base):
    """One uploaded log file. Also the worker's job queue (status = 'queued')."""

    __tablename__ = "uploads"
    __table_args__ = (
        # Text + CHECK instead of a Postgres ENUM: same protection, easy to extend later.
        CheckConstraint(f"status IN {UPLOAD_STATUSES}", name="status"),
        CheckConstraint(f"format IN {LOG_FORMATS}", name="format"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="progress"),
        # Partial index: only queued rows, exactly what the worker's claim query looks for.
        Index("ix_uploads_queued", "created_at", postgresql_where=text("status = 'queued'")),
    )

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))  # display only, never used as a path
    format: Mapped[str] = mapped_column(String(10))
    log_timezone: Mapped[str] = mapped_column(String(64), server_default="UTC")
    # Uploads are evidence: they outlive the uploader's account (SET NULL, not CASCADE).
    uploaded_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))  # evidence integrity + duplicate detection
    raw_key: Mapped[str] = mapped_column(Text)  # storage key, e.g. "uploads/<uuid>/raw.log"
    parquet_key: Mapped[str | None] = mapped_column(Text)  # set by pass 1

    status: Mapped[str] = mapped_column(String(20), server_default="queued")
    progress: Mapped[int] = mapped_column(server_default="0")
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(server_default="0")
    # A temporarily failed job waits until this time before it can be claimed again (backoff).
    retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Detectors switched off when this upload was last scanned (snapshot, so old results stay explainable).
    disabled_detectors: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    error: Mapped[str | None] = mapped_column(Text)

    line_count: Mapped[int | None]
    bad_line_count: Mapped[int | None]
    bad_line_samples: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, server_default=text("'[]'::jsonb")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def events_partition_name(upload_id: int) -> str:
    """Physical table holding one upload's events, e.g. events_u42 (created by the worker)."""
    return f"events_u{int(upload_id)}"


class Event(Base):
    """One parsed log line. LIST-partitioned by upload: one physical table per upload.

    The parent table comes from the Alembic migration; per-upload partitions are created at
    runtime by the worker. Delete/re-analyze = DROP the partition (instant, no dead rows).
    """

    __tablename__ = "events"
    __table_args__ = (
        # Defined once on the parent; Postgres creates them on every partition.
        Index("ix_events_ts_line", "ts", "line_no"),        # time-ordered keyset paging
        Index("ix_events_username_ts", "username", "ts"),   # drill-down / window joins
        {"postgresql_partition_by": "LIST (upload_id)"},
    )

    # The partition key must be part of the primary key on a partitioned table.
    upload_id: Mapped[int] = mapped_column(
        ForeignKey("uploads.id", ondelete="CASCADE"), primary_key=True
    )
    line_no: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    username: Mapped[str] = mapped_column(Text)
    client_ip: Mapped[str] = mapped_column(Text)  # text, not inet: one odd IP must not fail a COPY batch
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(SmallInteger)
    bytes_out: Mapped[int] = mapped_column(BigInteger)
    bytes_in: Mapped[int] = mapped_column(BigInteger)
    department: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(Text)
    server_ip: Mapped[str | None] = mapped_column(Text)
    protocol: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text)
    app_name: Mapped[str | None] = mapped_column(Text)
    threat: Mapped[str | None] = mapped_column(Text)
    malware_category: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(SmallInteger)
    user_agent: Mapped[str | None] = mapped_column(Text)
    file_type: Mapped[str | None] = mapped_column(Text)
    device: Mapped[str | None] = mapped_column(Text)  # Client Connector hostname; often empty
    device_os: Mapped[str | None] = mapped_column(Text)
    # Detection layer 1 (app/detection/rules.py): names of the rules that fired + highest score.
    rule_hits: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    rule_max_score: Mapped[float] = mapped_column(REAL, server_default=text("0"))


class UploadSummary(Base):
    """Dashboard aggregates for one upload, computed once in pass 2 (app/pipeline/aggregates.py).

    JSONB documents: always read whole by upload_id, and their shape grows without migrations.
    Separate from `uploads` so the list/poll queries stay light.
    """

    __tablename__ = "upload_summary"

    upload_id: Mapped[int] = mapped_column(
        ForeignKey("uploads.id", ondelete="CASCADE"), primary_key=True
    )
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB)
    timeline: Mapped[dict[str, Any]] = mapped_column(JSONB)
    top_n: Mapped[dict[str, Any]] = mapped_column(JSONB)
    narrative: Mapped[dict[str, Any] | None] = mapped_column(JSONB)  # Claude summary (step 23)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


ANOMALY_SOURCES = ("rule", "stat", "ml", "ai")  # ai: the Claude domain classifier (D136)


class Anomaly(Base):
    """One finding about a user over a time window (from rules, statistics or ML).

    Scores are 0-1 ranking signals, not probabilities. `details` keeps the numbers behind the
    score (observed value, baseline, robust z...) so every finding is explainable.
    """

    __tablename__ = "anomalies"
    __table_args__ = (
        CheckConstraint(f"source IN {ANOMALY_SOURCES}", name="source"),
        CheckConstraint("score >= 0 AND score <= 1", name="score"),
        CheckConstraint("window_end >= window_start", name="window"),
        Index("ix_anomalies_upload_user_start", "upload_id", "username", "window_start"),
    )

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"))
    username: Mapped[str] = mapped_column(Text)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(10))
    kind: Mapped[str] = mapped_column(String(40))  # e.g. request_burst, large_upload, off_hours
    score: Mapped[float] = mapped_column(REAL)
    reason: Mapped[str] = mapped_column(Text)  # human-readable explanation
    count: Mapped[int] = mapped_column(server_default="0")  # events involved
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    # The incident this finding belongs to (set by correlation). One incident per anomaly, so a
    # plain foreign key, not a link table. SET NULL: rebuilding incidents never deletes evidence.
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )


INCIDENT_PRIORITIES = ("critical", "high", "medium", "low")


class Incident(Base):
    """A user's correlated anomalies close together in time: what an analyst triages.

    priority_score (0-1) = strongest severity-weighted finding + a bonus for each other category
    of evidence (corroboration). A ranking signal, not a probability. See docs/DECISIONS.md.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(f"priority IN {INCIDENT_PRIORITIES}", name="priority"),
        CheckConstraint("priority_score >= 0 AND priority_score <= 1", name="priority_score"),
        CheckConstraint("end_ts >= start_ts", name="window"),
        # The UI lists an upload's incidents worst first.
        Index("ix_incidents_upload_priority", "upload_id", text("priority_score DESC")),
    )

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"))
    username: Mapped[str] = mapped_column(Text)
    start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(Text)  # e.g. "Beaconing, executable download, off-hours"
    priority_score: Mapped[float] = mapped_column(REAL)
    priority: Mapped[str] = mapped_column(String(10))
    categories: Mapped[list[str]] = mapped_column(ARRAY(Text))  # e.g. {command_and_control, delivery}
    narrative: Mapped[str | None] = mapped_column(Text)  # LLM summary (step 23)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


REVIEW_SOURCES = ("ai", "template")


class CompanyReview(Base):
    """A written review of the company-wide picture (dashboard), generated on demand and kept.

    `fingerprint` identifies the set of unique incidents it described, so the dashboard can say
    "new analyses since this review" when they change.
    """

    __tablename__ = "company_reviews"
    __table_args__ = (CheckConstraint(f"source IN {REVIEW_SOURCES}", name="source"),)

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(10))
    model: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)  # plain text; may quote log-derived names
    # Structured sections (D80); empty for reviews written before them.
    headline: Mapped[str | None] = mapped_column(Text)
    key_findings: Mapped[list[dict[str, str]]] = mapped_column(JSONB, server_default=text("'[]'"))
    actions: Mapped[list[str]] = mapped_column(JSONB, server_default=text("'[]'"))
    fingerprint: Mapped[str] = mapped_column(String(64))  # sha256 hex of the incidents it covered
    incident_count: Mapped[int]


class UserReview(Base):
    """An on-demand AI (or template) review of one user from the logs across all their incidents.
    Same rules as CompanyReview: kept, and marked stale when that user's incidents change."""

    __tablename__ = "user_reviews"
    __table_args__ = (CheckConstraint(f"source IN {REVIEW_SOURCES}", name="source"),)

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    username: Mapped[str] = mapped_column(Text, index=True)  # the person reviewed (log user)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(10))
    model: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)  # plain text; may quote log-derived names
    # Structured sections (D80); empty for reviews written before them.
    headline: Mapped[str | None] = mapped_column(Text)
    key_findings: Mapped[list[dict[str, str]]] = mapped_column(JSONB, server_default=text("'[]'"))
    actions: Mapped[list[str]] = mapped_column(JSONB, server_default=text("'[]'"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    incident_count: Mapped[int]


CASE_STATUSES = ("open", "investigating", "resolved")
CASE_VERDICTS = ("true_positive", "false_positive", "benign")


class Case(Base):
    """An investigation: one per unique incident (user + time window + title) across uploads, so
    re-uploading the same logs never creates a new case and the analyst's work stays attached.
    Numbered from 1001 (shown as INC-1001)."""

    __tablename__ = "cases"
    __table_args__ = (
        UniqueConstraint("username", "start_ts", "end_ts", "title"),  # one case per unique incident
        CheckConstraint(f"status IN {CASE_STATUSES}", name="status"),
        CheckConstraint(f"verdict IN {CASE_VERDICTS}", name="verdict"),
    )

    id: Mapped[int] = mapped_column(Identity(start=1001), primary_key=True)
    username: Mapped[str] = mapped_column(Text)
    start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), server_default="open")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    verdict: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CaseNote(Base):
    """An analyst's note on a case. Plain text, shown as text."""

    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


DOMAIN_LABELS = ("random_generated", "brand_lookalike", "anonymous_file_sharing", "likely_benign")
DOMAIN_CONFIDENCES = ("low", "medium", "high")


class DomainVerdict(Base):
    """The AI domain classifier's answer for one host (D136), cached across uploads: a domain seen
    before costs no API call. A domain name says the same thing in every log, so the cache is global."""

    __tablename__ = "domain_verdicts"
    __table_args__ = (
        CheckConstraint(f"label IN {DOMAIN_LABELS}", name="label"),
        CheckConstraint(f"confidence IN {DOMAIN_CONFIDENCES}", name="confidence"),
    )

    host: Mapped[str] = mapped_column(Text, primary_key=True)  # lower-case
    label: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(Text)  # model-written: plain text
    model: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DetectorSetting(Base):
    """An analyst's on/off switch for one detector (app/detection/catalog.py). No row = enabled.
    Applies to new scans only; who changed it and when is kept for accountability."""

    __tablename__ = "detector_settings"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)  # the detector's finding kind
    enabled: Mapped[bool] = mapped_column(Boolean)
    changed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
