"""Analysis results for one upload (computed by the worker; read-only here)."""

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, get_args

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, exists, func, or_, select, tuple_
from sqlalchemy.orm import Session

from app.auth import CurrentUser
from app.db import get_db
from app.detection.rules import RULES
from app.models import INCIDENT_PRIORITIES, Anomaly, Event, Incident, Upload, UploadSummary

router = APIRouter(prefix="/api/uploads", tags=["analysis"])


# Typed response models (not raw dicts): FastAPI validates the output and the OpenAPI schema
# describes every field, so `npm run gen:api` gives the dashboard exact TypeScript types.
class SummaryStats(BaseModel):
    total_events: int
    first_event: str | None
    last_event: str | None
    unique_users: int
    unique_hosts: int
    unique_client_ips: int
    allowed: int
    blocked: int
    bytes_out: int
    bytes_in: int
    threat_events: int
    flagged_events: int
    rule_hits: dict[str, int]


class TimelinePoint(BaseModel):
    t: str  # bucket start, ISO 8601 UTC
    total: int
    blocked: int
    flagged: int


class Timeline(BaseModel):
    bucket: str  # e.g. "1 hour"
    points: list[TimelinePoint]


class TopItem(BaseModel):
    name: str
    value: int


class TopLists(BaseModel):
    users_by_requests: list[TopItem]
    users_by_bytes_out: list[TopItem]
    hosts: list[TopItem]
    categories: list[TopItem]
    blocked_categories: list[TopItem]
    threats: list[TopItem]


class NarrativeOut(BaseModel):
    source: Literal["ai", "template"]  # the UI labels AI text as AI-generated
    model: str | None  # e.g. "claude-sonnet-5-5" when source is "ai"
    summary: str  # plain text; may quote log-derived names: render as text
    generated_at: str


class UploadSummaryOut(BaseModel):
    upload_id: int
    stats: SummaryStats
    timeline: Timeline
    top: TopLists
    computed_at: str
    narrative: NarrativeOut | None  # None while being written, or if writing it failed


def _summary_or_404(db: Session, upload_id: int, what: str) -> UploadSummary:
    """Pass 2 writes the summary, anomalies and incidents in one transaction: if the summary
    exists, all analysis results do."""
    summary = db.get(UploadSummary, upload_id)
    if summary is None:
        upload = db.get(Upload, upload_id)
        detail = (
            "Upload not found"
            if upload is None
            else f"{what} not available yet (status: {upload.status})"
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return summary


@router.get("/{upload_id}/summary")
def get_summary(
    upload_id: int, user: CurrentUser, db: Annotated[Session, Depends(get_db)]
) -> UploadSummaryOut:
    """Dashboard data: stats, timeline and top-10 lists (one request for the whole page)."""
    summary = _summary_or_404(db, upload_id, "Summary")
    return UploadSummaryOut(
        upload_id=upload_id,
        stats=SummaryStats(**summary.stats),
        timeline=Timeline(**summary.timeline),
        top=TopLists(**summary.top_n),
        computed_at=summary.computed_at.isoformat(),
        narrative=NarrativeOut(**{k: summary.narrative[k] for k in ("source", "model", "summary", "generated_at")})
        if summary.narrative else None,
    )


# ---------------------------------------------------------------------------------------------
# Events: filtered, keyset-paginated log lines
# ---------------------------------------------------------------------------------------------

RULE_NAMES = tuple(rule.__name__ for rule in RULES)
RuleName = Literal[RULE_NAMES]  # type: ignore[valid-type]  # unknown rule names -> 422


class EventOut(BaseModel):
    line_no: int
    ts: datetime
    username: str
    client_ip: str
    method: str | None
    url: str  # attacker-controlled text: the UI renders it as plain text
    host: str | None
    action: str
    category: str | None
    risk_score: int
    status_code: int | None
    bytes_out: int
    bytes_in: int
    threat: str | None
    user_agent: str | None
    file_type: str | None
    device: str | None  # Client Connector hostname; None when the log has no device fields
    device_os: str | None
    rule_hits: list[str]
    rule_max_score: float
    # Kinds of statistical/ML findings whose time window contains this event (same user), e.g.
    # ["beaconing", "off_hours"]. Rule hits are line-level (rule_hits); these are window-level.
    windows: list[str] = []


WINDOW_SOURCES = ("stat", "ml", "ai")
# Findings about specific destinations: only events to those hosts are "inside" them (otherwise
# jdoe's normal google.com browsing during the 8-hour beacon would be badged "Beaconing").
# Bursts, unusual hours and large uploads are about ALL the user's activity in the window.
HOST_KEYS = {"beaconing": "host", "rare_domain": "domains", "ai_suspicious_domain": "host"}  # kind -> details key


def _window_covers_sql():
    """SQL condition: this anomaly's window applies to the Event row (same user, time, host)."""
    return and_(
        Anomaly.username == Event.username,
        Anomaly.window_start <= Event.ts, Anomaly.window_end >= Event.ts,
        or_(
            Anomaly.kind.notin_(HOST_KEYS),
            and_(Anomaly.kind.in_(("beaconing", "ai_suspicious_domain")), Anomaly.details["host"].astext == Event.host),
            # details.domains is a JSON array: `?` = "is this string an element of it".
            and_(Anomaly.kind == "rare_domain", Anomaly.details["domains"].has_key(Event.host)),
        ),
    )


def _window_covers(kind: str, details: dict[str, Any], start: datetime, end: datetime, event: "EventOut") -> bool:
    """The same rule in Python, for one page of events (keep in sync with _window_covers_sql)."""
    if not start <= event.ts <= end:
        return False
    if kind in ("beaconing", "ai_suspicious_domain"):
        return details.get("host") == event.host
    if kind == "rare_domain":
        return event.host in details.get("domains", [])  # capped at 20 names per finding
    return True


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None  # opaque; pass back as ?cursor= for the next page, null on the last


def _encode_cursor(ts: datetime, line_no: int) -> str:
    raw = json.dumps({"ts": ts.isoformat(), "line": line_no}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data = json.loads(raw)
        return _utc(datetime.fromisoformat(data["ts"])), int(data["line"])
    except (binascii.Error, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cursor") from None


def _utc(value: datetime | None) -> datetime | None:
    """Query times without a zone are read as UTC (like everything stored)."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


LineSeverity = Literal["critical", "high", "medium", "low", "none"]
# Sources checkboxes (D99): "rule:<name>" (the line matched that rule) or "window:stat|ml" (the line
# sits inside a statistical / ML finding's window). Several are OR-ed.
SOURCE_VALUES = tuple(f"rule:{name}" for name in RULE_NAMES) + ("window:stat", "window:ml", "window:ai")
SourceValue = Literal[SOURCE_VALUES]  # type: ignore[valid-type]


@dataclass
class EventFilterParams:
    """The events filters (all AND-ed), shared by the page and the count endpoints."""

    username: str | None = None
    action: Literal["Allowed", "Blocked"] | None = None
    category: str | None = None
    host: str | None = None
    flagged: bool = False
    rule: RuleName | None = None
    in_window: bool = False
    start: datetime | None = None
    end: datetime | None = None
    # Filter bar (D83): one search box, severity, detection source, "anomaly only".
    q: Annotated[str | None, Query(max_length=200)] = None
    min_score: Annotated[float | None, Query(ge=0, le=1)] = None
    window_source: Literal["stat", "ml", "ai"] | None = None
    anomalous: bool = False
    # Severity checkboxes (D88): bands of the line's highest rule score, OR-ed (?severity=a&severity=b).
    severity: Annotated[list[LineSeverity] | None, Query()] = None
    source: Annotated[list[SourceValue] | None, Query()] = None


SEVERITY_BANDS = ("critical", "high", "medium", "low", "none")


def _severity_band(level: str, score=Event.rule_max_score):
    """SQL condition for one severity band of a line (incident cutoffs; "none" = no rule hit)."""
    return {
        "critical": score >= 0.95,
        "high": and_(score >= 0.75, score < 0.95),
        "medium": and_(score >= 0.45, score < 0.75),
        "low": and_(score > 0, score < 0.45),
        "none": score == 0,
    }[level]


def _filtered_events(upload_id: int, f: EventFilterParams, *, with_severity: bool = True):
    """SELECT of this upload's events with every filter applied (all values bound parameters)."""
    username, action, category, host, flagged, rule = f.username, f.action, f.category, f.host, f.flagged, f.rule
    in_window, start, end, q, min_score = f.in_window, f.start, f.end, f.q, f.min_score
    window_source, anomalous = f.window_source, f.anomalous
    severity = f.severity if with_severity else None
    sources = f.source or []
    query = select(Event).where(Event.upload_id == upload_id)  # partition pruning: one partition
    if username:
        query = query.where(Event.username == username.lower())
    if action:
        query = query.where(Event.action == action)
    if category:
        query = query.where(Event.category == category)
    if host:
        query = query.where(Event.host == host.lower())
    if flagged:
        query = query.where(func.cardinality(Event.rule_hits) > 0)
    if rule:
        query = query.where(Event.rule_hits.contains([rule]))  # Postgres: rule_hits @> ARRAY[rule]
    def inside_window(sources: tuple[str, ...]):
        # Inside some stat/ML finding's window for the same user. EXISTS per event row, served by
        # the anomalies (upload_id, username, window_start) index.
        return exists().where(Anomaly.upload_id == upload_id, Anomaly.source.in_(sources), _window_covers_sql())

    if in_window or window_source:
        query = query.where(inside_window((window_source,) if window_source else WINDOW_SOURCES))
    if anomalous:  # "Anomaly only": the line matched a rule OR sits inside a finding's window
        query = query.where(or_(func.cardinality(Event.rule_hits) > 0, inside_window(WINDOW_SOURCES)))
    if min_score is not None:  # severity of the line = its highest rule score
        query = query.where(Event.rule_max_score >= min_score)
    if q and (needle := q.strip()):
        # Contains, case-insensitive, over the fields an analyst searches by. LIKE wildcards in the
        # input are escaped (searching "a_b" means the text a_b, not "a" + any char + "b").
        pattern = "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(*(column.ilike(pattern, escape="\\") for column in (
            Event.username, Event.client_ip, Event.host, Event.category, Event.device))))
    if severity:
        query = query.where(or_(*(_severity_band(level) for level in severity)))
    if sources:  # any checked source: a matched rule OR inside a checked finding window type
        rules = [s.split(":", 1)[1] for s in sources if s.startswith("rule:")]
        windows = tuple(s.split(":", 1)[1] for s in sources if s.startswith("window:"))
        query = query.where(or_(
            *(Event.rule_hits.contains([r]) for r in rules),
            *((inside_window(windows),) if windows else ()),
        ))
    if start:
        query = query.where(Event.ts >= _utc(start))
    if end:
        query = query.where(Event.ts < _utc(end))
    return query


def _upload_or_404(db: Session, upload_id: int) -> None:
    if db.get(Upload, upload_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload not found")


class EventCount(BaseModel):
    total: int
    # Per severity band, with every OTHER filter applied: what each checkbox would show.
    by_severity: dict[str, int]


class HistogramPoint(BaseModel):
    ts: datetime  # bucket start (UTC)
    total: int
    blocked: int
    flagged: int  # matched a rule


class EventHistogram(BaseModel):
    bucket_minutes: int  # 1/5/15/60/360/1440: the smallest that keeps <= 200 bars (D123)
    points: list[HistogramPoint]  # gap-filled across the time filter (or the matching events)


BUCKET_CHOICES = (1, 5, 15, 60, 360, 1440)  # minutes; all divide a day, so bins align to midnight UTC
MAX_BUCKETS = 200
BIN_ORIGIN = datetime(2000, 1, 1, tzinfo=UTC)


def _bucket_minutes(span: timedelta) -> int:
    """Smallest bucket that keeps the chart under MAX_BUCKETS bars: 1 h -> 1 min, 1 day -> 15 min,
    a week -> 1 h, a month -> 6 h (D123: zooming in gets finer bars instead of one fat one)."""
    for minutes in BUCKET_CHOICES:
        if span / timedelta(minutes=minutes) <= MAX_BUCKETS:
            return minutes
    return BUCKET_CHOICES[-1]


@router.get("/{upload_id}/events/histogram")
def events_histogram(
    upload_id: int, user: CurrentUser, db: Annotated[Session, Depends(get_db)],
    filters: Annotated[EventFilterParams, Depends()],
) -> EventHistogram:
    """Events over time for the current filters (D118): the Logs chart above the table. The range is
    the time filter when set (so a zoom shows the whole zoomed window), else the matching events'."""
    _upload_or_404(db, upload_id)
    rows = _filtered_events(upload_id, filters).subquery()
    first, last = db.execute(select(func.min(rows.c.ts), func.max(rows.c.ts)).select_from(rows)).one()
    if first is None:
        return EventHistogram(bucket_minutes=60, points=[])
    lo = _utc(filters.start) if filters.start else first
    hi = _utc(filters.end) - timedelta(microseconds=1) if filters.end else last  # end is exclusive
    minutes = _bucket_minutes(hi - lo)
    step = timedelta(minutes=minutes)
    binned = func.date_bin(step, rows.c.ts, BIN_ORIGIN).label("bin")
    counts = {
        b: (total, blocked, flagged) for b, total, blocked, flagged in db.execute(
            select(binned, func.count(), func.count().filter(rows.c.action == "Blocked"),
                   func.count().filter(func.cardinality(rows.c.rule_hits) > 0))
            .select_from(rows).group_by(binned)
        )
    }

    def floor(t: datetime) -> datetime:
        return BIN_ORIGIN + (t - BIN_ORIGIN) // step * step

    points, cursor = [], floor(lo)
    while cursor <= floor(hi):  # gap-filled: quiet buckets show as zero, not missing
        total, blocked, flagged = counts.get(cursor, (0, 0, 0))
        points.append(HistogramPoint(ts=cursor, total=total, blocked=blocked, flagged=flagged))
        cursor += step
    return EventHistogram(bucket_minutes=minutes, points=points)


@router.get("/{upload_id}/events/count")
def count_events(
    upload_id: int, user: CurrentUser, db: Annotated[Session, Depends(get_db)],
    filters: Annotated[EventFilterParams, Depends()],
) -> EventCount:
    """How many events match the filters (for "Showing 51–75 of N" and page numbers). Separate from
    the page request so paging doesn't recount: the UI asks once per filter and caches it."""
    _upload_or_404(db, upload_id)
    total = db.scalar(select(func.count()).select_from(_filtered_events(upload_id, filters).subquery())) or 0
    rows = _filtered_events(upload_id, filters, with_severity=False).subquery()
    counts = db.execute(select(*(func.count().filter(_severity_band(level, rows.c.rule_max_score))
                                 for level in SEVERITY_BANDS)).select_from(rows)).one()
    return EventCount(total=total, by_severity=dict(zip(SEVERITY_BANDS, counts)))


@router.get("/{upload_id}/events")
def list_events(
    upload_id: int,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    filters: Annotated[EventFilterParams, Depends()],
    cursor: str | None = None,
    offset: Annotated[int | None, Query(ge=0, le=10_000_000)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> EventPage:
    """Log lines in time order, filtered (all filters AND-ed). Two ways to page (D86):
    - `cursor` (KEYSET): `(ts, line_no) > cursor` uses the (ts, line_no) index, so Next/Previous
      are equally fast at any depth. `line_no` breaks ties between events with the same timestamp,
      so no row is skipped or repeated at a page boundary.
    - `offset`: jump straight to page N (clicking a page number). Postgres reads and discards the
      rows before it, which is fast for our files and slower only deep into multi-million-line ones.
    The total comes from /events/count (asked once per filter). The sort order is fixed.
    """
    _upload_or_404(db, upload_id)
    query = _filtered_events(upload_id, filters)
    if cursor:
        after_ts, after_line = _decode_cursor(cursor)
        query = query.where(tuple_(Event.ts, Event.line_no) > tuple_(after_ts, after_line))

    # Fetch one extra row to know whether another page exists.
    ordered = query.order_by(Event.ts, Event.line_no)
    if offset and not cursor:
        ordered = ordered.offset(offset)
    rows = db.scalars(ordered.limit(limit + 1)).all()
    page, more = rows[:limit], len(rows) > limit
    items = [EventOut.model_validate(row, from_attributes=True) for row in page]
    _add_windows(db, upload_id, items)
    return EventPage(
        items=items,
        next_cursor=_encode_cursor(page[-1].ts, page[-1].line_no) if more else None,
    )


def _add_windows(db: Session, upload_id: int, items: list[EventOut]) -> None:
    """Fill `windows` for one page with ONE query: the stat/ML findings of the page's users that
    overlap the page's time span, matched to events in Python (a page is at most 200 rows)."""
    if not items:
        return
    windows = db.execute(
        select(Anomaly.username, Anomaly.window_start, Anomaly.window_end, Anomaly.kind, Anomaly.details).where(
            Anomaly.upload_id == upload_id, Anomaly.source.in_(WINDOW_SOURCES),
            Anomaly.username.in_({e.username for e in items}),
            Anomaly.window_start <= items[-1].ts, Anomaly.window_end >= items[0].ts,
        )
    ).all()
    for event in items:
        event.windows = sorted({kind for username, start, end, kind, details in windows
                                if username == event.username and _window_covers(kind, details, start, end, event)})


# ---------------------------------------------------------------------------------------------
# Incidents: correlated findings, worst first
# ---------------------------------------------------------------------------------------------

Priority = Literal["critical", "high", "medium", "low"]
assert get_args(Priority) == INCIDENT_PRIORITIES  # one source of truth with the DB CHECK


class AnomalyOut(BaseModel):
    id: int
    source: str  # rule | stat | ml
    kind: str
    window_start: datetime
    window_end: datetime
    score: float  # 0..1 ranking signal, not a probability
    reason: str  # may contain log text (domains, user agents): render as plain text
    count: int
    details: dict[str, Any]


class IncidentOut(BaseModel):
    id: int
    username: str
    start_ts: datetime
    end_ts: datetime
    title: str
    priority: Priority
    priority_score: float  # heuristic ranking score, not a probability
    categories: list[str]
    narrative: str | None  # written summary of this incident (AI or template), plain text
    next_steps: list[str]  # suggested first actions (AI or template)
    anomalies: list[AnomalyOut]  # the evidence, in time order


class IncidentList(BaseModel):
    upload_id: int
    counts: dict[str, int]  # per priority, for ALL incidents (the filter doesn't change these)
    incidents: list[IncidentOut]


@router.get("/{upload_id}/incidents")
def list_incidents(
    upload_id: int,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    min_priority: Priority = "low",
) -> IncidentList:
    """Incidents worst first, each with its findings. `min_priority=medium` hides the low ones."""
    summary = _summary_or_404(db, upload_id, "Incidents")
    written = (summary.narrative or {}).get("incidents", {})  # incident id (str) -> narrative, next steps
    shown = INCIDENT_PRIORITIES[: INCIDENT_PRIORITIES.index(min_priority) + 1]

    counts = dict.fromkeys(INCIDENT_PRIORITIES, 0) | dict(db.execute(
        select(Incident.priority, func.count()).where(Incident.upload_id == upload_id)
        .group_by(Incident.priority)
    ).all())
    incidents = db.scalars(
        select(Incident).where(Incident.upload_id == upload_id, Incident.priority.in_(shown))
        .order_by(Incident.priority_score.desc(), Incident.start_ts, Incident.id)
    ).all()
    # All findings of the shown incidents in ONE query (not one query per incident).
    evidence: dict[int, list[AnomalyOut]] = {i.id: [] for i in incidents}
    for anomaly in db.scalars(
        select(Anomaly).where(Anomaly.incident_id.in_(list(evidence)))
        .order_by(Anomaly.window_start, Anomaly.id)
    ):
        evidence[anomaly.incident_id].append(AnomalyOut.model_validate(anomaly, from_attributes=True))

    return IncidentList(upload_id=upload_id, counts=counts, incidents=[
        IncidentOut(
            id=i.id, username=i.username, start_ts=i.start_ts, end_ts=i.end_ts, title=i.title,
            priority=i.priority, priority_score=i.priority_score, categories=i.categories,
            narrative=i.narrative, next_steps=written.get(str(i.id), {}).get("next_steps", []),
            anomalies=evidence[i.id],
        )
        for i in incidents
    ])
