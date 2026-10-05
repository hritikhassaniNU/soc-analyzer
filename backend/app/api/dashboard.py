"""The company-wide dashboard: every completed upload, with each incident counted once.

The same logs are often uploaded more than once (re-uploads, the CSV and the JSON export of the
same week), so plain sums would multiply incidents. Two identities fix that:
- an incident is the same incident when it has the same user, time window and title, whichever
  upload it came from (the newest analysis represents it);
- a dataset is the same dataset when it has the same event count and first/last event time; event
  numbers (flagged, blocked) are summed once per dataset.
"""

import hashlib
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from app.api.analysis import Priority
from app.auth import CurrentUser
from app.config import get_settings
from app.db import get_db
from app.detection.correlate import CATEGORY_LABELS
from app.detection.findings import hosts_in
from app.llm.client import summarize
from app.llm.payload import FindingInput, IncidentInput
from app.models import INCIDENT_PRIORITIES, Anomaly, Case, CompanyReview, Event, Incident, Upload, UploadSummary, User

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

TOP_USERS = 4
TOP_INCIDENTS = 5
TOP_ENTITIES = 5
TYPE_ORDER = {"user": 0, "ip": 1, "domain": 2}  # ties: the person, then their device, then destinations
PER_TYPE = 2  # pure risk order would fill every slot with one user's story (user, IP, 3 domains)
AT_RISK = ("critical", "high", "medium")  # "affected" users and the category breakdown


class RiskyUser(BaseModel):
    username: str
    priority: Priority  # of the user's highest-scoring UNRESOLVED incident
    priority_score: float  # heuristic ranking score, not a probability
    incidents: int
    findings: int
    reason: str  # the main category of each of the user's medium+ incidents, strongest first
    upload_id: int  # where that incident's evidence lives (for links)


class CategoryCount(BaseModel):
    category: str  # e.g. command_and_control
    label: str  # e.g. "command & control"
    incidents: int


class DashboardIncident(BaseModel):
    id: int
    case_id: int | None  # the investigation (INC-…) this incident belongs to
    upload_id: int
    username: str
    priority: Priority
    priority_score: float
    title: str
    start_ts: datetime
    end_ts: datetime
    findings: int


class Entity(BaseModel):
    """Something worth watching: a user, a device's source IP, or a destination domain."""
    type: Literal["user", "ip", "domain"]
    name: str  # attacker-controlled for domains: render as plain text
    risk: int  # 0-100: the highest score (x100) of the medium+ incidents it appears in
    alerts: int  # findings involving it
    detail: str  # why, in words: "beacon destination", "users: jdoe"


class DayCount(BaseModel):
    day: date
    critical: int
    high: int
    medium: int
    low: int


class Kpis(BaseModel):
    incidents: int  # unique incidents, all priorities
    critical: int
    affected_users: int  # users with a medium-or-higher incident
    flagged_events: int  # summed once per distinct dataset
    blocked_events: int
    events: int
    datasets: int  # distinct datasets among the completed uploads
    uploads: int  # completed uploads (copies included)
    # Security overview tiles (D81)
    findings: int  # detections (rule, statistical, ML) in the unique incidents
    findings_high: int  # of which scored high or critical (>= 0.75)
    open_cases: int  # unresolved cases (open + investigating), every priority
    unassigned_urgent: int  # unresolved critical/high cases with no owner
    high_risk_users: int  # users with an unresolved critical/high case
    high_risk_ips: int  # client IPs seen in those cases' windows
    events_last_period: int  # events in the last PERIOD_DAYS days of data
    events_previous_period: int | None  # the PERIOD_DAYS before (None: no data that far back)
    period_days: int


class DatasetCount(BaseModel):
    upload_id: int  # the newest upload of this dataset (Logs opens it)
    filename: str
    first_event: datetime | None
    last_event: datetime | None
    events: int
    flagged: int
    blocked: int


class Dashboard(BaseModel):
    kpis: Kpis
    datasets: list[DatasetCount]  # what "Events analyzed" adds up (newest first)
    users_at_risk: list[RiskyUser]
    severity: dict[str, int]  # every priority, always present
    categories: list[CategoryCount]  # medium-or-higher incidents by their strongest category
    top_incidents: list[DashboardIncident]
    top_entities: list[Entity]  # mixed types, at most 2 of each, highest risk first
    timeline: list[DayCount]  # incidents per day (by start, UTC), gap-filled


def unique_incidents(db: Session) -> list[Incident]:
    """One row per (user, window, title), from the NEWEST scan of each distinct dataset only (D72):
    re-scanning a week (e.g. with a detector switched off) replaces its results instead of adding
    near-duplicate incidents next to the old ones."""
    identity = (Incident.username, Incident.start_ts, Incident.end_ts, Incident.title)
    return list(db.scalars(
        select(Incident).where(Incident.upload_id.in_(unique_dataset_uploads(db)))
        .ext(distinct_on(*identity)).order_by(*identity, Incident.upload_id.desc())
    ))


PERIOD_DAYS = 7
URGENT = ("critical", "high")


def _overview(db: Session, incidents: list[Incident]) -> dict[str, Any]:
    """The security-overview tile numbers (D81), all over the same unique incidents / datasets."""
    ids = [i.id for i in incidents]
    findings, findings_high = db.execute(
        select(func.count(), func.count().filter(Anomaly.score >= 0.75)).where(Anomaly.incident_id.in_(ids))
    ).one() if ids else (0, 0)

    identity = {(i.username, i.start_ts, i.end_ts, i.title): i for i in incidents}
    unresolved = [(c, identity[k]) for c in db.scalars(select(Case).where(Case.status != "resolved"))
                  if (k := (c.username, c.start_ts, c.end_ts, c.title)) in identity]
    urgent = [(c, i) for c, i in unresolved if i.priority in URGENT]
    ips: set[str] = set()
    for _, i in urgent:  # the client IPs of each urgent case's user inside its window
        ips.update(db.scalars(select(Event.client_ip).where(
            Event.upload_id == i.upload_id, Event.username == i.username,
            Event.ts >= i.start_ts, Event.ts <= i.end_ts).distinct()))

    # Trend: events in the last PERIOD_DAYS days that have data vs the PERIOD_DAYS before.
    uploads = unique_dataset_uploads(db)
    day = func.date_trunc("day", Event.ts).label("day")
    per_day = dict(db.execute(select(day, func.count()).where(Event.upload_id.in_(uploads)).group_by(day)).all()) if uploads else {}
    last = previous = 0
    has_previous = False
    if per_day:
        end = max(per_day)
        for d, n in per_day.items():
            age = (end - d).days
            if age < PERIOD_DAYS:
                last += n
            elif age < 2 * PERIOD_DAYS:
                previous += n
        has_previous = min(per_day) <= end - timedelta(days=PERIOD_DAYS)
    return dict(
        findings=findings, findings_high=findings_high,
        open_cases=len(unresolved), unassigned_urgent=sum(c.owner_id is None for c, _ in urgent),
        high_risk_users=len({i.username for _, i in urgent}), high_risk_ips=len(ips),
        events_last_period=last, events_previous_period=previous if has_previous else None,
        period_days=PERIOD_DAYS,
    )


def _dataset_counts(db: Session) -> list[DatasetCount]:
    rows = db.execute(
        select(Upload.id, Upload.filename, UploadSummary.stats).join(UploadSummary, UploadSummary.upload_id == Upload.id)
        .where(Upload.id.in_(unique_dataset_uploads(db))).order_by(Upload.id.desc())
    ).all()
    return [DatasetCount(upload_id=i, filename=name, first_event=s["first_event"], last_event=s["last_event"],
                         events=s["total_events"], flagged=s["flagged_events"], blocked=s["blocked"])
            for i, name, s in rows]


def unique_dataset_uploads(db: Session) -> list[int]:
    """One completed upload per distinct dataset (same event count + first/last event = same data),
    the newest one. For per-user history across uploads, so a re-uploaded week counts once."""
    rows = db.execute(
        select(Upload.id, UploadSummary.stats).join(UploadSummary, UploadSummary.upload_id == Upload.id)
        .where(Upload.status == "done").order_by(Upload.id.desc())
    ).all()
    seen: dict[tuple, int] = {}
    for upload_id, stats in rows:
        seen.setdefault((stats["total_events"], stats["first_event"], stats["last_event"]), upload_id)
    return sorted(seen.values())


def _dataset_stats(db: Session) -> tuple[list[dict[str, Any]], int]:
    """Stats of each distinct dataset (same events + first/last event = same data) and the number
    of completed uploads."""
    rows = db.execute(
        select(UploadSummary.stats).join(Upload, Upload.id == UploadSummary.upload_id)
        .where(Upload.status == "done").order_by(Upload.id.desc())
    ).scalars().all()
    seen: dict[tuple, dict[str, Any]] = {}
    for stats in rows:
        seen.setdefault((stats["total_events"], stats["first_event"], stats["last_event"]), stats)
    return list(seen.values()), len(rows)


# Why a domain is suspicious, from the strongest finding that names it.
DOMAIN_REASONS = {
    "beaconing": "beacon destination",
    "rare_domain": "rare random-looking domain",
    "ai_suspicious_domain": "AI: suspicious domain name",
    "large_upload": "large-upload destination",
    "zscaler_threat": "known threat",
    "high_risk_allowed": "high-risk site, allowed",
    "executable_download": "executable download source",
    "scripted_client": "contacted by a script",
}


def _ip_entities(db: Session, incidents: list[Incident], findings: Counter[int]) -> list[Entity]:
    """Source IPs (devices) seen in each medium+ incident's events. One indexed query per incident
    (events partition + username + time window); medium+ incidents are few."""
    ips: dict[str, dict[str, Any]] = {}
    for i in incidents:
        for (ip,) in db.execute(
            select(Event.client_ip).where(Event.upload_id == i.upload_id, Event.username == i.username,
                                          Event.ts >= i.start_ts, Event.ts <= i.end_ts).distinct()
        ):
            d = ips.setdefault(ip, {"risk": 0.0, "alerts": 0, "users": set()})
            d["risk"] = max(d["risk"], i.priority_score)
            d["alerts"] += findings[i.id]
            d["users"].add(i.username)
    return [Entity(type="ip", name=ip, risk=round(d["risk"] * 100), alerts=d["alerts"],
                   detail="used by " + ", ".join(sorted(d["users"]))) for ip, d in ips.items()]


_hosts = hosts_in  # shared with the case searches (app/llm/searches.py)


@router.get("")
def get_dashboard(user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> Dashboard:
    incidents = unique_incidents(db)
    by_id = {i.id: i for i in incidents}
    findings_per_incident: Counter[int] = Counter()
    domains: dict[str, dict[str, Any]] = {}  # host -> {risk, alerts, reason, reason_score}
    for incident_id, kind, score, details in db.execute(
        select(Anomaly.incident_id, Anomaly.kind, Anomaly.score, Anomaly.details)
        .where(Anomaly.incident_id.in_(list(by_id)))
    ):
        findings_per_incident[incident_id] += 1
        incident = by_id[incident_id]
        if incident.priority not in AT_RISK:
            continue
        for host in _hosts(details):
            d = domains.setdefault(host, {"risk": 0.0, "alerts": 0, "reason": "", "reason_score": -1.0})
            d["risk"] = max(d["risk"], incident.priority_score)
            d["alerts"] += 1
            if score > d["reason_score"] and kind in DOMAIN_REASONS:
                d["reason"], d["reason_score"] = DOMAIN_REASONS[kind], score

    # Users: their highest-scoring incident decides their rank and reason.
    # Users at risk = their worst UNRESOLVED case, the same rule as the Users page and profiles (D74):
    # once analysts resolve a user's cases, that user leaves this card (history stays on the profile).
    resolved = {(c.username, c.start_ts, c.end_ts, c.title)
                for c in db.scalars(select(Case).where(Case.status == "resolved"))}
    per_user: dict[str, list[Incident]] = defaultdict(list)
    for incident in incidents:
        if (incident.username, incident.start_ts, incident.end_ts, incident.title) not in resolved:
            per_user[incident.username].append(incident)
    risky = []
    for username, own in per_user.items():
        best = max(own, key=lambda i: (i.priority_score, i.start_ts))
        if best.priority in AT_RISK:
            # Every serious story of this user, not just the top one (jdoe: Tuesday's C2 AND
            # Sunday's large upload): each medium+ incident's main category, strongest first.
            main = []
            for i in sorted(own, key=lambda i: -i.priority_score):
                if i.priority in AT_RISK and i.categories and i.categories[0] not in main:
                    main.append(i.categories[0])
            reason = ", ".join(CATEGORY_LABELS.get(c, c) for c in main)
            risky.append(RiskyUser(
                username=username, priority=best.priority, priority_score=best.priority_score,
                incidents=len(own), findings=sum(findings_per_incident[i.id] for i in own),
                reason=reason[:1].upper() + reason[1:], upload_id=best.upload_id,
            ))
    risky.sort(key=lambda u: (-u.priority_score, u.username))

    severity = dict.fromkeys(INCIDENT_PRIORITIES, 0) | Counter(i.priority for i in incidents)
    categories = Counter(i.categories[0] for i in incidents if i.priority in AT_RISK and i.categories)

    ranked = sorted(incidents, key=lambda i: (-i.priority_score, -i.start_ts.timestamp()))
    case_of = {(c.username, c.start_ts, c.end_ts, c.title): c.id for c in db.scalars(select(Case))}
    top_incidents = [
        DashboardIncident(id=i.id, case_id=case_of.get((i.username, i.start_ts, i.end_ts, i.title)),
                          upload_id=i.upload_id, username=i.username, priority=i.priority,
                          priority_score=i.priority_score, title=i.title, start_ts=i.start_ts,
                          end_ts=i.end_ts, findings=findings_per_incident[i.id])
        for i in ranked[:TOP_INCIDENTS]
    ]
    entities = [Entity(type="user", name=u.username, risk=round(u.priority_score * 100), alerts=u.findings,
                       detail=f"{u.findings} alert{'s' if u.findings != 1 else ''}") for u in risky]
    entities += _ip_entities(db, [i for i in incidents if i.priority in AT_RISK], findings_per_incident)
    entities += [Entity(type="domain", name=host, risk=round(d["risk"] * 100), alerts=d["alerts"],
                        detail=d["reason"] or "in incident evidence") for host, d in domains.items()]
    entities.sort(key=lambda e: (-e.risk, -e.alerts, TYPE_ORDER[e.type], e.name))  # deterministic
    per_type: Counter[str] = Counter()
    top_entities = []
    for e in entities:
        if per_type[e.type] < PER_TYPE and len(top_entities) < TOP_ENTITIES:
            per_type[e.type] += 1
            top_entities.append(e)

    timeline: list[DayCount] = []
    if incidents:
        per_day: dict[date, Counter] = defaultdict(Counter)
        for i in incidents:
            per_day[i.start_ts.date()][i.priority] += 1  # timestamptz values are UTC
        day, last = min(per_day), max(per_day)
        while day <= last:  # gap-filled: quiet days show as zero, not missing
            counts = per_day.get(day, Counter())
            timeline.append(DayCount(day=day, **{p: counts[p] for p in INCIDENT_PRIORITIES}))
            day += timedelta(days=1)

    datasets, uploads = _dataset_stats(db)
    overview = _overview(db, incidents)
    return Dashboard(
        datasets=_dataset_counts(db),
        kpis=Kpis(**overview,
            incidents=len(incidents), critical=severity["critical"],
            affected_users=len(risky),
            flagged_events=sum(s["flagged_events"] for s in datasets),
            blocked_events=sum(s["blocked"] for s in datasets),
            events=sum(s["total_events"] for s in datasets),
            datasets=len(datasets), uploads=uploads,
        ),
        users_at_risk=risky[:TOP_USERS],
        severity=severity,
        categories=[CategoryCount(category=c, label=CATEGORY_LABELS.get(c, c), incidents=n)
                    for c, n in categories.most_common()],
        top_incidents=top_incidents,
        top_entities=top_entities,
        timeline=timeline,
    )


# ---------------------------------------------------------------------------------------------
# Company-wide AI review: written on demand, kept, and marked stale when the incidents change
# ---------------------------------------------------------------------------------------------

DOUBLE_CLICK_WINDOW = timedelta(seconds=60)


class KeyFinding(BaseModel):
    priority: Priority
    text: str  # plain text; may quote log-derived names


class ReviewOut(BaseModel):
    id: int
    source: Literal["ai", "template"]
    model: str | None
    headline: str | None
    key_findings: list[KeyFinding]
    actions: list[str]
    summary: str  # plain text; may quote log-derived names
    created_at: datetime
    created_by: str | None
    incident_count: int
    stale: bool  # the unique incidents changed since this review was written


def structured(narrative) -> dict[str, Any]:
    """The narrative's structured sections as stored on a review row."""
    return {"headline": narrative.headline, "actions": narrative.actions,
            "key_findings": [{"priority": p, "text": t} for p, t in narrative.key_findings]}


def fingerprint(incidents: list[Incident]) -> str:
    """Identifies the set of unique incidents (and their scores) a review describes."""
    rows = sorted(f"{i.username}|{i.start_ts.isoformat()}|{i.end_ts.isoformat()}|{i.title}|{i.priority_score:.3f}"
                  for i in incidents)
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def _review_out(db: Session, review: CompanyReview, current: str) -> ReviewOut:
    author = db.get(User, review.created_by) if review.created_by else None
    return ReviewOut(id=review.id, source=review.source, model=review.model, summary=review.summary,
                     headline=review.headline, key_findings=[KeyFinding(**f) for f in review.key_findings],
                     actions=review.actions,
                     created_at=review.created_at, created_by=author.username if author else None,
                     incident_count=review.incident_count, stale=review.fingerprint != current)


def _latest_review(db: Session) -> CompanyReview | None:
    return db.scalars(select(CompanyReview).order_by(CompanyReview.id.desc()).limit(1)).first()


@router.get("/review")
def get_review(user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> ReviewOut | None:
    """The latest company-wide review (null if none was written yet)."""
    review = _latest_review(db)
    return _review_out(db, review, fingerprint(unique_incidents(db))) if review else None


@router.post("/review")
def create_review(user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> ReviewOut:
    """Write a review of the company-wide picture now (Claude if configured, else the template).
    Plain `def`: the API call (~20 s) runs in the thread pool, not on the event loop."""
    incidents = unique_incidents(db)
    current = fingerprint(incidents)
    latest = _latest_review(db)
    if latest and latest.fingerprint == current and datetime.now(UTC) - latest.created_at < DOUBLE_CLICK_WINDOW:
        return _review_out(db, latest, current)  # a double click: the same data was just reviewed

    findings: dict[int, list[FindingInput]] = defaultdict(list)
    for a in db.scalars(select(Anomaly).where(Anomaly.incident_id.in_([i.id for i in incidents]))):
        findings[a.incident_id].append(FindingInput(a.kind, a.source, a.score, a.window_start, a.window_end, a.reason))
    inputs = [IncidentInput(i.id, i.username, i.priority, i.priority_score, i.title, i.start_ts, i.end_ts, findings[i.id])
              for i in incidents]
    datasets, _ = _dataset_stats(db)
    overview = {  # accurately named: the model once read "users with incidents" as all users
        "scope": "all analyzed logs of the company (each incident counted once)",
        "datasets": len(datasets),
        "events": sum(s["total_events"] for s in datasets),
        "users_with_incidents": len({i.username for i in incidents}),
        "first_event": min((s["first_event"] for s in datasets if s["first_event"]), default=None),
        "last_event": max((s["last_event"] for s in datasets if s["last_event"]), default=None),
        "blocked_requests": sum(s["blocked"] for s in datasets),
    }
    settings = get_settings()
    narrative = summarize({}, inputs, api_key=settings.anthropic_api_key, model=settings.anthropic_model,
                          timeout=settings.llm_review_timeout_seconds, scope="all analyzed logs of the company",
                          overview=overview)

    review = CompanyReview(created_by=user.id, source=narrative.source, model=narrative.model,
                           summary=narrative.summary, fingerprint=current, incident_count=len(incidents),
                           **structured(narrative))
    db.add(review)
    db.commit()
    db.refresh(review)
    return _review_out(db, review, current)
