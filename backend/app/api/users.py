"""User profiles: one person from the logs (not an analyst account) across every scanned upload.

History counts each dataset once (a re-uploaded week is not double-counted) and each unique incident
once, like the dashboard. A user's risk is the highest risk among their UNRESOLVED cases: a case an
analyst resolved (any verdict) no longer drives it, but stays in the history and verdict counts.
"""

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from statistics import median
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.api.analysis import Priority
from app.api.dashboard import DOUBLE_CLICK_WINDOW, KeyFinding, ReviewOut, fingerprint, structured, unique_dataset_uploads, unique_incidents
from app.api.investigations import InvestigationItem, _cases_with_incidents, _findings, _item, _owners
from app.auth import CurrentUser
from app.config import get_settings
from app.detection.correlate import CATEGORY_LABELS
from app.db import get_db
from app.llm.client import summarize
from app.llm.payload import FindingInput, IncidentInput
from app.models import Anomaly, Event, User, UserReview

router = APIRouter(prefix="/api/users", tags=["users"])

TOP_N = 5


class UserListItem(BaseModel):
    username: str
    department: str | None
    risk: int | None  # highest risk among unresolved cases; None = no unresolved case
    priority: Priority | None
    open_cases: int  # unresolved (open + investigating)
    cases: int
    events: int
    last_seen: datetime
    reason: str | None  # main kinds of evidence in the unresolved cases, strongest first


class Count(BaseModel):
    name: str
    count: int


class Device(BaseModel):
    name: str
    os: str | None
    events: int


class UserRisk(BaseModel):
    score: int | None
    priority: Priority | None
    case_id: int | None  # the unresolved case that sets it
    explanation: str


class Verdicts(BaseModel):
    true_positive: int
    false_positive: int
    benign: int
    unresolved: int


class DayIncidents(BaseModel):
    day: date
    incidents: int
    worst: Priority


class ActivityPoint(BaseModel):
    ts: datetime  # bucket start (UTC)
    events: int
    blocked: int
    flagged: int  # lines that matched a rule


class IncidentWindow(BaseModel):
    case_id: int
    start: datetime
    end: datetime
    priority: Priority


class Activity(BaseModel):
    bucket_hours: int  # 1 for up to 31 days of data, 6 up to 90 days, else 24
    points: list[ActivityPoint]  # gap-filled: quiet buckets are zeros, not missing
    incidents: list[IncidentWindow]  # shaded on the chart


class Baseline(BaseModel):
    active_days: int
    median_daily_events: int
    median_daily_bytes_out: int
    max_daily_bytes_out: int
    hours_utc: list[int]  # events per hour of day (0-23, UTC)
    blocked_share: float
    top_domains: list[Count]
    top_categories: list[Count]


class UserProfile(BaseModel):
    username: str
    department: str | None
    location: str | None
    first_seen: datetime
    last_seen: datetime
    events: int
    datasets: int  # distinct uploaded weeks/files this user appears in
    devices: list[Device]
    ips: list[Count]
    risk: UserRisk
    verdicts: Verdicts
    cases: list[InvestigationItem]  # newest first
    timeline: list[DayIncidents]
    baseline: Baseline
    activity: Activity  # blocked and flagged per time bucket


def _risk_by_user(db: Session) -> dict[str, list]:
    """username -> [(case, incident), ...] for every case still backed by a completed analysis."""
    by_user: dict[str, list] = defaultdict(list)
    for c, incident in _cases_with_incidents(db):
        by_user[c.username].append((c, incident))
    return by_user


def _worst_unresolved(pairs: list) -> tuple | None:
    unresolved = [(c, i) for c, i in pairs if c.status != "resolved"]
    return max(unresolved, key=lambda p: (p[1].priority_score, p[1].start_ts), default=None)


@router.get("")
def list_users(user: CurrentUser, db: Annotated[Session, Depends(get_db)], q: str | None = None) -> list[UserListItem]:
    """Everyone seen in the logs, riskiest first (users without an unresolved case after them)."""
    uploads = unique_dataset_uploads(db)
    if not uploads:
        return []
    rows = db.execute(
        select(Event.username, func.count(), func.max(Event.ts), func.mode().within_group(Event.department))
        .where(Event.upload_id.in_(uploads)).group_by(Event.username)
    ).all()
    cases = _risk_by_user(db)
    items = []
    for username, events, last_seen, department in rows:
        if q and q.strip().lower() not in username:
            continue
        pairs = cases.get(username, [])
        worst = _worst_unresolved(pairs)
        open_pairs = sorted((p for p in pairs if p[0].status != "resolved"), key=lambda p: -p[1].priority_score)
        kinds: list[str] = []
        for _, incident in open_pairs:
            if incident.categories and incident.categories[0] not in kinds:
                kinds.append(incident.categories[0])
        reason = ", ".join(CATEGORY_LABELS.get(k, k) for k in kinds[:3]) or None
        items.append(UserListItem(
            username=username, department=department,
            risk=round(worst[1].priority_score * 100) if worst else None,
            priority=worst[1].priority if worst else None,
            open_cases=sum(c.status != "resolved" for c, _ in pairs), cases=len(pairs),
            events=events, last_seen=last_seen,
            reason=reason[:1].upper() + reason[1:] if reason else None,
        ))
    return sorted(items, key=lambda u: (-(u.risk if u.risk is not None else -1), -u.open_cases, u.username))


@router.get("/{username}")
def get_user(username: str, user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> UserProfile:
    username = username.lower()  # usernames are stored lowercased by the parser
    uploads = unique_dataset_uploads(db)
    mine = (Event.upload_id.in_(uploads), Event.username == username)
    summary = db.execute(
        select(func.count(), func.min(Event.ts), func.max(Event.ts), func.count(Event.upload_id.distinct()),
               func.mode().within_group(Event.department), func.mode().within_group(Event.location),
               func.avg(case((Event.action == "Blocked", 1), else_=0)))
        .where(*mine)
    ).one() if uploads else None
    if summary is None or summary[0] == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found in any scanned upload")
    events, first_seen, last_seen, datasets, department, location, blocked = summary

    def top(column, limit=TOP_N) -> list[Count]:
        count = func.count().label("n")
        return [Count(name=name, count=n) for name, n in db.execute(
            select(column, count).where(*mine, column.is_not(None)).group_by(column)
            .order_by(count.desc(), column).limit(limit))]

    count = func.count().label("n")
    devices = [Device(name=d, os=os_type, events=n) for d, os_type, n in db.execute(
        select(Event.device, func.max(Event.device_os), count).where(*mine, Event.device.is_not(None))
        .group_by(Event.device).order_by(count.desc(), Event.device))]

    day = func.date_trunc("day", Event.ts).label("day")
    daily = db.execute(select(day, func.count(), func.sum(Event.bytes_out)).where(*mine).group_by(day)).all()
    hour = func.extract("hour", func.timezone("UTC", Event.ts)).label("hour")
    hours = {int(h): n for h, n in db.execute(select(hour, func.count()).where(*mine).group_by(hour))}

    # Cases and risk
    pairs = sorted(_risk_by_user(db).get(username, []), key=lambda p: p[1].start_ts, reverse=True)
    findings = _findings(db, [i.id for _, i in pairs])
    owners = _owners(db)
    worst = _worst_unresolved(pairs)
    resolved = Counter(c.verdict for c, _ in pairs if c.status == "resolved")
    unresolved = sum(c.status != "resolved" for c, _ in pairs)
    if worst:
        explanation = (f"Highest risk among {unresolved} unresolved case{'s' if unresolved != 1 else ''}: "
                       f"INC-{worst[0].id} ({worst[1].title}).")
    elif pairs:
        explanation = f"All {len(pairs)} cases are resolved, so none counts toward current risk."
    else:
        explanation = "No incidents for this user."

    by_day: dict[date, list[str]] = defaultdict(list)
    for _, incident in pairs:
        by_day[incident.start_ts.date()].append(incident.priority)
    order = ["low", "medium", "high", "critical"]

    # Activity chart: hourly counts from Postgres, re-bucketed here so long histories stay readable.
    hour_start = func.date_trunc("hour", Event.ts).label("hour")
    hourly = db.execute(
        select(hour_start, func.count(), func.count().filter(Event.action == "Blocked"),
               func.count().filter(func.cardinality(Event.rule_hits) > 0))
        .where(*mine).group_by(hour_start)
    ).all()
    span_days = (last_seen - first_seen).total_seconds() / 86400
    bucket_hours = 1 if span_days <= 31 else 6 if span_days <= 90 else 24
    buckets: dict[datetime, list[int]] = defaultdict(lambda: [0, 0, 0])
    for hour_ts, n, blocked_n, flagged_n in hourly:
        key = hour_ts.replace(hour=hour_ts.hour - hour_ts.hour % bucket_hours)
        for i, value in enumerate((n, blocked_n, flagged_n)):
            buckets[key][i] += value
    points = []
    if buckets:
        step = timedelta(hours=bucket_hours)
        cursor, end_bucket = min(buckets), max(buckets)
        while cursor <= end_bucket:
            n, blocked_n, flagged_n = buckets.get(cursor, (0, 0, 0))
            points.append(ActivityPoint(ts=cursor, events=n, blocked=blocked_n, flagged=flagged_n))
            cursor += step
    activity = Activity(bucket_hours=bucket_hours, points=points, incidents=[
        IncidentWindow(case_id=c.id, start=i.start_ts, end=i.end_ts, priority=i.priority) for c, i in pairs])

    return UserProfile(
        activity=activity,
        username=username, department=department, location=location, first_seen=first_seen,
        last_seen=last_seen, events=events, datasets=datasets, devices=devices, ips=top(Event.client_ip, 10),
        risk=UserRisk(score=round(worst[1].priority_score * 100) if worst else None,
                      priority=worst[1].priority if worst else None,
                      case_id=worst[0].id if worst else None, explanation=explanation),
        verdicts=Verdicts(true_positive=resolved["true_positive"], false_positive=resolved["false_positive"],
                          benign=resolved["benign"], unresolved=unresolved),
        cases=[InvestigationItem(**_item(db, c, i, findings[i.id], owners)) for c, i in pairs],
        timeline=[DayIncidents(day=d, incidents=len(p), worst=max(p, key=order.index))
                  for d, p in sorted(by_day.items())],
        baseline=Baseline(
            active_days=len(daily),
            median_daily_events=round(median(n for _, n, _ in daily)),
            median_daily_bytes_out=round(median(b or 0 for _, _, b in daily)),
            max_daily_bytes_out=max(b or 0 for _, _, b in daily),
            hours_utc=[int(hours.get(h, 0)) for h in range(24)],
            blocked_share=round(float(blocked or 0), 3),
            top_domains=top(Event.host), top_categories=top(Event.category),
        ),
    )


# ---------------------------------------------------------------------------------------------
# AI review of one user: written on demand, kept, marked stale when their incidents change
# ---------------------------------------------------------------------------------------------


def _user_incidents(db: Session, username: str):
    return [i for i in unique_incidents(db) if i.username == username]


def _user_review_out(db: Session, review: UserReview, current: str) -> ReviewOut:
    author = db.get(User, review.created_by) if review.created_by else None
    return ReviewOut(id=review.id, source=review.source, model=review.model, summary=review.summary,
                     headline=review.headline, key_findings=[KeyFinding(**f) for f in review.key_findings],
                     actions=review.actions,
                     created_at=review.created_at, created_by=author.username if author else None,
                     incident_count=review.incident_count, stale=review.fingerprint != current)


def _latest_user_review(db: Session, username: str) -> UserReview | None:
    return db.scalars(select(UserReview).where(UserReview.username == username)
                      .order_by(UserReview.id.desc()).limit(1)).first()


@router.get("/{username}/review")
def get_user_review(username: str, user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> ReviewOut | None:
    """The latest review of this user (null if none was written yet)."""
    username = username.lower()
    review = _latest_user_review(db, username)
    return _user_review_out(db, review, fingerprint(_user_incidents(db, username))) if review else None


@router.post("/{username}/review")
def create_user_review(username: str, user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> ReviewOut:
    """Write a review of this user's history now (Claude if configured, else the template). Only
    stand-ins reach the model: the overview below holds counts and dates, never names or IPs."""
    profile = get_user(username, user, db)  # 404 for someone never seen
    username = profile.username
    incidents = _user_incidents(db, username)
    current = fingerprint(incidents)
    latest = _latest_user_review(db, username)
    if latest and latest.fingerprint == current and datetime.now(UTC) - latest.created_at < DOUBLE_CLICK_WINDOW:
        return _user_review_out(db, latest, current)  # a double click: the same data was just reviewed

    findings: dict[int, list[FindingInput]] = defaultdict(list)
    for a in db.scalars(select(Anomaly).where(Anomaly.incident_id.in_([i.id for i in incidents]))):
        findings[a.incident_id].append(FindingInput(a.kind, a.source, a.score, a.window_start, a.window_end, a.reason))
    inputs = [IncidentInput(i.id, i.username, i.priority, i.priority_score, i.title, i.start_ts, i.end_ts, findings[i.id])
              for i in incidents]
    overview = {
        "scope": "one user's activity across all analyzed logs (each incident counted once)",
        "datasets": profile.datasets,
        "events": profile.events,
        "first_seen": profile.first_seen.isoformat(),
        "last_seen": profile.last_seen.isoformat(),
        "active_days": profile.baseline.active_days,
        "blocked_share": profile.baseline.blocked_share,
        # Analysts' verdicts: lets the review say e.g. "two earlier alerts were false positives".
        "cases_unresolved": profile.verdicts.unresolved,
        "cases_true_positive": profile.verdicts.true_positive,
        "cases_false_positive": profile.verdicts.false_positive,
        "cases_benign": profile.verdicts.benign,
    }
    settings = get_settings()
    narrative = summarize({}, inputs, api_key=settings.anthropic_api_key, model=settings.anthropic_model,
                          timeout=settings.llm_review_timeout_seconds, scope="one user's activity across all analyzed logs",
                          overview=overview)

    review = UserReview(username=username, created_by=user.id, source=narrative.source, model=narrative.model,
                        summary=narrative.summary, fingerprint=current, incident_count=len(incidents),
                        **structured(narrative))
    db.add(review)
    db.commit()
    db.refresh(review)
    return _user_review_out(db, review, current)
