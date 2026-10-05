"""Investigations: the company-wide case queue and each case's full picture.

A case is one unique incident (user + time window + title) across all completed uploads; its
evidence comes from the newest analysis of that incident.
"""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.analysis import Priority
from app.api.dashboard import DOMAIN_REASONS, _hosts, unique_incidents
from app.auth import CurrentUser
from app.config import get_settings
from app.db import get_db
from app.detection.correlate import (
    CATEGORY_LABELS,
    CATEGORY_OF_KIND,
    CORROBORATION_MIN,
    is_approved,
    parse_hosts,
    priority_label,
    weighted_score,
)
from app.detection.findings import Finding
from app.llm.searches import default_picks, search_menu
from app.llm.template import NEXT_QUESTIONS
from app.models import CASE_VERDICTS, Anomaly, Case, CaseNote, Event, Incident, UploadSummary, User

router = APIRouter(prefix="/api/investigations", tags=["investigations"])

CaseStatus = Literal["open", "investigating", "resolved"]
Verdict = Literal[CASE_VERDICTS]  # type: ignore[valid-type]  # true_positive / false_positive / benign
NOTE_MAX_CHARS = 5000

# A readable name for a case, from its strongest kind of evidence.
CASE_NAMES = {
    "known_threat": "Known threat activity",
    "command_and_control": "Possible command & control",
    "large_upload": "Possible data exfiltration",
    "executable_download": "Suspicious executable download",
    "automated_traffic": "Automated traffic",
    "unusual_hours": "Activity at unusual hours",
    "behavioral_outlier": "Unusual behavior",
    "suspicious_domain": "Suspicious domain",
}
# What each kind of evidence means, for the "Detection signals" list.
SIGNAL_DESCRIPTIONS = {
    "known_threat": "Zscaler identified a threat, or a high-risk site was allowed.",
    "command_and_control": "Machine-regular traffic or random-looking domains, typical of malware checking in.",
    "large_upload": "Much more data sent than this user's usual hour.",
    "executable_download": "An executable file was downloaded.",
    "automated_traffic": "Requests from a script or tool, or a burst no person could make.",
    "unusual_hours": "Activity well outside this user's usual working hours.",
    "behavioral_outlier": "An unusual combination of behavior in one hour (machine learning, evidence only).",
    "suspicious_domain": "AI judged a rare domain's name suspicious: generated, a brand look-alike or anonymous file sharing.",
}
# Approved storage (APPROVED_UPLOAD_HOSTS) lowers the score; the name shouldn't sound like a breach.
APPROVED_UPLOAD_NAME = "Large upload to approved storage"
KIND_NAMES = {
    "zscaler_threat": "Zscaler threat", "high_risk_allowed": "High-risk site allowed",
    "scripted_client": "Scripted client", "executable_download": "Executable download",
    "request_burst": "Request burst", "large_upload": "Large upload", "off_hours": "Unusual hours",
    "beaconing": "Beaconing", "rare_domain": "Rare random-looking domain",
    "behavioral_outlier": "Unusual combination (ML)",
    "ai_suspicious_domain": "Suspicious domain (AI)",
}


EntityType = Literal["user", "device", "ip", "domain"]


class EntityChip(BaseModel):
    type: EntityType
    name: str  # attacker-controlled for domains: render as plain text


class InvestigationItem(BaseModel):
    id: int
    number: str  # "INC-1001"
    name: str  # "Possible data exfiltration"
    title: str  # the categories that drive the priority
    priority: Priority
    risk: int  # 0-100: priority score x 100 (heuristic, not a probability)
    signals: int  # independent kinds of evidence that drive the priority
    alerts: int  # findings
    entities: list[EntityChip]
    status: CaseStatus
    owner: str | None
    verdict: str | None
    updated_at: datetime
    start_ts: datetime
    end_ts: datetime
    upload_id: int  # where the evidence lives (View events)


class RiskPart(BaseModel):
    category: str
    label: str
    weight: int  # 0-100: the category's strongest finding score x its severity
    counted: bool  # drives the priority (strongest, or corroborating >= 0.4)


class Signal(BaseModel):
    category: str
    label: str
    description: str
    counted: bool  # same rule as the risk breakdown: False = evidence only (not in the Signals number)


class EvidenceItem(BaseModel):
    kind: str
    name: str
    reason: str  # may contain log text: render as plain text
    score: float
    level: Priority  # the finding's own score as a level
    source: Literal["rule", "stat", "ml", "ai"]
    window_start: datetime
    window_end: datetime


class DetailEntity(BaseModel):
    type: EntityType
    name: str
    detail: str


class NoteOut(BaseModel):
    id: int
    author: str | None  # None if the account was deleted
    text: str  # analyst-written: rendered as plain text
    created_at: datetime


class ActivityPoint(BaseModel):
    ts: datetime  # bucket start (UTC)
    total: int
    blocked: int
    flagged: int


class CaseActivity(BaseModel):
    bucket_minutes: int  # 15 for windows up to 12 h, 60 up to 3 days, else 360
    start: datetime  # the incident window padded by 1 h each side
    end: datetime
    points: list[ActivityPoint]  # gap-filled


class AiAssessment(BaseModel):
    """The AI's triage suggestion: the analyst decides; words, never a percentage."""
    verdict: Literal["likely_malicious", "likely_benign", "needs_more_evidence"]
    confidence: Literal["low", "medium", "high"]
    reason: str  # model-written: plain text


class CaseSearch(BaseModel):
    """A ready-made Logs search. Filters come from our menu, never from the model."""
    id: str
    label: str
    username: str | None
    host: str | None
    action: str | None
    anomalous: bool
    start: datetime | None  # UTC, inclusive
    end: datetime | None    # UTC, exclusive


class InvestigationDetail(InvestigationItem):
    why_flagged: str | None  # the incident's narrative (AI or template)
    narrative_source: Literal["ai", "template"] | None
    next_steps: list[str]
    next_questions: list[str]
    ai_assessment: AiAssessment | None  # only when Claude wrote the analysis
    searches: list[CaseSearch]  # 1-3 next-step searches (AI-picked or the defaults)
    risk_breakdown: list[RiskPart]
    detection_signals: list[Signal]
    evidence: list[EvidenceItem]  # in time order (the Timeline tab uses the same list)
    related_entities: list[DetailEntity]
    notes: list[NoteOut]  # oldest first; append-only
    analysts: list[str]  # who a case can be assigned to
    activity: CaseActivity  # the user's traffic around the incident (Timeline strip)


def _identity(x: Any) -> tuple:
    return (x.username, x.start_ts, x.end_ts, x.title)


def _cases_with_incidents(db: Session) -> list[tuple[Case, Incident]]:
    """Every case that still has a completed analysis, with its newest incident."""
    incidents = {_identity(i): i for i in unique_incidents(db)}
    cases = db.scalars(select(Case)).all()
    return [(c, incidents[_identity(c)]) for c in cases if _identity(c) in incidents]


def _findings(db: Session, incident_ids: list[int]) -> dict[int, list[Anomaly]]:
    rows: dict[int, list[Anomaly]] = defaultdict(list)
    for a in db.scalars(select(Anomaly).where(Anomaly.incident_id.in_(incident_ids))
                        .order_by(Anomaly.window_start, Anomaly.id)):
        rows[a.incident_id].append(a)
    return rows


def _ips(db: Session, incident: Incident) -> list[str]:
    return sorted(db.scalars(
        select(Event.client_ip).where(Event.upload_id == incident.upload_id, Event.username == incident.username,
                                      Event.ts >= incident.start_ts, Event.ts <= incident.end_ts).distinct()
    ))


def _devices(db: Session, incident: Incident) -> list[tuple[str, str | None, int]]:
    """(hostname, OS, events) the user's traffic came from in the incident window, most used first.
    Empty when the log has no device fields (traffic not through Zscaler Client Connector)."""
    count = func.count().label("events")
    rows = db.execute(
        select(Event.device, func.max(Event.device_os), count)
        .where(Event.upload_id == incident.upload_id, Event.username == incident.username,
               Event.ts >= incident.start_ts, Event.ts <= incident.end_ts, Event.device.is_not(None))
        .group_by(Event.device).order_by(count.desc(), Event.device)
    ).all()
    return [(device, os_type, events) for device, os_type, events in rows]


def _domains(findings: list[Anomaly]) -> dict[str, str]:
    """Domain -> why it is suspicious (the strongest finding naming it)."""
    best: dict[str, tuple[float, str]] = {}
    for f in findings:
        for host in _hosts(f.details):
            reason = DOMAIN_REASONS.get(f.kind, "in incident evidence")
            if host not in best or f.score > best[host][0]:
                best[host] = (f.score, reason)
    return {host: reason for host, (_, reason) in sorted(best.items(), key=lambda kv: -kv[1][0])}


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _case_name(main: str, findings: list[Anomaly]) -> str:
    uploads = [f for f in findings if f.kind == "large_upload"]
    approved = parse_hosts(get_settings().approved_upload_hosts)
    if main == "large_upload" and uploads and all(is_approved(f.details.get("top_host"), approved) for f in uploads):
        return APPROVED_UPLOAD_NAME
    return CASE_NAMES.get(main, "Incident")


def _item(db: Session, case: Case, incident: Incident, findings: list[Anomaly], owners: dict[int, str]) -> dict:
    domains = list(_domains(findings))
    chips = ([EntityChip(type="user", name=incident.username)]
             + [EntityChip(type="device", name=d) for d, _, _ in _devices(db, incident)[:1]]
             + [EntityChip(type="ip", name=ip) for ip in _ips(db, incident)[:2]]
             + [EntityChip(type="domain", name=d) for d in domains[:2]])
    main = incident.categories[0] if incident.categories else "behavioral_outlier"
    return dict(
        id=case.id, number=f"INC-{case.id}", name=_case_name(main, findings), title=incident.title,
        priority=incident.priority, risk=round(incident.priority_score * 100),
        signals=len(incident.title.split(", ")),  # the title lists exactly the categories that count
        alerts=len(findings), entities=chips, status=case.status,
        owner=owners.get(case.owner_id) if case.owner_id else None, verdict=case.verdict,
        updated_at=case.updated_at, start_ts=incident.start_ts, end_ts=incident.end_ts, upload_id=incident.upload_id,
    )


def _owners(db: Session) -> dict[int, str]:
    return {u.id: u.username for u in db.scalars(select(User))}


@router.get("")
def list_investigations(
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    q: str | None = None,
    severity: Priority | None = None,
    # "unresolved" = open + investigating (the dashboard's "Open investigations" tile).
    case_status: Annotated[CaseStatus | Literal["unresolved"] | None, Query(alias="status")] = None,
    detector: str | None = None,
) -> list[InvestigationItem]:
    """All cases, unresolved first, then worst first. `q` searches the case number, user, name and entities;
    `detector` keeps cases with at least one finding of that kind (Detection Rules "View cases")."""
    pairs = _cases_with_incidents(db)
    if severity:
        pairs = [(c, i) for c, i in pairs if i.priority == severity]
    if case_status == "unresolved":
        pairs = [(c, i) for c, i in pairs if c.status != "resolved"]
    elif case_status:
        pairs = [(c, i) for c, i in pairs if c.status == case_status]
    findings = _findings(db, [i.id for _, i in pairs])
    if detector:
        pairs = [(c, i) for c, i in pairs if any(f.kind == detector for f in findings[i.id])]
    owners = _owners(db)
    items = [InvestigationItem(**_item(db, c, i, findings[i.id], owners)) for c, i in pairs]
    if q and (needle := q.strip().lower()):
        items = [it for it in items if needle in " ".join(
            [it.number, it.name, it.title] + [e.name for e in it.entities]).lower()]
    # Unresolved first (what analysts work on), then worst first, newest first.
    return sorted(items, key=lambda it: (it.status == "resolved", -it.risk, -it.start_ts.timestamp(), it.id))


@router.get("/{case_id}")
def get_investigation(case_id: int, user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> InvestigationDetail:
    return _detail(db, case_id)


PAD = timedelta(hours=1)


def _activity(db: Session, incident: Incident) -> CaseActivity:
    """This user's events per bucket across the incident window (+1 h either side)."""
    start, end = incident.start_ts - PAD, incident.end_ts + PAD
    span_h = (end - start).total_seconds() / 3600
    minutes = 15 if span_h <= 12 else 60 if span_h <= 72 else 360
    secs = minutes * 60
    slot = (func.floor(func.extract("epoch", Event.ts) / secs) * secs).label("slot")
    rows = db.execute(
        select(slot, func.count(), func.count().filter(Event.action == "Blocked"),
               func.count().filter(func.cardinality(Event.rule_hits) > 0))
        .where(Event.upload_id == incident.upload_id, Event.username == incident.username,
               Event.ts >= start, Event.ts <= end)
        .group_by(slot)
    ).all()
    counts = {int(sl): (n, b, fl) for sl, n, b, fl in rows}
    first = int(start.timestamp() // secs * secs)
    points = []
    for t in range(first, int(end.timestamp()) + 1, secs):
        n, b, fl = counts.get(t, (0, 0, 0))
        points.append(ActivityPoint(ts=datetime.fromtimestamp(t, UTC), total=n, blocked=b, flagged=fl))
    return CaseActivity(bucket_minutes=minutes, start=start, end=end, points=points)


def _detail(db: Session, case_id: int) -> InvestigationDetail:
    pair = next(((c, i) for c, i in _cases_with_incidents(db) if c.id == case_id), None)
    if pair is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    case, incident = pair
    findings = _findings(db, [incident.id])[incident.id]

    # Risk breakdown: the correlation formula per category, from the findings themselves.
    approved = parse_hosts(get_settings().approved_upload_hosts)
    weights: dict[str, float] = {}
    for f in findings:
        finding = Finding(f.username, f.window_start, f.window_end, f.kind, f.score, f.reason, f.count, f.details)
        category = CATEGORY_OF_KIND.get(f.kind, "behavioral_outlier")
        weights[category] = max(weights.get(category, 0.0), weighted_score(finding, approved))
    ranked = sorted(weights, key=lambda c: -weights[c])
    breakdown = [RiskPart(category=c, label=CATEGORY_LABELS.get(c, c), weight=round(weights[c] * 100),
                          counted=(n == 0 or weights[c] >= CORROBORATION_MIN) and c != "behavioral_outlier")
                 for n, c in enumerate(ranked)]

    summary = db.get(UploadSummary, incident.upload_id)
    written = ((summary.narrative or {}).get("incidents", {}) if summary else {}).get(str(incident.id), {})
    # Per incident (low incidents get template text even when Claude wrote the rest);
    # older analyses only have the document's source.
    source = written.get("source") or ((summary.narrative or {}).get("source") if summary and summary.narrative else None)

    domains = _domains(findings)
    related = ([DetailEntity(type="user", name=incident.username,
                             detail=f"Risk {round(incident.priority_score * 100)} · {_plural(len(findings), 'alert')}")]
               + [DetailEntity(type="device", name=device,
                               detail=" · ".join(filter(None, [os_type, f"used by {incident.username}",
                                                              f"{events:,} events in window"])))
                  for device, os_type, events in _devices(db, incident)]
               + [DetailEntity(type="ip", name=ip, detail=f"used by {incident.username}") for ip in _ips(db, incident)]
               + [DetailEntity(type="domain", name=d, detail=why) for d, why in domains.items()])

    owners = _owners(db)
    notes = db.scalars(select(CaseNote).where(CaseNote.case_id == case.id).order_by(CaseNote.created_at, CaseNote.id))
    return InvestigationDetail(
        **_item(db, case, incident, findings, owners),
        why_flagged=incident.narrative, narrative_source=source if incident.narrative else None,
        next_steps=written.get("next_steps", []),
        # Analyses written before questions existed: derive them from this case's evidence categories.
        next_questions=written.get("next_questions") or [NEXT_QUESTIONS[c] for c in ranked if c in NEXT_QUESTIONS][:3],
        ai_assessment=written.get("assessment") if source == "ai" else None,
        # Older analyses have no searches: the defaults, from this case's evidence.
        searches=written.get("searches") or [s.stored() for s in default_picks(search_menu(
            incident.username, incident.start_ts, incident.end_ts,
            [f.details or {} for f in sorted(findings, key=lambda f: -f.score)]))],
        risk_breakdown=breakdown,
        detection_signals=[Signal(category=p.category, label=p.label, counted=p.counted,
                                  description=SIGNAL_DESCRIPTIONS.get(p.category, "")) for p in breakdown],
        evidence=[EvidenceItem(kind=f.kind, name=KIND_NAMES.get(f.kind, f.kind), reason=f.reason, score=f.score,
                               level=priority_label(f.score), source=f.source,
                               window_start=f.window_start, window_end=f.window_end) for f in findings],
        related_entities=related,
        notes=[NoteOut(id=n.id, author=owners.get(n.author_id) if n.author_id else None, text=n.text,
                       created_at=n.created_at) for n in notes],
        analysts=sorted(owners.values()),
        activity=_activity(db, incident),
    )


# ---------------------------------------------------------------------------------------------
# Workflow: status, owner, verdict, notes
# ---------------------------------------------------------------------------------------------


class CaseUpdate(BaseModel):
    """Only the fields sent are changed; send `"owner": null` / `"verdict": null` to clear them."""

    status: CaseStatus | None = None
    owner: str | None = None  # a username
    verdict: Verdict | None = None
    # The updated_at the analyst saw: if the case changed since, the update is refused (409)
    # instead of silently overwriting someone else's change.
    expected_updated_at: datetime


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=NOTE_MAX_CHARS)


def _locked_case(db: Session, case_id: int) -> Case:
    case = db.scalar(select(Case).where(Case.id == case_id).with_for_update())  # one writer at a time
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return case


@router.patch("/{case_id}")
def update_investigation(case_id: int, change: CaseUpdate, user: CurrentUser,
                         db: Annotated[Session, Depends(get_db)]) -> InvestigationDetail:
    case = _locked_case(db, case_id)
    if case.updated_at != change.expected_updated_at:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Someone else changed this case since you opened it. It has been reloaded; try again.")
    sent = change.model_fields_set
    if "status" in sent and change.status is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Status can't be empty")

    if "owner" in sent:
        if change.owner is None:
            if (change.status or case.status) == "investigating":
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    "A case being investigated needs an owner; set it to Open first")
            case.owner_id = None
        else:
            owner_id = db.scalar(select(User.id).where(User.username == change.owner))
            if owner_id is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown analyst '{change.owner}'")
            case.owner_id = owner_id
    if "verdict" in sent:
        case.verdict = change.verdict
    if change.status is not None:
        case.status = change.status

    # Workflow rules: someone owns what is being investigated; a resolved case says why.
    if case.status == "investigating" and case.owner_id is None:
        case.owner_id = user.id
    if case.status == "resolved" and case.verdict is None:
        db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Choose a verdict (true positive, false positive or benign) to resolve the case")

    case.updated_at = func.now()
    db.commit()
    return _detail(db, case_id)


@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(case_id: int, note: NoteIn, user: CurrentUser,
             db: Annotated[Session, Depends(get_db)]) -> InvestigationDetail:
    """Append-only: notes are never edited or deleted (add a new one to correct one)."""
    text = note.text.strip()
    if not text:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A note can't be empty")
    case = _locked_case(db, case_id)
    db.add(CaseNote(case_id=case.id, author_id=user.id, text=text))
    case.updated_at = func.now()
    db.commit()
    return _detail(db, case_id)
