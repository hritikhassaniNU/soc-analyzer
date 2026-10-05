"""Detection Rules: the detector catalog with live hit counts, how risk is scored, MITRE coverage,
and analysts' on/off switches (new scans only; who and when is recorded)."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.dashboard import unique_incidents
from app.auth import CurrentUser
from app.config import get_settings
from app.db import get_db
from app.detection import catalog
from app.detection.correlate import (
    APPROVED_STORAGE_WEIGHT,
    CATEGORY_LABELS,
    CHAIN_GAP,
    CORROBORATION_BONUS,
    CORROBORATION_MIN,
    PRIORITY_CUTOFFS,
    SEVERITY,
    parse_hosts,
)
from app.models import Anomaly, DetectorSetting, User

router = APIRouter(prefix="/api/rules", tags=["rules"])

# The 14 ATT&CK Enterprise tactics in matrix order (for the coverage grid).
TACTICS = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)
assert all(t.tactic in TACTICS for d in catalog.DETECTORS for t in d.techniques)


class TechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    url: str
    approximate: bool
    supports: bool


class DetectorOut(BaseModel):
    kind: str
    name: str
    layer: Literal["rule", "stat", "ml", "ai"]
    category: str
    category_label: str
    weight: float  # the category's severity in the risk formula
    summary: str
    logic: list[str]
    false_positives: list[str]
    tuning: str
    techniques: list[TechniqueOut]
    enabled: bool
    changed_by: str | None  # who last switched it (None: never switched, or account deleted)
    changed_at: datetime | None
    hits: int  # findings company-wide (each unique incident counted once, like the dashboard)
    cases: int  # cases with at least one such finding
    last_seen: datetime | None  # end of the latest such finding


class CategoryWeight(BaseModel):
    category: str
    label: str
    weight: float


class Cutoff(BaseModel):
    priority: str
    min_score: float


class Scoring(BaseModel):
    weights: list[CategoryWeight]
    corroboration_bonus: float
    corroboration_min: float
    chain_hours: int
    cutoffs: list[Cutoff]
    approved_hosts: list[str]
    approved_weight: float


class RulesCatalog(BaseModel):
    detectors: list[DetectorOut]
    scoring: Scoring
    tactics: list[str]
    blind_spots: list[str]


class DetectorSwitch(BaseModel):
    enabled: bool


def _detectors(db: Session) -> list[DetectorOut]:
    ids = [i.id for i in unique_incidents(db)]
    usage = {kind: (hits, cases, last) for kind, hits, cases, last in db.execute(
        select(Anomaly.kind, func.count(), func.count(Anomaly.incident_id.distinct()), func.max(Anomaly.window_end))
        .where(Anomaly.incident_id.in_(ids)).group_by(Anomaly.kind)
    )} if ids else {}
    settings = {s.kind: s for s in db.scalars(select(DetectorSetting))}
    names = {u.id: u.username for u in db.scalars(select(User))}

    out = []
    for d in catalog.DETECTORS:
        setting = settings.get(d.kind)
        hits, cases, last = usage.get(d.kind, (0, 0, None))
        out.append(DetectorOut(
            kind=d.kind, name=d.name, layer=d.layer, category=d.category,
            category_label=CATEGORY_LABELS[d.category], weight=d.severity, summary=d.summary, logic=d.logic,
            false_positives=d.false_positives, tuning=d.tuning,
            techniques=[TechniqueOut(id=t.id, name=t.name, tactic=t.tactic, url=t.url, approximate=t.approximate,
                                     supports=t.supports) for t in d.techniques],
            enabled=setting.enabled if setting else True,
            changed_by=names.get(setting.changed_by) if setting and setting.changed_by else None,
            changed_at=setting.changed_at if setting else None,
            hits=hits, cases=cases, last_seen=last,
        ))
    return out


@router.get("")
def get_rules(user: CurrentUser, db: Annotated[Session, Depends(get_db)]) -> RulesCatalog:
    return RulesCatalog(
        detectors=_detectors(db),
        scoring=Scoring(
            weights=[CategoryWeight(category=c, label=CATEGORY_LABELS[c], weight=w) for c, w in SEVERITY.items()],
            corroboration_bonus=CORROBORATION_BONUS, corroboration_min=CORROBORATION_MIN,
            chain_hours=int(CHAIN_GAP.total_seconds() // 3600),
            cutoffs=[Cutoff(priority=label, min_score=cut) for cut, label in PRIORITY_CUTOFFS],
            approved_hosts=sorted(parse_hosts(get_settings().approved_upload_hosts)),
            approved_weight=APPROVED_STORAGE_WEIGHT,
        ),
        tactics=list(TACTICS),
        blind_spots=list(catalog.BLIND_SPOTS),
    )


@router.put("/{kind}")
def switch_detector(kind: str, switch: DetectorSwitch, user: CurrentUser,
                    db: Annotated[Session, Depends(get_db)]) -> DetectorOut:
    """Switch a detector on or off for NEW scans (existing results are kept as they were scanned)."""
    if kind not in catalog.KINDS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown detector")
    statement = insert(DetectorSetting).values(kind=kind, enabled=switch.enabled, changed_by=user.id)
    db.execute(statement.on_conflict_do_update(
        index_elements=[DetectorSetting.kind],
        set_={"enabled": statement.excluded.enabled, "changed_by": statement.excluded.changed_by,
              "changed_at": func.now()},
    ))
    db.commit()
    return next(d for d in _detectors(db) if d.kind == kind)
