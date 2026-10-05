"""Correlation: a user's findings close together in time become one incident, ranked by priority.

Detectors judge one kind of evidence each; ranking PEOPLE needs corroboration. A legitimate big
upload stands alone; a compromised user shows several independent kinds of evidence in a short
time (jdoe: executable download -> beaconing -> off-hours).

- Grouping: per user, findings chain into one incident while each starts within 24 h of the
  incident so far. jdoe's Tuesday and Sunday stories (4 days apart) stay separate, so the bonus
  only counts evidence that is close in time.
- priority_score = min(1, strongest severity-weighted score + 0.1 x each OTHER category that is
  itself meaningful: weighted score >= 0.4). Without that minimum, two weak benign signals backed
  each other up (a developer's curl + a legit Drive upload -> "medium" on a clean file), and a
  0.18 Windows update inflated a real incident. Weak findings stay attached as evidence.
  Severity says how much a kind of evidence matters on its own: a request burst at 0.99 is still
  "a script ran fast", not a breach. Categories, not kinds, earn the bonus, so two findings that
  measure the same thing (two off-hours episodes) don't corroborate each other.
- Large uploads to approved company storage are weighted x0.4: down-ranked, never hidden.
- A ranking signal, not a probability (see docs/DECISIONS.md).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.detection.findings import Finding

CATEGORY_OF_KIND = {
    "zscaler_threat": "known_threat",
    "high_risk_allowed": "known_threat",
    "beaconing": "command_and_control",
    "rare_domain": "command_and_control",
    "large_upload": "large_upload",
    "executable_download": "executable_download",
    "scripted_client": "automated_traffic",
    "request_burst": "automated_traffic",
    "off_hours": "unusual_hours",
    "behavioral_outlier": "behavioral_outlier",  # ML: attached as evidence only (see run.py)
    "ai_suspicious_domain": "suspicious_domain",  # the Claude domain classifier (D136)
}
SEVERITY = {
    "known_threat": 1.0,
    "command_and_control": 1.0,
    "large_upload": 1.0,
    "executable_download": 0.9,
    "automated_traffic": 0.6,
    "unusual_hours": 0.6,
    "behavioral_outlier": 0.4,
    # Low (user's choice, D136): an AI opinion corroborates other evidence but rarely raises a case alone.
    "suspicious_domain": 0.6,
}
# Except a brand look-alike (phishing), weighted like an executable download (D137): alone at high
# confidence 0.7 x 0.9 = 0.63, a medium case that gets the full analysis instead of a hidden low one.
BRAND_LOOKALIKE_SEVERITY = 0.9
# Neutral wording: titles describe what was seen, not intent (a legit upload is not "exfiltration").
CATEGORY_LABELS = {
    "known_threat": "known threat",
    "command_and_control": "command & control",
    "large_upload": "large upload",
    "executable_download": "executable download",
    "automated_traffic": "automated traffic",
    "unusual_hours": "unusual hours",
    "behavioral_outlier": "unusual combination (ML)",
    "suspicious_domain": "suspicious domain (AI)",
}
CHAIN_GAP = timedelta(hours=24)
CORROBORATION_BONUS = 0.1
CORROBORATION_MIN = 0.4  # a category must be nearly 'medium' on its own to corroborate
APPROVED_STORAGE_WEIGHT = 0.4
PRIORITY_CUTOFFS = ((0.95, "critical"), (0.75, "high"), (0.45, "medium"))  # else "low"


@dataclass(frozen=True)
class IncidentDraft:
    username: str
    start: datetime  # first finding's start
    end: datetime    # last finding's end
    title: str
    priority_score: float
    priority: str
    categories: list[str]  # every category present, strongest first
    members: list[int]     # indexes into the findings passed to correlate()


def parse_hosts(setting: str) -> frozenset[str]:
    """"a.com, B.com" -> {"a.com", "b.com"}."""
    return frozenset(h.strip().lower() for h in setting.split(",") if h.strip())


def is_approved(host: str | None, approved: frozenset[str]) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in approved)


def weighted_score(finding: Finding, approved_hosts: frozenset[str]) -> float:
    """The finding's score x the severity of its category (x0.4 for approved storage uploads;
    a brand look-alike domain counts like delivery, 0.9: D137)."""
    weight = SEVERITY[CATEGORY_OF_KIND[finding.kind]]
    if finding.kind == "ai_suspicious_domain" and finding.details.get("label") == "brand_lookalike":
        weight = BRAND_LOOKALIKE_SEVERITY
    if finding.kind == "large_upload" and is_approved(finding.details.get("top_host"), approved_hosts):
        weight *= APPROVED_STORAGE_WEIGHT
    return finding.score * weight


def priority_label(score: float) -> str:
    return next((label for cutoff, label in PRIORITY_CUTOFFS if score >= cutoff), "low")


def _draft(findings: Sequence[Finding], members: list[int], approved: frozenset[str]) -> IncidentDraft:
    strongest: dict[str, float] = {}  # category -> its best weighted score in this incident
    for i in members:
        category = CATEGORY_OF_KIND[findings[i].kind]
        strongest[category] = max(strongest.get(category, 0.0), weighted_score(findings[i], approved))
    categories = sorted(strongest, key=lambda c: (-strongest[c], c))
    counted = [categories[0]] + [c for c in categories[1:] if strongest[c] >= CORROBORATION_MIN]
    score = min(1.0, strongest[categories[0]] + CORROBORATION_BONUS * (len(counted) - 1))
    title = ", ".join(CATEGORY_LABELS[c] for c in counted)  # what drives the priority
    return IncidentDraft(
        username=findings[members[0]].username,
        start=min(findings[i].window_start for i in members),
        end=max(findings[i].window_end for i in members),
        title=title[0].upper() + title[1:],
        priority_score=round(score, 3), priority=priority_label(round(score, 3)),
        categories=categories, members=members,
    )


def correlate(findings: Sequence[Finding], approved_hosts: frozenset[str] = frozenset()) -> list[IncidentDraft]:
    """Group findings into incidents (every finding ends up in exactly one), worst first."""
    order = sorted(range(len(findings)), key=lambda i: (findings[i].username, findings[i].window_start))
    chains: list[list[int]] = []
    chain_end = None
    for i in order:
        f = findings[i]
        same_user = chains and findings[chains[-1][0]].username == f.username
        if same_user and f.window_start - chain_end <= CHAIN_GAP:
            chains[-1].append(i)
            chain_end = max(chain_end, f.window_end)
        else:
            chains.append([i])
            chain_end = f.window_end
    drafts = [_draft(findings, chain, approved_hosts) for chain in chains]
    return sorted(drafts, key=lambda d: (-d.priority_score, d.start, d.username))
