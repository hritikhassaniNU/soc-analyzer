"""What the LLM is allowed to see: a compact, pseudonymized, cleaned view of the analysis.

- Never raw log lines, never IP addresses, never real usernames (stand-ins: user_1, user_2…, mapped
  back after the reply). Incident ids are stand-ins too (incident_1…), so the reply can only refer
  to incidents we sent.
- Only medium-or-higher incidents (top 10), with their findings' kinds, scores, times and reasons.
- Reasons can contain attacker-controlled text (domains, user agents, threat names): every string is
  cleaned (control and invisible characters removed, whitespace collapsed, < > replaced so the
  prompt's data tags can't be closed from inside), length-capped, and any IPv4 address or real
  username inside it is replaced. The prompt then passes this as JSON DATA (see client.py).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.llm.searches import Search, search_menu

MAX_INCIDENTS = 10
MAX_FINDINGS = 8          # per incident, strongest first
MAX_TEXT = 300            # characters per string field
SENT_PRIORITIES = ("critical", "high", "medium")

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁯]")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class FindingInput:
    kind: str
    source: str
    score: float
    start: datetime
    end: datetime
    reason: str
    details: dict[str, Any] = field(default_factory=dict)  # detector evidence (hosts for searches)


@dataclass(frozen=True)
class IncidentInput:
    id: int
    username: str
    priority: str
    priority_score: float
    title: str
    start: datetime
    end: datetime
    findings: list[FindingInput]


@dataclass
class StandIns:
    """Real name <-> stand-in, both directions. Built while making the payload."""

    users: dict[str, str] = field(default_factory=dict)      # "jdoe" -> "user_1"
    incidents: dict[str, int] = field(default_factory=dict)  # "incident_1" -> 42 (our id)
    # "incident_1" -> "jdoe's critical incident (Tue 22 Sep 14:05 UTC)": what an analyst understands
    incident_labels: dict[str, str] = field(default_factory=dict)
    # "incident_1" -> {"host1": Search(...)}: the searches offered, so a reply can only pick these (D135)
    searches: dict[str, dict[str, Search]] = field(default_factory=dict)

    def user(self, username: str) -> str:
        return self.users.setdefault(username, f"user_{len(self.users) + 1}")

    def restore(self, text: str) -> str:
        """Put real usernames and readable incident labels back into the model's text (only
        stand-ins we issued; anything else is left as written)."""
        text = re.sub(r"\bincident_\d+\b", lambda m: self.incident_labels.get(m.group(0), m.group(0)), text)
        real = {stand_in: name for name, stand_in in self.users.items()}
        return re.sub(r"\buser_\d+\b", lambda m: real.get(m.group(0), m.group(0)), text)


def clean(text: str, stand_ins: StandIns, limit: int = MAX_TEXT) -> str:
    """Make log-derived text inert and private: no control/invisible characters, single line,
    no IPs, no real usernames, bounded length."""
    text = _CONTROL.sub(" ", text)
    text = text.replace("<", "‹").replace(">", "›")  # can't forge the prompt's <analysis_data> tags
    text = _IPV4.sub("[ip]", text)
    for name, stand_in in sorted(stand_ins.users.items(), key=lambda kv: -len(kv[0])):
        text = re.sub(rf"\b{re.escape(name)}\b", stand_in, text, flags=re.IGNORECASE)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="minutes")


def incident_menu(incident: IncidentInput) -> list[Search]:
    """The case's next-step searches (the strongest finding's hosts first)."""
    return search_menu(incident.username, incident.start, incident.end,
                       [f.details for f in sorted(incident.findings, key=lambda f: -f.score)])


def build_payload(stats: dict[str, Any], incidents: list[IncidentInput],
                  overview: dict[str, Any] | None = None, triage: bool = False) -> tuple[dict[str, Any], StandIns]:
    """The JSON the model sees, plus the stand-in map to translate its reply back. `triage` adds each
    incident's menu of searches (D135), so the model can pick next steps only from it."""
    stand_ins = StandIns()
    shown = sorted((i for i in incidents if i.priority in SENT_PRIORITIES),
                   key=lambda i: -i.priority_score)[:MAX_INCIDENTS]
    for incident in shown:  # register every user first, so reasons mentioning them get replaced
        stand_ins.user(incident.username)

    counts = {p: sum(i.priority == p for i in incidents) for p in ("critical", "high", "medium", "low")}
    if overview is None:  # one upload's numbers
        overview = {
            "events": stats.get("total_events"),
            "users": stats.get("unique_users"),
            "first_event": stats.get("first_event"),
            "last_event": stats.get("last_event"),
            "blocked": stats.get("blocked"),
        }
        section = "upload"
    else:  # e.g. the company-wide review: its own, accurately named section
        section = "overview"
    payload: dict[str, Any] = {section: {**overview, "incidents_by_priority": counts}, "incidents": []}
    for n, incident in enumerate(shown, start=1):
        key = f"incident_{n}"
        stand_ins.incidents[key] = incident.id
        stand_ins.incident_labels[key] = (f"{stand_ins.user(incident.username)}'s {incident.priority} incident "
                                          f"({incident.start:%a %d %b %H:%M} UTC)")  # user_N restored after
        findings = sorted(incident.findings, key=lambda f: -f.score)[:MAX_FINDINGS]
        payload["incidents"].append({
            "id": key,
            "user": stand_ins.user(incident.username),
            "priority": incident.priority,
            "priority_score": round(incident.priority_score, 2),
            "title": clean(incident.title, stand_ins),
            "start": _iso(incident.start),
            "end": _iso(incident.end),
            "findings": [
                {"kind": f.kind, "source": f.source, "score": round(f.score, 2),
                 "start": _iso(f.start), "end": _iso(f.end), "reason": clean(f.reason, stand_ins)}
                for f in sorted(findings, key=lambda f: f.start)
            ],
        })
        if triage:
            menu = incident_menu(incident)
            stand_ins.searches[key] = {s.id: s for s in menu}
            # Labels name hosts (attacker-controlled) and users: cleaned like every other string.
            payload["incidents"][-1]["searches"] = [{"id": s.id, "what": clean(s.label, stand_ins)} for s in menu]
    return payload, stand_ins
