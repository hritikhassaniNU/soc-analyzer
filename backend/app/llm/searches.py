"""Next-step searches for a case: ready-made Logs filters built from the evidence.

The backend builds the menu; the AI may only pick entries by id and label them, so it can never
invent a filter (a prompt-injected answer can at worst choose a less useful search). Without an
API key, or if the answer picks nothing valid, DEFAULT_PICKS are used.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from app.detection.findings import hosts_in

MAX_DOMAINS = 3   # per-domain searches offered
MAX_PICKS = 3
BEFORE = timedelta(hours=24)


@dataclass(frozen=True)
class Search:
    """One Logs search. Times are UTC, start inclusive and end exclusive (the events API)."""
    id: str
    label: str
    username: str | None = None
    host: str | None = None
    action: str | None = None
    anomalous: bool = False
    start: datetime | None = None
    end: datetime | None = None

    def stored(self, label: str | None = None) -> dict[str, Any]:
        """JSON for the narrative document (and the API), optionally relabeled by the AI."""
        data = asdict(self) | {"label": label or self.label}
        for key in ("start", "end"):
            data[key] = data[key].isoformat() if data[key] else None
        return data


def _minute_floor(t: datetime) -> datetime:
    return t.replace(second=0, microsecond=0)


def _minute_ceil(t: datetime) -> datetime:
    return _minute_floor(t) + timedelta(minutes=1)  # end is exclusive: include the last event


def search_menu(username: str, start: datetime, end: datetime, details: list[dict[str, Any]]) -> list[Search]:
    """Every search worth offering for one case, most generally useful first. `details` are the
    findings' details (strongest finding first), where detectors store the hosts involved."""
    lo, hi = _minute_floor(start), _minute_ceil(end)
    hosts: list[str] = []
    for d in details:
        for h in sorted(hosts_in(d)):
            if h not in hosts:
                hosts.append(h)
    menu = [Search("flagged", f"{username}'s flagged events in the window", username=username,
                   anomalous=True, start=lo, end=hi)]
    for n, host in enumerate(hosts[:MAX_DOMAINS], start=1):
        menu.append(Search(f"host{n}", f"{username} → {host} in the window", username=username, host=host,
                           start=lo, end=hi))
    if hosts:
        # Blast radius: anyone else who reached the strongest destination, any time in the dataset.
        menu.append(Search("everyone_host1", f"Everyone who contacted {hosts[0]}", host=hosts[0]))
    menu += [
        Search("blocked", f"{username}'s blocked requests in the window", username=username, action="Blocked",
               start=lo, end=hi),
        Search("before", f"{username}'s activity in the 24 h before", username=username, start=lo - BEFORE, end=lo),
        Search("all", f"All of {username}'s events in the window", username=username, start=lo, end=hi),
    ]
    return menu


def default_picks(menu: list[Search]) -> list[Search]:
    """Without the AI: flagged events, the strongest destination, then its blast radius (or the
    blocked requests when no destination is involved)."""
    order = ["flagged", "host1", "everyone_host1", "blocked", "before", "all"]
    by_id = {s.id: s for s in menu}
    return [by_id[i] for i in order if i in by_id][:MAX_PICKS]
