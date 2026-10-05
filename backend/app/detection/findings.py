"""The common output of every detector: one finding about one user over a time window.
Pass 2 stores findings as `anomalies` rows (same fields)."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Finding:
    username: str
    window_start: datetime  # first and last event of the episode (UTC)
    window_end: datetime
    kind: str
    score: float  # 0..1 ranking signal, not a probability
    reason: str  # human-readable explanation
    count: int  # events in the episode
    details: dict[str, Any] = field(default_factory=dict)


def hosts_in(details: dict[str, Any]) -> set[str]:
    """Destinations named in a finding's evidence (each detector stores them under its own key)."""
    hosts = set(details.get("hosts") or {})        # grouped rule hits: {host: count}
    hosts.update(details.get("domains") or [])      # rare domains
    for key in ("host", "top_host"):                # beaconing, large upload
        if details.get(key):
            hosts.add(details[key])
    return {h for h in hosts if isinstance(h, str)}


def describe_duration(seconds: float) -> str:
    """'45 seconds', '4 minutes', '8 h 5 min' - for reason texts."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        minutes = round(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours, minutes = divmod(round(seconds / 60), 60)
    return f"{hours} h {minutes} min"
