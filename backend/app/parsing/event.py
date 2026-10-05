"""The parsed, typed form of one log line."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

Action = Literal["Allowed", "Blocked"]


# slots: no per-object __dict__ (less memory across millions of events).
# frozen: an event is a fact from the log; nothing should modify it after parsing.
@dataclass(slots=True, frozen=True)
class ZscalerEvent:
    line_no: int          # 1-based line number in the uploaded file; with upload_id, the event's key
    ts: datetime          # always timezone-aware UTC
    username: str         # lowercased
    client_ip: str
    url: str
    host: str | None      # derived from url
    action: Action
    risk_score: int       # 0-100
    bytes_out: int        # bytes_sent (client -> internet)
    bytes_in: int         # bytes_received (internet -> client)
    department: str | None = None
    location: str | None = None
    server_ip: str | None = None
    protocol: str | None = None
    method: str | None = None
    category: str | None = None
    app_name: str | None = None
    threat: str | None = None  # None when Zscaler reported no threat
    malware_category: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    file_type: str | None = None
    device: str | None = None     # hostname (Client Connector only)
    device_os: str | None = None


def derive_host(url: str) -> str | None:
    """Hostname from a Zscaler URL, which usually has no scheme ("mega.nz/upload?x=1").

    Lowercased, without port or userinfo; IPv6 brackets removed. None if there is no host.
    """
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "//" + url  # tells urlsplit that what follows is the network location
    try:
        return urlsplit(url).hostname  # already lowercased, port/userinfo stripped
    except ValueError:  # e.g. malformed IPv6 "[::1"
        return None
