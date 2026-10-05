"""Our documented Zscaler web log CSV layout: the single source of truth for column order.

Zscaler NSS lets admins choose which fields a feed contains and in what order, so there is
no single "Zscaler CSV". This is OUR feed layout. Column names are modeled on NSS web log
variables (shown in comments); the parser, the sample-log generator and the README all use it.
"""

CSV_COLUMNS: tuple[str, ...] = (
    "time",              # %s{time}       when the request happened
    "user",              # %s{login}      who
    "department",        # %s{dept}
    "location",          # %s{location}
    "client_ip",         # %s{cip}        which device
    "server_ip",         # %s{sip}        destination server
    "protocol",          # %s{proto}      HTTP / HTTPS
    "method",            # %s{reqmethod}  GET / POST / ...
    "url",               # %s{url}        destination (host is derived from it)
    "action",            # %s{action}     Allowed / Blocked
    "url_category",      # %s{urlcat}
    "app_name",          # %s{appname}
    "threat_name",       # %s{threatname} "None" when no threat
    "malware_category",  # %s{malwarecat}
    "risk_score",        # %d{riskscore}  0-100
    "status_code",       # %s{respcode}
    "bytes_sent",        # %d{reqsize}    client -> internet (exfiltration signal)
    "bytes_received",    # %d{respsize}   internet -> client
    "user_agent",        # %s{ua}
    "file_type",         # %s{filetype}
    # Added later, so appended: older 20-column files without them still parse (see LEGACY_WIDTH).
    # Only filled when traffic comes through Zscaler Client Connector (empty for GRE/IPsec/PAC).
    "device",            # device hostname
    "device_os",         # device OS type, e.g. Windows / macOS
)

# Headerless CSV written before the device columns existed.
LEGACY_WIDTH = 20

# A line missing any of these is rejected as a bad line; all other columns may be empty.
REQUIRED_COLUMNS: frozenset[str] = frozenset(
    {"time", "user", "client_ip", "url", "action", "risk_score", "bytes_sent", "bytes_received"}
)

# Other names accepted for each field (case-insensitive), in CSV headers and JSON keys.
# Zscaler NSS lets admins name fields in each feed's template, so no list covers every feed; these
# are the NSS variable names (login, reqsize…) and the keys of Zscaler's common JSON feed for
# Splunk (records nested under "event": datetime, requestsize, useragent…).
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "time": ("datetime", "timestamp"),
    "user": ("login", "username"),
    "department": ("dept",),
    "location": (),
    "client_ip": ("cip", "clientip"),
    "server_ip": ("sip", "serverip"),
    "protocol": ("proto",),
    "method": ("reqmethod", "requestmethod"),
    "url": (),
    "action": (),
    "url_category": ("urlcat", "urlcategory"),
    "app_name": ("appname",),
    "threat_name": ("threatname",),
    "malware_category": ("malwarecat", "threatcategory"),
    "risk_score": ("riskscore", "pagerisk"),
    "status_code": ("respcode", "status"),
    "bytes_sent": ("reqsize", "requestsize"),
    "bytes_received": ("respsize", "responsesize"),
    "user_agent": ("ua", "useragent"),
    "file_type": ("filetype",),
    # Client Connector device fields; names as we understand NSS (verify against the feed template).
    "device": ("devicehostname", "devicename"),
    "device_os": ("deviceostype", "deviceos"),
}
assert set(FIELD_ALIASES) == set(CSV_COLUMNS)

_CANONICAL = {name: name for name in CSV_COLUMNS} | {
    alias: name for name, aliases in FIELD_ALIASES.items() for alias in aliases
}


def canonical_name(key: str) -> str | None:
    """Our field name for a CSV header cell or JSON key ("Login" -> "user"), or None if unknown."""
    return _CANONICAL.get(key.strip().lower())
