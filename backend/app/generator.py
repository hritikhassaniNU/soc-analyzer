"""Generate realistic synthetic Zscaler web proxy logs with planted attacks and an answer key.

    uv run python -m app.generator --out ../samples/zscaler_sample.csv            # attacks planted
    uv run python -m app.generator --out ../samples/zscaler_clean.csv --clean     # no attacks
    uv run python -m app.generator --out big.csv --target-mb 500                  # scale testing

Writes our documented CSV layout (app.parsing.fields) and, next to it, `<name>.truth.json`
listing every planted attack (kind, user, time window, line numbers). Detection tests use it
as ground truth. Same seed + same options = byte-identical output.

Synthetic data is not real traffic: it is good for proving the pipeline and detectors find
what we planted, not for claiming real-world accuracy.
"""

import argparse
import csv
import json
import random
import string
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TextIO

from app.parsing.fields import CSV_COLUMNS

_JSON_NUMBERS = {"risk_score", "status_code", "bytes_sent", "bytes_received"}  # numbers, not strings, in JSON

# ---------------------------------------------------------------------------------------------
# The world: domains, users
# ---------------------------------------------------------------------------------------------

BLOCKED_CATEGORIES = {"Gambling", "Proxy Avoidance", "Adult Material"}

# (host, category, app_name, typical response size range in bytes)
KNOWN_DOMAINS: list[tuple[str, str, str, tuple[int, int]]] = [
    ("www.google.com", "Web Search", "Google Search", (20_000, 120_000)),
    ("mail.google.com", "Web-based Email", "Gmail", (30_000, 300_000)),
    ("outlook.office365.com", "Web-based Email", "Outlook", (30_000, 400_000)),
    ("teams.microsoft.com", "Professional Services", "Microsoft Teams", (10_000, 200_000)),
    ("acme.sharepoint.com", "Business and Economy", "SharePoint", (50_000, 2_000_000)),
    ("acme.atlassian.net", "Professional Services", "Jira", (40_000, 600_000)),
    ("github.com", "Professional Services", "GitHub", (30_000, 800_000)),
    ("slack.com", "Professional Services", "Slack", (5_000, 150_000)),
    ("zoom.us", "Professional Services", "Zoom", (10_000, 300_000)),
    ("www.salesforce.com", "Business and Economy", "Salesforce", (40_000, 900_000)),
    ("www.linkedin.com", "Social Networking", "LinkedIn", (50_000, 700_000)),
    ("www.facebook.com", "Social Networking", "Facebook", (50_000, 900_000)),
    ("x.com", "Social Networking", "X", (40_000, 700_000)),
    ("www.youtube.com", "Streaming Media", "YouTube", (200_000, 8_000_000)),
    ("open.spotify.com", "Streaming Media", "Spotify", (100_000, 4_000_000)),
    ("www.nytimes.com", "News and Media", "", (80_000, 900_000)),
    ("www.bbc.com", "News and Media", "", (80_000, 900_000)),
    ("www.reuters.com", "News and Media", "", (60_000, 700_000)),
    ("www.amazon.com", "Online Shopping", "Amazon", (80_000, 1_500_000)),
    ("www.dropbox.com", "File Sharing", "Dropbox", (20_000, 3_000_000)),
    ("drive.google.com", "File Sharing", "Google Drive", (20_000, 3_000_000)),
    ("update.microsoft.com", "Software Updates", "Windows Update", (100_000, 20_000_000)),
    ("stackoverflow.com", "Professional Services", "", (40_000, 400_000)),
    ("www.wikipedia.org", "Reference", "", (30_000, 300_000)),
    ("www.bet365.com", "Gambling", "", (20_000, 200_000)),
    ("free-vpn-proxy.net", "Proxy Avoidance", "", (5_000, 50_000)),
]
WORDS = ["cloud", "data", "smart", "global", "market", "tech", "health", "travel", "finance",
         "secure", "green", "digital", "prime", "metro", "nova", "apex", "blue", "bright"]
# Made-up domains get a category that matches their name (like Zscaler categorizing a real site):
# the first word with a meaning decides; names with no meaningful word default to business.
WORD_CATEGORIES = {
    "health": "Health", "travel": "Travel", "finance": "Finance", "market": "Finance",
    "tech": "Information Technology", "data": "Information Technology",
    "cloud": "Information Technology", "digital": "Information Technology",
    "secure": "Information Technology",
}
DEFAULT_CATEGORY = "Business and Economy"


def category_for_host(host: str) -> str:
    """'novahealth.co' -> 'Health'; 'travelglobal.io' -> 'Travel'; 'novaapex.com' -> default."""
    name = host.split(".")[0]
    hits = sorted((name.find(word), category) for word, category in WORD_CATEGORIES.items() if word in name)
    return hits[0][1] if hits else DEFAULT_CATEGORY

DEPARTMENTS = {"Finance": "NYC-HQ", "Engineering": "SF-Office", "Sales": "NYC-HQ",
               "HR": "London", "Marketing": "London", "IT": "SF-Office"}
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "morgan", "riley", "jamie", "drew", "quinn",
         "avery", "logan", "harper", "rowan", "emery", "parker", "reese", "skyler", "dakota", "kai"]
LAST = ["garcia", "nguyen", "smith", "brown", "lee", "wilson", "martin", "clark", "lewis",
        "walker", "young", "king", "wright", "lopez", "hill", "scott", "green", "adams", "baker"]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0",
]
PATHS = ["/", "/index.html", "/search?q=report", "/api/v1/items", "/news/latest", "/login",
         "/dashboard", "/docs/view?id=4821", "/assets/app.js", "/static/style.css"]

# Users with a role in the planted attacks (fixed names so the answer key is readable).
STORY_USER = "jdoe"          # the compromised-user story
THREAT_USER = "amiller"      # Zscaler-flagged threat
HIGH_RISK_USER = "kchen"     # high-risk site that was allowed
BURST_USER = "bsmith"        # request burst
RARE_DOMAIN_USER = "rpatel"  # random-looking (DGA-style) domains
PLANT_USERS = [STORY_USER, THREAT_USER, HIGH_RISK_USER, BURST_USER, RARE_DOMAIN_USER]


@dataclass
class Domain:
    host: str
    category: str
    app: str
    size_range: tuple[int, int]
    server_ip: str


@dataclass
class User:
    username: str
    department: str
    location: str
    client_ip: str
    user_agent: str
    work_start: float  # hour of day (UTC) the user usually starts
    favorites: list[Domain]
    devices: list[str] = field(default_factory=list)  # laptop hostnames; empty = no Client Connector
    device_os: str = ""


# ---------------------------------------------------------------------------------------------
# Output rows and the answer key
# ---------------------------------------------------------------------------------------------


@dataclass
class Plant:
    """One planted attack in the answer key."""

    kind: str
    username: str
    start: str
    end: str
    description: str
    line_nos: list[int] = field(default_factory=list)


@dataclass
class Row:
    ts: datetime
    values: dict[str, str]
    plant: Plant | None = None  # set if this row belongs to a planted attack


@dataclass
class GeneratorConfig:
    days: int = 7
    users: int = 30
    seed: int = 42
    start: date = date(2026, 9, 21)  # a Monday
    clean: bool = False
    time_format: str = "iso"         # "iso" or "nss"
    header: bool = False             # CSV only
    log_format: str = "csv"          # "csv" or "json" (JSON lines, same field names)
    target_mb: float | None = None   # keep adding days until the file reaches this size


class Generator:
    def __init__(self, config: GeneratorConfig) -> None:
        if not config.clean and config.days < 7:
            raise ValueError("Planted attacks need at least 7 days (use --clean for fewer)")
        self.config = config
        self.rng = random.Random(config.seed)  # main randomness source: reproducible output
        # Devices use their own stream (same seed), so adding them didn't change any other value.
        self.device_rng = random.Random(f"devices-{config.seed}")
        # The AI-detector plants too: every row that existed before is byte-identical.
        self.ai_rng = random.Random(f"ai-plants-{config.seed}")
        self.domains = self._make_domains()
        self.weights = [1 / (rank + 1) for rank in range(len(self.domains))]  # Zipf-like popularity
        self.users = self._make_users()
        self._assign_devices()
        self.plants: list[Plant] = []
        # Innocent look-alikes ("hard negatives"): suspicious-looking but benign. Present in clean
        # mode too, so the false-positive check is meaningful. One answer-key entry per kind.
        self.benign: dict[str, Plant] = {}
        others = [u for u in self.users if u.username not in PLANT_USERS]
        self.dev_user = next((u for u in others if u.department == "Engineering"), others[0])
        self.evening_users = [u for u in others if u is not self.dev_user][:2]
        for user in self.evening_users:
            user.work_start = self.rng.uniform(13.0, 14.0)  # works until ~22:00 UTC: their normal

    # ---- world building ----

    def _ip(self) -> str:
        return f"{self.rng.randint(23, 223)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def _make_domains(self) -> list[Domain]:
        domains = [Domain(h, c, a, s, self._ip()) for h, c, a, s in KNOWN_DOMAINS]
        while len(domains) < 300:
            host = f"{self.rng.choice(WORDS)}{self.rng.choice(WORDS)}.{self.rng.choice(['com', 'io', 'net', 'co'])}"
            if all(d.host != host for d in domains):
                domains.append(Domain(host, category_for_host(host), "", (10_000, 600_000), self._ip()))
        return domains

    def _make_users(self) -> list[User]:
        names = list(PLANT_USERS)
        while len(names) < max(self.config.users, len(PLANT_USERS)):
            name = self.rng.choice(FIRST)[0] + self.rng.choice(LAST)
            if name not in names:
                names.append(name)
        users = []
        for i, name in enumerate(names):
            department = self.rng.choice(list(DEPARTMENTS))
            popular = self.rng.choices(self.domains, weights=self.weights, k=15)
            allowed = [d for d in popular if d.category not in BLOCKED_CATEGORIES] or popular
            users.append(User(
                username=name, department=department, location=DEPARTMENTS[department],
                client_ip=f"10.{list(DEPARTMENTS).index(department) + 1}.{i // 250}.{i % 250 + 2}",
                user_agent=self.rng.choice(BROWSER_UAS),
                work_start=self.rng.uniform(7.5, 9.5),
                favorites=allowed,
            ))
        return users

    def _assign_devices(self) -> None:
        """1 laptop per user, ~20% with a second one; ~15% have none (traffic not through Client
        Connector: GRE/IPsec/PAC, so NSS has no device fields). OS follows the browser."""
        rng = self.device_rng
        for user in self.users:
            if rng.random() < 0.15:
                continue
            count = 2 if rng.random() < 0.2 else 1
            user.devices = [f"LT-{user.username.upper()}-{n:02d}" for n in range(1, count + 1)]
            user.device_os = "macOS" if "Macintosh" in user.user_agent else "Windows"

    # ---- one request ----

    def _row(self, user: User, ts: datetime, domain: Domain, rng: random.Random | None = None,
             **overrides: object) -> Row:
        rng = rng or self.rng
        method = "POST" if rng.random() < 0.08 else "GET"
        blocked = domain.category in BLOCKED_CATEGORIES
        values = {
            "user": user.username, "department": user.department, "location": user.location,
            "client_ip": user.client_ip, "server_ip": domain.server_ip,
            "protocol": "HTTPS", "method": method,
            "url": domain.host + rng.choice(PATHS),
            "action": "Blocked" if blocked else "Allowed",
            "url_category": domain.category, "app_name": domain.app,
            "threat_name": "None", "malware_category": "",
            "risk_score": rng.randint(0, 25),
            "status_code": 403 if blocked else rng.choices([200, 304, 404], weights=[90, 7, 3])[0],
            "bytes_sent": rng.randint(400, 2_500) if method == "GET" else rng.randint(2_000, 60_000),
            "bytes_received": 0 if blocked else rng.randint(*domain.size_range),
            "user_agent": user.user_agent, "file_type": "",
            # Given device: don't draw from device_rng (the AI plants must not shift later devices).
            "device": overrides.pop("device") if "device" in overrides else self._device(user),
            "device_os": user.device_os,
        }
        plant = overrides.pop("plant", None)
        values.update({k: v for k, v in overrides.items()})
        return Row(ts=ts, values={k: str(v) for k, v in values.items()}, plant=plant)  # type: ignore[arg-type]

    def _device(self, user: User) -> str:
        if len(user.devices) > 1 and self.device_rng.random() < 0.25:
            return user.devices[1]  # the second laptop, used now and then
        return user.devices[0] if user.devices else ""

    def _pick_domain(self, user: User) -> Domain:
        if self.rng.random() < 0.7:
            return self.rng.choice(user.favorites)
        return self.rng.choices(self.domains, weights=self.weights)[0]

    # ---- a normal day ----

    def _normal_day(self, day: date) -> list[Row]:
        rows: list[Row] = []
        weekend = day.weekday() >= 5
        for user in self.users:
            if weekend and self.rng.random() > 0.08:
                continue  # most people don't work weekends
            sessions = self.rng.randint(1, 2) if weekend else self.rng.randint(4, 8)
            for _ in range(sessions):
                start_hour = (self.rng.uniform(10, 16) if weekend
                              else self.rng.uniform(user.work_start, user.work_start + 8.5))
                ts = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(hours=start_hour)
                domain = self._pick_domain(user)
                for _ in range(self.rng.randint(4, 30)):  # a browsing session
                    rows.append(self._row(user, ts, domain))
                    ts += timedelta(seconds=self.rng.uniform(1, 40))
                    if self.rng.random() < 0.25:
                        domain = self._pick_domain(user)
        return rows

    # ---- innocent look-alikes (hard negatives) ----

    def _benign(self, kind: str, user: str, ts: datetime, description: str) -> Plant:
        entry = self.benign.get(kind)
        if entry is None:
            entry = self.benign[kind] = Plant(kind, user, ts.isoformat(), ts.isoformat(), description)
        entry.start, entry.end = min(entry.start, ts.isoformat()), max(entry.end, ts.isoformat())
        if user not in entry.username.split(","):
            entry.username += "," + user
        return entry

    def _lookalikes_for_day(self, day: date) -> list[Row]:
        if day.weekday() >= 5:
            return []
        rng = self.rng
        at = lambda hour: datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(hours=hour)  # noqa: E731
        rows: list[Row] = []

        def work_time(user: User) -> datetime:
            return at(rng.uniform(user.work_start, user.work_start + 8))

        # 1. Legit software updates: .exe/.msi downloads from Microsoft, normal browser.
        updates = next(d for d in self.domains if d.host == "update.microsoft.com")
        for user in rng.sample(self.users, 2):
            ts = work_time(user)
            p = self._benign("legit_update_download", user.username, ts,
                             "Windows updates (.exe/.msi) from update.microsoft.com")
            kb = rng.randint(5_030_000, 5_049_999)
            rows.append(self._row(user, ts, updates, plant=p, method="GET",
                                  url=f"update.microsoft.com/download/KB{kb}.{rng.choice(['exe', 'msi'])}",
                                  file_type=rng.choice(["exe", "msi"]),
                                  bytes_received=rng.randint(20_000_000, 90_000_000)))

        # 2. A developer's scripts calling GitHub with curl.
        github = next(d for d in self.domains if d.host == "github.com")
        ts = work_time(self.dev_user)
        p = self._benign("dev_scripted_client", self.dev_user.username, ts,
                         "developer tooling calling github.com with curl")
        for i in range(rng.randint(5, 15)):
            rows.append(self._row(self.dev_user, ts + timedelta(seconds=i * rng.uniform(5, 30)), github,
                                  plant=p, user_agent="curl/8.9.1", url="github.com/acme/app/archive/main.zip"))

        # 3. A legit large upload to company storage during work hours.
        user = rng.choice(self.users)
        storage_host = rng.choice(["drive.google.com", "acme.sharepoint.com"])
        storage = next(d for d in self.domains if d.host == storage_host)
        ts = work_time(user)
        p = self._benign("legit_large_upload", user.username, ts,
                         "50-150 MB uploads to company storage during work hours")
        rows.append(self._row(user, ts, storage, plant=p, method="POST", url=f"{storage.host}/upload",
                              bytes_sent=rng.randint(50, 150) * 1_000_000))

        # 4. Mid-risk ad-network pages that are allowed (below the high-risk threshold of 75).
        ads = Domain("ads.adnetwork-cdn.com", "Advertisements", "", (2_000, 30_000), "104.18.22.7")
        for user in rng.sample(self.users, 3):
            ts = work_time(user)
            p = self._benign("mid_risk_allowed", user.username, ts, "ad-network pages with risk 40-60, allowed")
            rows.append(self._row(user, ts, ads, plant=p, risk_score=rng.randint(40, 60),
                                  url="ads.adnetwork-cdn.com/pixel.gif"))

        # 5. Regular app polling: Teams heartbeats every ~120 s while the app is open.
        teams = next(d for d in self.domains if d.host == "teams.microsoft.com")
        for user in rng.sample(self.users, 2):
            start = at(user.work_start + rng.uniform(0, 2))
            p = self._benign("app_polling", user.username, start,
                             "Teams heartbeat every ~120 s for 4 hours (regular, like beaconing, but benign)")
            ts = start
            while ts < start + timedelta(hours=4):
                rows.append(self._row(user, ts, teams, plant=p, method="POST",
                                      url="teams.microsoft.com/api/presence/heartbeat",
                                      bytes_sent=rng.randint(200, 400), bytes_received=rng.randint(100, 300)))
                ts += timedelta(seconds=120 + rng.uniform(-5, 5))

        # 6. Evening workers are produced by their late work_start (see __init__); record them.
        for user in self.evening_users:
            self._benign("evening_worker", user.username, at(user.work_start + 7),
                         "users who normally work until ~22:00 UTC")
        return rows

    # ---- planted attacks ----

    def _plant(self, kind: str, user: str, start: datetime, end: datetime, description: str) -> Plant:
        plant = Plant(kind=kind, username=user, start=start.isoformat(), end=end.isoformat(),
                      description=description)
        self.plants.append(plant)
        return plant

    def _user(self, name: str) -> User:
        return next(u for u in self.users if u.username == name)

    def _attacks_for_day(self, day_index: int, day: date) -> list[Row]:
        if self.config.clean:
            return []
        rng = self.rng
        at = lambda h, m=0, s=0: datetime(day.year, day.month, day.day, h, m, s, tzinfo=UTC)  # noqa: E731
        rows: list[Row] = []

        if day_index == 1:  # Tuesday: jdoe downloads malware with a script, then the laptop beacons
            jdoe = self._user(STORY_USER)
            share = Domain("files.anonshare.io", "File Sharing", "", (0, 0), "185.199.110.42")
            p = self._plant("executable_download", STORY_USER, at(14, 5), at(14, 5, 3),
                            "invoice.exe downloaded from a file-sharing site by a scripted client")
            rows.append(self._row(jdoe, at(14, 5), share, plant=p, url="files.anonshare.io/d/invoice.exe",
                                  method="GET", file_type="exe", bytes_received=2_400_000,
                                  user_agent="python-requests/2.32.3", risk_score=60))

            c2 = Domain("cdn-update-check.xyz", "Miscellaneous", "", (0, 0), "45.137.21.9")
            start = at(14, 6)
            p = self._plant("beaconing", STORY_USER, start, start + timedelta(hours=8),
                            "laptop calls cdn-update-check.xyz about every 60 s for 8 hours")
            ts = start
            while ts < start + timedelta(hours=8):
                rows.append(self._row(jdoe, ts, c2, plant=p, url="cdn-update-check.xyz/api/ping",
                                      method="POST", bytes_sent=rng.randint(300, 420),
                                      bytes_received=rng.randint(120, 200), risk_score=35,
                                      user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"))
                ts += timedelta(seconds=60 + rng.uniform(-2, 2))  # very regular: machine, not human

        if day_index == 2:  # Wednesday: amiller hits a malware site, Zscaler blocks it
            user = self._user(THREAT_USER)
            bad = Domain("free-invoice-download.ru", "Malware", "", (0, 0), "91.215.85.17")
            p = self._plant("zscaler_threat", THREAT_USER, at(10, 15), at(10, 16),
                            "3 attempts to a malware site, blocked by Zscaler (Trojan)")
            for i in range(3):
                rows.append(self._row(user, at(10, 15, i * 20), bad, plant=p,
                                      url="free-invoice-download.ru/doc.php?id=8812", action="Blocked",
                                      threat_name="Trojan.GenericKD.71345", malware_category="Trojan",
                                      risk_score=95, status_code=403, bytes_received=0))

        if day_index == 3:  # Thursday: kchen reaches a risky site that was allowed; bsmith bursts
            user = self._user(HIGH_RISK_USER)
            risky = Domain("promo-giftcard-claim.biz", "Newly Registered Domains", "", (5_000, 40_000), "103.224.182.9")
            p = self._plant("high_risk_allowed", HIGH_RISK_USER, at(15, 20), at(15, 21),
                            "risk-85 newly registered domain was allowed")
            for i in range(2):
                rows.append(self._row(user, at(15, 20, i * 30), risky, plant=p, risk_score=85,
                                      url="promo-giftcard-claim.biz/claim"))

            user = self._user(BURST_USER)
            target = next(d for d in self.domains if d.host == "acme.sharepoint.com")
            start = at(11, 0)
            p = self._plant("request_burst", BURST_USER, start, start + timedelta(minutes=2),
                            "about 600 requests in 2 minutes (normal is a few per minute)")
            for i in range(600):
                rows.append(self._row(user, start + timedelta(seconds=i * 0.2), target, plant=p,
                                      url=f"acme.sharepoint.com/sites/finance/doc{i}.xlsx", method="GET"))

        if day_index == 4:  # Friday: rpatel visits random-looking (DGA-style) domains, once each
            user = self._user(RARE_DOMAIN_USER)
            p = self._plant("rare_domain", RARE_DOMAIN_USER, at(13, 0), at(13, 5),
                            "3 random-looking domains, each seen once by one user")
            for i in range(3):
                label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=12))
                dga = Domain(f"{label}.top", "Miscellaneous", "", (500, 3_000), self._ip())
                rows.append(self._row(user, at(13, i * 2), dga, plant=p, url=f"{label}.top/", risk_score=40))

        if day_index == 6:  # Sunday 02:40: jdoe (weekday 9-to-6 user) is active and exfiltrates
            jdoe = self._user(STORY_USER)
            p = self._plant("off_hours", STORY_USER, at(2, 40), at(3, 10),
                            "activity at 02:40 on a Sunday; this user normally works weekdays 8-18")
            for i in range(25):
                domain = self._pick_domain(jdoe)
                rows.append(self._row(jdoe, at(2, 40) + timedelta(seconds=i * 70), domain, plant=p))
            mega = Domain("mega.nz", "File Sharing", "MEGA", (0, 0), "89.44.169.135")
            p = self._plant("large_upload", STORY_USER, at(2, 47), at(2, 55),
                            "about 400 MB uploaded to mega.nz in 4 POSTs at night")
            for i in range(4):
                rows.append(self._row(jdoe, at(2, 47 + i * 2), mega, plant=p, url="mega.nz/upload",
                                      method="POST", bytes_sent=rng.randint(98, 104) * 1_000_000,
                                      bytes_received=rng.randint(500, 2_000), risk_score=30,
                                      user_agent="python-requests/2.32.3"))
        return rows

    # ---- for the AI domain classifier: only a language model can judge these names ----

    def _ai_plants_for_day(self, day_index: int, day: date) -> list[Row]:
        rng = self.ai_rng
        at = lambda h, m=0, s=0: datetime(day.year, day.month, day.day, h, m, s, tzinfo=UTC)  # noqa: E731
        rows: list[Row] = []
        if day_index == 0 and not self.config.clean:
            # Monday: amiller opens a Microsoft look-alike login page and submits the form. No rule or
            # statistic sees it: low risk score, a normal browser, no digits in the name, one visit.
            user = self._user(THREAT_USER)
            fake = Domain("rnicrosoft-login.com", "Miscellaneous", "", (8_000, 40_000), "193.42.33.17")
            p = self._plant("lookalike_domain", THREAT_USER, at(9, 40), at(9, 42),
                            "Microsoft look-alike login page (rn for m), credentials POSTed")
            device = user.devices[0] if user.devices else ""
            rows.append(self._row(user, at(9, 40), fake, rng, plant=p, method="GET", device=device,
                                  url="rnicrosoft-login.com/common/oauth2/authorize", risk_score=30))
            rows.append(self._row(user, at(9, 41, 30), fake, rng, plant=p, method="POST", device=device,
                                  url="rnicrosoft-login.com/common/login", risk_score=30,
                                  bytes_sent=rng.randint(900, 1_400)))
        if day.weekday() < 5:
            # Every weekday, in clean weeks too: Windows' own connectivity probe on one laptop. It looks
            # like a Microsoft look-alike but IS Microsoft (a hard negative for the AI).
            user = self.users[-1]
            ts = at(int(user.work_start), rng.randint(0, 59))
            p = self._benign("real_brand_domain", user.username, ts,
                             "msftconnecttest.com: Windows' real connectivity check (looks odd, is Microsoft)")
            rows.append(self._row(user, ts, Domain("www.msftconnecttest.com", "Information Technology", "",
                                                   (20, 200), "13.107.4.52"), rng, plant=p, method="GET",
                                  device=user.devices[0] if user.devices else "",
                                  url="www.msftconnecttest.com/connecttest.txt", user_agent="Microsoft NCSI"))
        return rows

    # ---- output ----

    def _format_ts(self, ts: datetime) -> str:
        if self.config.time_format == "nss":
            return ts.strftime("%a %b %d %H:%M:%S %Y")  # e.g. "Mon Jun 20 15:29:11 2022"
        return ts.strftime("%Y-%m-%d %H:%M:%S")       # naive UTC

    def day_rows(self, day_index: int) -> list[Row]:
        """One day of traffic (normal + any planted attacks), in time order."""
        day = self.config.start + timedelta(days=day_index)
        rows = self._normal_day(day) + self._lookalikes_for_day(day) + self._attacks_for_day(day_index, day)
        rows += self._ai_plants_for_day(day_index, day)  # last: a stable sort keeps every older row's order
        rows.sort(key=lambda r: r.ts)
        return rows

    def write(self, out: TextIO) -> list[Plant]:
        """Write day by day (memory bounded by one day). Stops after `days`, or, with
        target_mb, after the first whole day at which the file has reached that size."""
        writer = csv.writer(out, lineterminator="\n")
        target = self.config.target_mb * 1_000_000 if self.config.target_mb else 0
        line_no = 0
        written = 0
        if self.config.header and self.config.log_format == "csv":
            writer.writerow(CSV_COLUMNS)
            line_no += 1
        day_index = 0
        while day_index < self.config.days or written < target:
            for row in self.day_rows(day_index):
                values = {**row.values, "time": self._format_ts(row.ts)}
                line = [values[c] for c in CSV_COLUMNS]
                if self.config.log_format == "json":
                    record = {c: (int(values[c]) if c in _JSON_NUMBERS else values[c]) for c in CSV_COLUMNS}
                    out.write(json.dumps(record) + "\n")
                else:
                    writer.writerow(line)
                line_no += 1
                written += sum(len(v) for v in line) + len(line)  # approximate bytes
                if row.plant is not None:
                    row.plant.line_nos.append(line_no)
            day_index += 1
        return self.plants


def answer_key(config: GeneratorConfig, generator: Generator) -> dict:
    """plants = attacks that SHOULD be detected; benign = look-alikes that should NOT be incidents."""
    return {
        "seed": config.seed, "days": config.days, "users": config.users, "clean": config.clean,
        "plants": [asdict(p) for p in generator.plants],
        "benign": [asdict(p) for p in generator.benign.values()],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--users", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--start", type=date.fromisoformat, default=date(2026, 9, 21))
    parser.add_argument("--clean", action="store_true", help="no planted attacks")
    parser.add_argument("--time-format", choices=["iso", "nss"], default="iso")
    parser.add_argument("--header", action="store_true", help="write a header row (CSV)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv", help="CSV or JSON lines")
    parser.add_argument("--target-mb", type=float, help="keep adding days until about this size")
    args = parser.parse_args()

    config = GeneratorConfig(days=args.days, users=args.users, seed=args.seed, start=args.start,
                             clean=args.clean, time_format=args.time_format, header=args.header,
                             target_mb=args.target_mb, log_format=args.format)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as out:
        generator = Generator(config)
        generator.write(out)
    truth = args.out.with_suffix(".truth.json")
    truth.write_text(json.dumps(answer_key(config, generator), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({args.out.stat().st_size / 1e6:.1f} MB) and {truth} "
          f"({len(generator.plants)} attacks, {len(generator.benign)} benign look-alike kinds)")


if __name__ == "__main__":
    main()
