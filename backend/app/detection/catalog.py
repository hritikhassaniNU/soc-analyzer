"""The detector catalog: what each detector looks for, its thresholds, false positives and MITRE ATT&CK
mapping. Shown on the Detection Rules page.

Thresholds are read from the detector modules' own constants, so this page can't drift from the
code that runs. MITRE mappings are deliberately conservative: `approximate=True` marks a loose fit,
and detectors with no honest technique have none (analysts would rather see a gap than a guess).
"""

from dataclasses import dataclass, field

from app.detection import ai_domains, beaconing, behavior, ml, rare_domains, rules, stats
from app.detection.correlate import CATEGORY_OF_KIND, SEVERITY

Layer = str  # "rule" | "stat" | "ml" | "ai"


@dataclass(frozen=True)
class Technique:
    id: str           # "T1071.001"
    name: str
    tactic: str       # ATT&CK tactic, for the coverage grid
    approximate: bool = False  # a loose fit: shown with an "approximate" tag
    supports: bool = False     # not a technique detected, but evidence that supports one

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass(frozen=True)
class Detector:
    kind: str          # the finding kind it produces (also its rule name)
    name: str
    layer: Layer
    summary: str       # one line: what it finds
    logic: list[str]   # how it decides, with the real thresholds
    false_positives: list[str]
    tuning: str        # what can be adjusted, and where
    techniques: list[Technique] = field(default_factory=list)

    @property
    def category(self) -> str:
        return CATEGORY_OF_KIND[self.kind]

    @property
    def severity(self) -> float:
        return SEVERITY[self.category]


_Z = f"robust z-score ≥ {stats.Z_THRESHOLD:g} (median/MAD against the user's own history, else everyone's)"

DETECTORS: tuple[Detector, ...] = (
    # ---- Layer 1: rules, one log line at a time ----
    Detector(
        "zscaler_threat", "Zscaler threat", "rule",
        "Zscaler itself named a threat on the request.",
        ["Fires when the log's threat name is set (not None/N/A).",
         "Score 0.99 if the request was allowed (it got through), 0.90 if blocked."],
        ["Rare: these are Zscaler's own verdicts. Blocked hits may need no action beyond a check."],
        "No threshold; trusts Zscaler's threat engine.",
        [],  # depends on the threat Zscaler named: no single technique
    ),
    Detector(
        "high_risk_allowed", "High-risk site allowed", "rule",
        "A request Zscaler rated high-risk was still allowed.",
        [f"Page risk score ≥ {rules.HIGH_RISK_THRESHOLD} and action Allowed.",
         "Score = risk score / 100."],
        ["Risky-but-legitimate sites some teams need (measured look-alike: ad-network pages at risk 40-60 stay "
         "below the threshold)."],
        f"HIGH_RISK_THRESHOLD = {rules.HIGH_RISK_THRESHOLD} in detection/rules.py.",
        [Technique("T1189", "Drive-by Compromise", "Initial Access", approximate=True)],
    ),
    Detector(
        "scripted_client", "Scripted client", "rule",
        "A command-line tool or HTTP library instead of a browser.",
        ["User agent matches curl, wget, python-requests, python-urllib, Go-http-client, PowerShell "
         "or libwww-perl.", "Score 0.6."],
        ["Developers and automation use these daily (measured look-alike: a developer's curl to GitHub); "
         "weighted as automated traffic (0.6), so it rarely drives an incident alone."],
        "SCRIPTED_CLIENT pattern in detection/rules.py.",
        [Technique("T1059", "Command and Scripting Interpreter", "Execution", approximate=True)],
    ),
    Detector(
        "executable_download", "Executable download", "rule",
        "An executable file type was downloaded.",
        [f"File type is one of {', '.join(sorted(rules.EXECUTABLE_TYPES))}.",
         "Score 0.8; 0.2 if Zscaler's category is Software Updates (ranked down, never hidden)."],
        ["Software updates and IT installs (measured look-alike: update.microsoft.com, scored 0.2)."],
        "EXECUTABLE_TYPES and SOFTWARE_UPDATE_CATEGORY in detection/rules.py.",
        [Technique("T1105", "Ingress Tool Transfer", "Command and Control")],
    ),
    # ---- Layer 2: statistics over the whole file ----
    Detector(
        "request_burst", "Request burst", "stat",
        "Far more requests in one minute than this user normally makes.",
        [f"≥ {behavior.BURST_MIN_PER_MINUTE} requests in a minute (one per second: beyond human browsing).",
         f"And {_Z}.",
         f"Personal baseline needs {behavior.BURST_MIN_POINTS} active minutes."],
        ["Sync clients and page-heavy web apps could cross the floor (no generated look-alike for this yet)."],
        "BURST_* constants in detection/behavior.py.",
        [],  # a sign of automation, not one technique
    ),
    Detector(
        "large_upload", "Large upload", "stat",
        "Much more data sent in an hour than this user's usual hour.",
        [f"≥ {behavior.UPLOAD_MIN_BYTES // 1_000_000} MB sent in one hour.",
         f"And {_Z}; spread floor {behavior.UPLOAD_FLOOR // 1_000_000} MB.",
         "Uploads to approved storage (APPROVED_UPLOAD_HOSTS) count 0.4× toward risk."],
        ["Backups and big shares to sanctioned storage (measured look-alikes: SharePoint, Google Drive)."],
        "UPLOAD_* in detection/behavior.py; APPROVED_UPLOAD_HOSTS setting.",
        [Technique("T1567", "Exfiltration Over Web Service", "Exfiltration")],
    ),
    Detector(
        "off_hours", "Unusual hours", "stat",
        "Activity well outside this user's usual working hours.",
        [f"Usual span learned from ≥ {behavior.OFF_HOURS_MIN_DAYS} active days, in the log's timezone.",
         f"Fires on ≥ {behavior.OFF_HOURS_MIN_EVENTS} events more than {behavior.OFF_HOURS_TOLERANCE} h "
         "outside that span.",
         f"Score {behavior.OFF_HOURS_BASE_SCORE:g}; +0.1 on a weekend, +0.1 if ≥ "
         f"{behavior.OFF_HOURS_BUSY_EVENTS} events."],
        ["Late workers and other timezones (measured look-alikes: evening shift users)."],
        "OFF_HOURS_* in detection/behavior.py.",
        [Technique("T1078", "Valid Accounts", "Defense Evasion", supports=True)],
    ),
    Detector(
        "beaconing", "Beaconing", "stat",
        "Machine-regular requests to a rarely used destination, like malware checking in.",
        [f"≥ {beaconing.MIN_REQUESTS} requests; ≥ {beaconing.MIN_REGULAR_SHARE:.0%} of gaps within "
         f"±{beaconing.NEAR_MEDIAN:.0%} of the median gap.",
         f"Median gap ≥ {beaconing.MIN_MEDIAN_GAP_S} s, lasting ≥ {beaconing.MIN_DURATION_S // 3600} h.",
         f"Destination used by ≤ max({beaconing.MAX_HOST_USERS}, {beaconing.MAX_HOST_USER_SHARE:.0%} of users)."],
        ["Polling apps to popular hosts are excluded by the rarity test (measured look-alike: Teams "
         "presence heartbeats every ~120 s)."],
        "Constants in detection/beaconing.py.",
        [Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")],
    ),
    Detector(
        "rare_domain", "Rare random-looking domain", "stat",
        "A random-looking domain only one user contacted (typical of generated malware domains).",
        ["Seen by exactly one user in the file.",
         f"Name label ≥ {rare_domains.MIN_LABEL_LENGTH} characters with a digit inside letters, and "
         f"≥ {rare_domains.MIN_DIGITS} digits or ≤ {rare_domains.MAX_VOWEL_SHARE:.0%} vowels.",
         f"Score {rare_domains.BASE_SCORE:g} + 0.1 per extra domain in the hour, at most {rare_domains.MAX_SCORE:g}."],
        ["CDN and tracking hosts with codes in their names (no generated look-alike for this yet; a letters-only "
         "random name is a known blind spot)."],
        "Constants in detection/rare_domains.py.",
        [Technique("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control")],
    ),
    # ---- Layer 4: machine learning (evidence only) ----
    Detector(
        "behavioral_outlier", "Unusual combination (ML)", "ml",
        "An hour whose mix of behavior is unusual for this user (IsolationForest).",
        [f"{len(ml.FEATURES)} features per user-hour, each as a robust z against the user's own hours.",
         f"Reported when the anomaly score ≥ {ml.SCORE_THRESHOLD:g} and ≥ {ml.MIN_UNUSUAL_FEATURES} features "
         f"have z ≥ {ml.FEATURE_Z:g}.",
         "Evidence only: attached to an existing incident, never changes its risk."],
        ["Noisy on its own (measured: as many flags on clean weeks as on attack weeks), hence evidence only."],
        "Constants in detection/ml.py.",
        [],
    ),
    # ---- Layer 5: AI (Claude), only with an API key ----
    Detector(
        "ai_suspicious_domain", "Suspicious domain (AI)", "ai",
        "Claude judges a rare domain's name: generated, a brand look-alike, or anonymous file sharing.",
        [f"Candidates: domains contacted by ≤ {ai_domains.MAX_USERS} users, at most {ai_domains.MAX_CANDIDATES} "
         "per scan (rarest first); only names, URL categories and counts are sent, no users or IPs.",
         "One fixed label + low/medium/high confidence per domain; answers cached per domain.",
         f"Score {ai_domains.SCORES['high']:g} (high confidence) or {ai_domains.SCORES['medium']:g} (medium); "
         "low confidence and 'likely benign' are dropped.",
         "Risk weight 0.6, except brand look-alikes (phishing): 0.9, so one alone is a medium case.",
         "Runs only when ANTHROPIC_API_KEY is set."],
        ["Real but unusual brand domains (measured look-alike: msftconnecttest.com, Microsoft's own); "
         "the model can be wrong, so it counts with a low weight and every answer shows its reason."],
        "MAX_USERS, MAX_CANDIDATES, SCORES in detection/ai_domains.py; prompt in llm/domains.py.",
        [Technique("T1566.002", "Phishing: Spearphishing Link", "Initial Access", approximate=True),
         Technique("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control")],
    ),
)

BY_KIND = {d.kind: d for d in DETECTORS}
KINDS = frozenset(BY_KIND)
assert KINDS == set(CATEGORY_OF_KIND), "every finding kind needs a catalog entry"

# Honest gaps (also in the README): what these detectors can't see.
BLIND_SPOTS = (
    "Command & control hidden in popular services (prevalence makes it look normal).",
    "Beacons with heavy random jitter.",
    "Random domain names made only of letters.",
    "Attackers acting within a user's usual hours and volumes.",
    "Very small files: no history means no baseline; with one user every destination looks rare.",
)
