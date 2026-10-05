"""Layer 1 of detection: rules that look at ONE log line at a time.

Each rule is a small function: event in, RuleHit (or None) out. They run inline in pass 1,
so they must be cheap (~3M calls for a 500 MB file).

Scores are heuristic ranking signals in [0, 1] (how strong and reliable the signal is),
NOT probabilities that the event is malicious.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.parsing.event import ZscalerEvent

HIGH_RISK_THRESHOLD = 75

# Command-line tools and HTTP libraries, rarely a person in a browser. Precompiled: runs per line.
# Note PowerShell's real agent is "... WindowsPowerShell/5.1" (no separator before "PowerShell").
SCRIPTED_CLIENT = re.compile(
    r"(?:^|[\s(;])(curl|wget|python-requests|python-urllib|go-http-client|(?:windows)?powershell|libwww-perl)\b",
    re.IGNORECASE,
)

EXECUTABLE_TYPES = frozenset({"exe", "dll", "msi", "ps1", "bat", "scr", "vbs", "jar"})
SOFTWARE_UPDATE_CATEGORY = "software updates"


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule: str     # stable name, stored per event
    score: float  # 0..1 ranking signal, not a probability
    reason: str   # human-readable explanation for the analyst


def zscaler_threat(e: ZscalerEvent) -> RuleHit | None:
    """Zscaler itself identified a threat. Allowed = it got through (worse than blocked)."""
    if e.threat is None:
        return None
    outcome = "allowed" if e.action == "Allowed" else "blocked"
    return RuleHit("zscaler_threat", 0.99 if e.action == "Allowed" else 0.90,
                   f"Zscaler detected {e.threat} ({outcome})")


def high_risk_allowed(e: ZscalerEvent) -> RuleHit | None:
    """A request Zscaler rated high-risk was still allowed."""
    if e.action != "Allowed" or e.risk_score < HIGH_RISK_THRESHOLD:
        return None
    return RuleHit("high_risk_allowed", e.risk_score / 100,
                   f"Risk {e.risk_score} request to {e.host or e.url} was allowed")


def scripted_client(e: ZscalerEvent) -> RuleHit | None:
    """A command-line tool or HTTP library instead of a browser (scripts, malware, or developers)."""
    if not e.user_agent:
        return None
    match = SCRIPTED_CLIENT.search(e.user_agent)
    if match is None:
        return None
    return RuleHit("scripted_client", 0.6, f"Scripted client: {e.user_agent[:80]}")


def executable_download(e: ZscalerEvent) -> RuleHit | None:
    """An executable file type. Software updates (Zscaler's category) get a low score, not a pass:
    trusted categories can be abused, so we rank them down instead of hiding them."""
    if not e.file_type or e.file_type.lower() not in EXECUTABLE_TYPES:
        return None
    is_update = (e.category or "").lower() == SOFTWARE_UPDATE_CATEGORY
    return RuleHit("executable_download", 0.2 if is_update else 0.8,
                   f"Executable ({e.file_type.lower()}) downloaded from {e.host or e.url}"
                   + (f" ({e.category})" if e.category else ""))


RULES: tuple[Callable[[ZscalerEvent], RuleHit | None], ...] = (
    zscaler_threat,
    high_risk_allowed,
    scripted_client,
    executable_download,
)


def apply_rules(event: ZscalerEvent, disabled: frozenset[str] = frozenset()) -> list[RuleHit]:
    """All rules that fire for this event (usually none). `disabled`: rules switched off by an analyst."""
    return [hit for rule in RULES if rule.__name__ not in disabled and (hit := rule(event)) is not None]
