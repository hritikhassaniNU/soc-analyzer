"""The summary without an LLM: deterministic text from the incidents. Used when no API key is set,
or when the API call fails or returns something invalid. Same shape as the AI version."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.detection.correlate import CATEGORY_LABELS, CATEGORY_OF_KIND
from app.llm.payload import SENT_PRIORITIES, IncidentInput, incident_menu
from app.llm.searches import default_picks

# Suggested first steps per category of evidence (generic SOC playbook, strongest category first).
NEXT_STEPS = {
    "known_threat": "Check whether the threat reached the device (allowed vs blocked) and scan it.",
    "command_and_control": "Isolate the device, check it for malware, and block the destination.",
    "large_upload": "Confirm with the user or their manager whether the upload was authorized and what was sent.",
    "executable_download": "Find the downloaded file on the device and check it (hash, sandbox).",
    "automated_traffic": "Identify the script or tool behind the traffic and who runs it.",
    "unusual_hours": "Verify the activity with the user; consider whether the account is compromised.",
    "behavioral_outlier": "Review the user's activity in that hour for anything unexpected.",
    "suspicious_domain": "Check what the user did on the domain, and block it if it is not needed.",
}


# Questions an analyst should answer, per category of evidence (strongest category first).
NEXT_QUESTIONS = {
    "known_threat": "Did the threat reach the device, and was anything executed afterwards?",
    "command_and_control": "Which process on the device makes these regular connections?",
    "large_upload": "What data was uploaded, and was the destination approved for it?",
    "executable_download": "Was the downloaded file run, and is it known to be malicious?",
    "automated_traffic": "Which script or tool generated the traffic, and who started it?",
    "unusual_hours": "Was the user working at that time, or could the account be used by someone else?",
    "behavioral_outlier": "What else changed in the user's activity during that hour?",
    "suspicious_domain": "Did the user enter credentials or download anything on that domain?",
}


@dataclass(frozen=True)
class IncidentNarrative:
    narrative: str
    next_steps: list[str]
    next_questions: list[str] = field(default_factory=list)
    # The AI's triage suggestion ({verdict, confidence, reason}; None from the template) and
    # the picked next-step searches (Search.stored() dicts: label + Logs filters).
    assessment: dict[str, str] | None = None
    searches: list[dict[str, Any]] = field(default_factory=list)
    # Who wrote THIS incident's text: with Claude on, low incidents still get template text.
    source: str = "template"


@dataclass(frozen=True)
class Narrative:
    source: str                 # "ai" | "template"
    summary: str
    incidents: dict[int, IncidentNarrative] = field(default_factory=dict)  # our incident id -> text
    model: str | None = None
    # Structured sections for the analysis cards: a one-line headline, the key findings
    # (priority of the incident each describes + one sentence) and the recommended actions.
    headline: str | None = None
    key_findings: list[tuple[str, str]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


def _when(start: datetime, end: datetime) -> str:
    day = f"{start:%a %d %b}"
    if start.date() == end.date():
        return f"{day} {start:%H:%M}–{end:%H:%M} UTC"
    return f"{day} {start:%H:%M} – {end:%a %d %b %H:%M} UTC"


def template_narrative(incidents: list[IncidentInput]) -> Narrative:
    shown = sorted((i for i in incidents if i.priority in SENT_PRIORITIES), key=lambda i: -i.priority_score)
    # Every incident gets the free "why flagged" text, low ones too: a low case can still be a
    # real attack (e.g. a phishing page only the AI saw). Claude still writes only medium+.
    narratives = _incident_narratives(incidents)
    if not shown:
        low = len(incidents)
        return Narrative("template", "No medium, high or critical incidents in this upload."
                         + (f" {low} low-priority incident{' is' if low == 1 else 's are'} listed for the record." if low else ""),
                         narratives)

    counts = [f"{n} {p}" for p in SENT_PRIORITIES if (n := sum(i.priority == p for i in shown))]
    top = shown[0]
    summary = (f"{len(shown)} incident{' needs' if len(shown) == 1 else 's need'} attention ({', '.join(counts)}). "
               f"Most serious: {top.username}, {_when(top.start, top.end)}: {top.title.lower()}.")
    headline = (f"{len(shown)} incident{' needs' if len(shown) == 1 else 's need'} attention; "
                f"most serious: {top.username} ({top.title.lower()}).")
    key_findings = [(i.priority, f"{i.username}: {i.title.lower()}, {i.start:%b %d}.") for i in shown[:3]]  # short
    actions: list[str] = []
    for incident in shown:  # the first step of each serious incident, most serious first
        step = narratives[incident.id].next_steps[0] if narratives[incident.id].next_steps else None
        if step and len(actions) < 3 and all(not a.endswith(step) for a in actions):
            actions.append(f"{incident.username}: {step.split(', ')[0].rstrip('.')}.")  # first clause only
    return Narrative("template", summary, narratives, headline=headline, key_findings=key_findings, actions=actions)


def _incident_narratives(incidents: list[IncidentInput]) -> dict[int, IncidentNarrative]:
    narratives = {}
    for incident in incidents:
        findings = sorted(incident.findings, key=lambda f: f.start)
        steps, questions = [], []
        for f in sorted(findings, key=lambda f: -f.score):
            category = CATEGORY_OF_KIND.get(f.kind, "behavioral_outlier")
            if NEXT_STEPS[category] not in steps:
                steps.append(NEXT_STEPS[category])
            if NEXT_QUESTIONS[category] not in questions:
                questions.append(NEXT_QUESTIONS[category])
        # Compact: when, then the strongest finding's reason, then what else was seen.
        strongest = max(findings, key=lambda f: f.score) if findings else None
        others = sorted({CATEGORY_LABELS[CATEGORY_OF_KIND.get(f.kind, 'behavioral_outlier')] for f in findings}
                        - ({CATEGORY_LABELS[CATEGORY_OF_KIND.get(strongest.kind, 'behavioral_outlier')]} if strongest else set()))
        lead = f"{incident.username}, {incident.start:%b %d %H:%M}–{incident.end:%H:%M} UTC: {strongest.reason.rstrip('.')}." if strongest \
            else f"{incident.username}, {incident.start:%b %d %H:%M} UTC."
        narratives[incident.id] = IncidentNarrative(
            narrative=(lead + (f" Also: {', '.join(others)}." if others else ""))[:320],
            next_steps=steps[:3],
            next_questions=questions[:3],
            searches=[s.stored() for s in default_picks(incident_menu(incident))],
        )
    return narratives
