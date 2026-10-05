"""Rare, random-looking domains: typical of malware that generates domain names (DGA) to find
its command server, e.g. `g9hvq1kn5cnt.top`.

Both conditions are needed:
- Rare: seen by exactly ONE user in the file. Rare alone is useless: everyone has a long tail
  (~78 one-user domains per generated week).
- Random-looking name (`looks_random`): a simple, explainable letter/digit rule. Measured
  alternatives: Shannon entropy did not separate short names (normal up to 3.39 bits, planted
  3.25); "few vowels" alone flagged real compounds like `brightsmart`.
Known limit: letters-only random names are missed (~14% of random 12-character names). The proper
fix is a character model trained on a large list of real domains (ML step).
"""

import re
from datetime import UTC, timedelta
from pathlib import Path

import duckdb

from app.detection.findings import Finding, describe_duration

MIN_LABEL_LENGTH = 8
MIN_DIGITS = 3
MAX_VOWEL_SHARE = 0.25          # of the letters
GROUP_GAP = timedelta(hours=1)  # one finding per user per burst of such domains
BASE_SCORE = 0.6                # heuristic: +0.1 per extra domain in the group, capped
MAX_SCORE = 0.8
NAMES_IN_REASON = 5

_DIGIT_INSIDE_LETTERS = re.compile(r"[a-z]\d+[a-z]")


def name_label(host: str) -> str:
    """The registered name without the top-level domain: 'files.example.com' -> 'example'.
    Approximation: two-part suffixes like '.co.uk' give 'co' (too short to flag: a missed
    detection, never a false alarm). A proper version uses the Public Suffix List."""
    parts = host.lower().rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def looks_random(label: str) -> bool:
    """>= 8 characters, a digit between letters (like 'g9h'), and either >= 3 digits or few
    vowels. Real names with digits usually have them at an end ('office365', 'win10tools')."""
    if len(label) < MIN_LABEL_LENGTH or label.startswith("xn--"):  # xn--: internationalized names
        return False
    if not _DIGIT_INSIDE_LETTERS.search(label):
        return False
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    vowel_share = sum(c in "aeiou" for c in letters) / len(letters)
    return digits >= MIN_DIGITS or vowel_share <= MAX_VOWEL_SHARE


def detect_rare_domains(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[Finding]:
    rows = con.execute("""
        SELECT any_value(username), host, min(ts)::TIMESTAMP, max(ts)::TIMESTAMP, count(*),
               any_value(category)
        FROM read_parquet(?) WHERE host IS NOT NULL AND username IS NOT NULL
        GROUP BY host HAVING count(DISTINCT username) = 1
        ORDER BY 1, 3
    """, [str(parquet)]).fetchall()
    suspicious = [row for row in rows if looks_random(name_label(row[1]))]

    # Group each user's domains that appear close together (sorted by user, then first seen).
    groups: list[list[tuple]] = []
    for row in suspicious:
        last = groups[-1][-1] if groups else None
        if last is not None and last[0] == row[0] and row[2] - max(r[3] for r in groups[-1]) <= GROUP_GAP:
            groups[-1].append(row)
        else:
            groups.append([row])

    findings = []
    for group in groups:
        username = group[0][0]
        start, end = min(r[2] for r in group), max(r[3] for r in group)
        names = [r[1] for r in group]
        shown = ", ".join(names[:NAMES_IN_REASON]) + (f" and {len(names) - NAMES_IN_REASON} more"
                                                      if len(names) > NAMES_IN_REASON else "")
        plural = "s" if len(names) > 1 else ""
        within = f" within {describe_duration((end - start).total_seconds())}" if len(names) > 1 else ""
        findings.append(Finding(
            username=username, window_start=start.replace(tzinfo=UTC), window_end=end.replace(tzinfo=UTC),
            kind="rare_domain", score=round(min(MAX_SCORE, BASE_SCORE + 0.1 * (len(names) - 1)), 2),
            count=sum(r[4] for r in group),
            reason=f"{len(names)} random-looking domain{plural} seen only by this user{within}: {shown}.",
            details={"domains": names[:20], "categories": sorted({r[5] or "uncategorized" for r in group})},
        ))
    return findings
