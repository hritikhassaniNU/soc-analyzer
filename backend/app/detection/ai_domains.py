"""AI domain classifier: the one detector where AI decides what is suspicious.

Statistics can tell that a domain is RARE; only a language model can tell that `rnicrosoft-login.com`
imitates Microsoft, or that `g9hvq1kn5cnt.top` reads like a generated name, without a hand-made list.

- Candidates: domains contacted by at most MAX_USERS users in the file (the long tail, where
  phishing and malware domains live; popular services are never sent), at most MAX_CANDIDATES,
  rarest first.
- The model only sees domain names, their URL categories and request counts: no users, no IPs
  (see app/llm/domains.py for the prompt-injection defenses).
- Each answer is one fixed label + low/medium/high confidence + a short reason. Suspicious labels
  with medium or high confidence become one finding per (user, domain); low confidence and
  "likely benign" are dropped.
- Weight: its own evidence category, severity 0.6 (correlate.py): it corroborates other evidence
  but rarely raises a case alone.
Without an API key the classifier is not called at all: detection is exactly as before.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path

import duckdb

from app.detection.findings import Finding

MAX_USERS = 2
MAX_CANDIDATES = 150
SUSPICIOUS = {"random_generated", "brand_lookalike", "anonymous_file_sharing"}
SCORES = {"high": 0.7, "medium": 0.5}  # low confidence: dropped
LABEL_WORDS = {
    "random_generated": "a randomly generated name (typical of malware)",
    "brand_lookalike": "a look-alike of a known brand (typical of phishing)",
    "anonymous_file_sharing": "an anonymous file-sharing service",
    "likely_benign": "likely benign",
}


@dataclass(frozen=True)
class DomainCandidate:
    host: str
    category: str | None
    requests: int
    users: int


@dataclass(frozen=True)
class DomainVerdictInput:
    """One classifier answer (what the cache stores)."""
    label: str
    confidence: str
    reason: str
    model: str


# host list in, verdicts out (missing hosts = no answer). The real one is the cached Claude call
# built in pass 2; tests and the evaluation pass fakes.
Classifier = Callable[[list[DomainCandidate]], dict[str, DomainVerdictInput]]


def domain_candidates(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[DomainCandidate]:
    rows = con.execute("""
        SELECT lower(host), any_value(category), count(*), count(DISTINCT username)
        FROM read_parquet(?) WHERE host IS NOT NULL AND username IS NOT NULL
        GROUP BY lower(host) HAVING count(DISTINCT username) <= ?
        ORDER BY 4, 3, 1 LIMIT ?
    """, [str(parquet), MAX_USERS, MAX_CANDIDATES]).fetchall()
    return [DomainCandidate(host, category, requests, users) for host, category, requests, users in rows]


def detect_ai_domains(con: duckdb.DuckDBPyConnection, parquet: Path, classify: Classifier) -> list[Finding]:
    candidates = domain_candidates(con, parquet)
    if not candidates:
        return []
    verdicts = classify(candidates)
    flagged = {host: v for host, v in verdicts.items() if v.label in SUSPICIOUS and v.confidence in SCORES}
    if not flagged:
        return []
    rows = con.execute("""
        SELECT username, lower(host), min(ts)::TIMESTAMP, max(ts)::TIMESTAMP, count(*)
        FROM read_parquet(?) WHERE lower(host) IN (SELECT unnest(?::VARCHAR[])) AND username IS NOT NULL
        GROUP BY username, lower(host) ORDER BY 1, 3
    """, [str(parquet), list(flagged)]).fetchall()
    findings = []
    for username, host, start, end, count in rows:
        v = flagged[host]
        findings.append(Finding(
            username=username, window_start=start.replace(tzinfo=UTC), window_end=end.replace(tzinfo=UTC),
            kind="ai_suspicious_domain", score=SCORES[v.confidence], count=count,
            reason=f"AI classified {host} as {LABEL_WORDS[v.label]} ({v.confidence} confidence): {v.reason}",
            details={"host": host, "label": v.label, "confidence": v.confidence, "model": v.model},
        ))
    return findings
