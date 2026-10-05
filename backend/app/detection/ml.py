"""Machine learning: user-hours whose COMBINATION of behavior is unusual (IsolationForest).

Each statistical detector judges one measure (requests/min, bytes/hour, hour of day). IsolationForest
scores how easily random splits isolate a point across many features at once, so it can surface
"a bit unusual on several measures" that no single threshold catches.

- Features per user-hour (DuckDB), each turned into "how unusual for THIS user" (robust z against the
  user's own medians, like stats.py; population medians for users with little history).
- A user-hour is reported only if it is isolated (score >= 0.60) AND at least two features are
  clearly unusual (z >= 3): ML's job is combinations; single-measure extremes belong to the
  statistical detectors, which explain them better.
- Measured on 5 generated weeks with attacks and 5 without: about as many flags on attack-free weeks
  (19) as on attack weeks (20), all on innocent look-alikes or on hours already in an incident.
  So ML findings are corroborating evidence only (see run.py): they never create or raise an
  incident. A fixed random_state makes results reproducible.
"""

import math
from datetime import UTC
from pathlib import Path

import duckdb
import numpy as np
from sklearn.ensemble import IsolationForest

from app.detection.findings import Finding

# (column, label, smallest meaningful spread) - order matches the SQL below
FEATURES = (
    ("requests", "requests", 1.0),
    ("hosts", "distinct destinations", 1.0),
    ("log_bytes_out", "data sent", 0.5),         # ln(1 + bytes): orders of magnitude, not bytes
    ("log_bytes_in", "data received", 0.5),
    ("blocked_share", "blocked requests", 0.05),  # fraction 0..1
    ("post_share", "POST requests", 0.05),
    ("categories", "distinct categories", 1.0),
    ("rare_hosts", "rarely visited destinations", 1.0),  # used by <= 2 users in the file
    ("risk", "average risk score", 5.0),
)
MIN_USER_HOURS = 10      # personal baseline needs this many active hours, else population
MIN_ROWS = 50            # fewer user-hours in the whole file: no basis for "unusual"
SCORE_THRESHOLD = 0.60   # IsolationForest anomaly score (0.5 ~ ordinary, near 1 = very isolated)
FEATURE_Z = 3.0          # a feature counts as "clearly unusual" from this robust z
MIN_UNUSUAL_FEATURES = 2
Z_CLIP = (-10.0, 50.0)   # keeps one extreme value from dominating every split
TREES = 200
SEED = 0

_SQL = """
WITH e AS (SELECT * FROM read_parquet(?) WHERE username IS NOT NULL),
     prevalence AS (SELECT host, count(DISTINCT username) AS users FROM e GROUP BY host)
SELECT username, time_bucket(INTERVAL '1 hour', ts)::TIMESTAMP AS hour,
       min(ts)::TIMESTAMP, max(ts)::TIMESTAMP,
       count(*), count(DISTINCT host), ln(1 + sum(bytes_out)), ln(1 + sum(bytes_in)),
       avg((action = 'Blocked')::INT), avg((method = 'POST')::INT), count(DISTINCT category),
       count(DISTINCT host) FILTER (WHERE prevalence.users <= 2), avg(risk_score)
FROM e LEFT JOIN prevalence USING (host)
GROUP BY username, hour ORDER BY username, hour
"""


def _describe(name: str, value: float) -> str:
    if name in ("blocked_share", "post_share"):
        return f"{value:.0%}"
    if name.startswith("log_bytes"):
        size = math.expm1(value)
        return f"{size / 1e6:,.1f} MB" if size >= 1e5 else f"{size / 1e3:,.0f} KB"
    if name == "risk":
        return f"{value:.0f}"
    return f"{value:,.0f}"


def detect_outliers(con: duckdb.DuckDBPyConnection, parquet: Path) -> list[Finding]:
    rows = con.execute(_SQL, [str(parquet)]).fetchall()
    if len(rows) < MIN_ROWS:
        return []
    users = [r[0] for r in rows]
    raw = np.array([r[4:] for r in rows], dtype=float)
    floors = np.array([floor for _, _, floor in FEATURES])

    # Per-user robust z: "how unusual is this hour for this user?"
    z = np.zeros_like(raw)
    usual = np.zeros_like(raw)
    population = np.median(raw, axis=0), np.median(np.abs(raw - np.median(raw, axis=0)), axis=0)
    for user in set(users):
        idx = np.array([i for i, u in enumerate(users) if u == user])
        if len(idx) >= MIN_USER_HOURS:
            median = np.median(raw[idx], axis=0)
            mad = np.median(np.abs(raw[idx] - median), axis=0)
        else:
            median, mad = population
        scale = np.maximum(1.4826 * mad, floors)
        z[idx] = np.clip((raw[idx] - median) / scale, *Z_CLIP)
        usual[idx] = median

    model = IsolationForest(n_estimators=TREES, random_state=SEED).fit(z)
    scores = -model.score_samples(z)  # sklearn returns the negated paper score: flip back to 0..1

    findings = []
    for i in np.flatnonzero(scores >= SCORE_THRESHOLD):
        unusual = [j for j in np.argsort(-z[i]) if z[i][j] >= FEATURE_Z]
        if len(unusual) < MIN_UNUSUAL_FEATURES:
            continue
        top = unusual[:3]
        username, _, first, last, events = rows[i][:5]
        parts = [f"{_describe(FEATURES[j][0], raw[i][j])} {FEATURES[j][1]} (usually {_describe(FEATURES[j][0], usual[i][j])})"
                 for j in top]
        findings.append(Finding(
            username=username, window_start=first.replace(tzinfo=UTC), window_end=last.replace(tzinfo=UTC),
            kind="behavioral_outlier", score=round(float(min(scores[i], 0.99)), 2), count=int(events),
            reason="Unusual combination for this user in this hour: " + ", ".join(parts) + ".",
            details={"isolation_score": round(float(scores[i]), 3),
                     "features": {FEATURES[j][0]: {"value": round(float(raw[i][j]), 3),
                                                   "usual": round(float(usual[i][j]), 3),
                                                   "z": round(float(z[i][j]), 1)} for j in top}},
        ))
    return findings
