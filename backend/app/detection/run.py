"""Every detector on one Parquet file, then correlation: the whole detection in one call.
Used by pass 2 (which stores the result) and by the evaluation harness (which scores it)."""

from dataclasses import dataclass, replace
from datetime import UTC, tzinfo
from pathlib import Path

import duckdb

from app.detection.ai_domains import Classifier, detect_ai_domains
from app.detection.correlate import IncidentDraft, correlate
from app.detection.findings import Finding
from app.detection.ml import detect_outliers
from app.detection.rule_groups import group_rule_hits
from app.detection.statistical import detect_statistical


@dataclass(frozen=True)
class Detection:
    findings: list[tuple[str, Finding]]  # (source: "rule" | "stat" | "ml" | "ai", finding)
    incidents: list[IncidentDraft]       # members index into `findings`


def detect(
    con: duckdb.DuckDBPyConnection, parquet: Path, log_tz: tzinfo = UTC,
    approved_upload_hosts: frozenset[str] = frozenset(), disabled: frozenset[str] = frozenset(),
    classify_domains: Classifier | None = None,
) -> Detection:
    """`disabled`: detector kinds switched off by an analyst (catalog.py); their findings are dropped
    before correlation, so incidents are built as if they didn't exist. `classify_domains`: the AI
    domain classifier; None (no API key, tests) = that detector doesn't run."""
    findings = ([("rule", f) for f in group_rule_hits(con, parquet, disabled)]
                + [("stat", f) for f in detect_statistical(con, parquet, log_tz) if f.kind not in disabled])
    if classify_domains is not None and "ai_suspicious_domain" not in disabled:
        findings += [("ai", f) for f in detect_ai_domains(con, parquet, classify_domains)]
    incidents = correlate([f for _, f in findings], approved_upload_hosts)
    outliers = [] if "behavioral_outlier" in disabled else detect_outliers(con, parquet)  # skip the cost too
    return _attach_ml(findings, incidents, outliers)


def _attach_ml(
    findings: list[tuple[str, Finding]], incidents: list[IncidentDraft], outliers: list[Finding]
) -> Detection:
    """ML findings are corroborating evidence only (measured: as many on attack-free weeks as on
    attack weeks). One is kept only if the same user already has an incident overlapping that hour;
    it joins that incident's evidence WITHOUT changing its score, title or window. Others are dropped."""
    findings = list(findings)
    by_id = {id(i): i for i in incidents}
    extra: dict[int, list[int]] = {}
    for outlier in outliers:
        match = next((i for i in incidents if i.username == outlier.username
                      and outlier.window_start <= i.end and outlier.window_end >= i.start), None)
        if match is not None:
            findings.append(("ml", outlier))
            extra.setdefault(id(match), []).append(len(findings) - 1)
    incidents = [
        replace(i, members=i.members + extra[key], categories=i.categories + ["behavioral_outlier"])
        if (key := id(i)) in extra else i
        for i in by_id.values()
    ]
    return Detection(findings, incidents)
