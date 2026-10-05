"""Rule hits -> findings: one per user and rule while the hits keep coming (gaps <= 1 hour).

Pass 1 stores, per log line, WHICH rules fired (`rule_hits`) and the line's highest score
(`rule_max_score`). Grouping needs each rule's OWN score and reason: a line that hits two rules
(jdoe's malware download: executable 0.8 + scripted client 0.6) would otherwise give the
scripted-client group a score of 0.8. So we re-run `apply_rules` on the flagged lines only:
the scoring logic stays in one place (rules.py) instead of being copied into SQL.
"""

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

from app.detection.findings import Finding, describe_duration
from app.detection.rules import RuleHit, apply_rules
from app.parsing.event import ZscalerEvent

GROUP_GAP = timedelta(hours=1)
BATCH_ROWS = 10_000   # flagged lines fetched at a time (memory stays bounded on huge files)
TOP_HOSTS = 5
SAMPLE_LINES = 5      # line numbers kept for drill-down

_EVENT_FIELDS = [f.name for f in fields(ZscalerEvent)]
# Fixed identifiers from our own dataclass, safe in SQL text. ts as naive UTC (see aggregates._iso).
_SELECT = ", ".join("ts::TIMESTAMP AS ts" if name == "ts" else name for name in _EVENT_FIELDS)


@dataclass
class _Group:
    username: str
    rule: str
    first: datetime
    last: datetime
    best: RuleHit                     # highest-scoring hit: its reason represents the group
    count: int = 0
    hosts: Counter = field(default_factory=Counter)
    line_nos: list[int] = field(default_factory=list)

    def add(self, event: ZscalerEvent, hit: RuleHit) -> None:
        self.last = event.ts
        self.count += 1
        if hit.score > self.best.score:
            self.best = hit
        if event.host:
            self.hosts[event.host] += 1
        if len(self.line_nos) < SAMPLE_LINES:
            self.line_nos.append(event.line_no)

    def finding(self) -> Finding:
        repeated = (f" ({self.count:,} times within {describe_duration((self.last - self.first).total_seconds())})"
                    if self.count > 1 else "")
        return Finding(
            username=self.username, window_start=self.first, window_end=self.last,
            kind=self.rule, score=self.best.score, count=self.count,
            reason=f"{self.best.reason}{repeated}.",
            details={"rule": self.rule, "hosts": dict(self.hosts.most_common(TOP_HOSTS)),
                     "sample_line_nos": self.line_nos},
        )


def _flagged_events(con: duckdb.DuckDBPyConnection, parquet: Path) -> Iterator[ZscalerEvent]:
    """Lines with at least one rule hit, ordered by user and time, fetched in batches."""
    result = con.execute(f"""
        SELECT {_SELECT} FROM read_parquet(?)
        WHERE len(rule_hits) > 0 AND username IS NOT NULL
        ORDER BY username, ts, line_no
    """, [str(parquet)])
    while batch := result.fetchmany(BATCH_ROWS):
        for row in batch:
            values = dict(zip(_EVENT_FIELDS, row))
            values["ts"] = values["ts"].replace(tzinfo=UTC)
            yield ZscalerEvent(**values)


def group_rule_hits(con: duckdb.DuckDBPyConnection, parquet: Path,
                    disabled: frozenset[str] = frozenset()) -> list[Finding]:
    open_groups: dict[tuple[str, str], _Group] = {}  # (username, rule) -> group still collecting
    findings: list[Finding] = []
    for event in _flagged_events(con, parquet):
        for hit in apply_rules(event, disabled):
            key = (event.username, hit.rule)
            group = open_groups.get(key)
            if group is not None and event.ts - group.last > GROUP_GAP:
                findings.append(group.finding())  # gap too long: close it, start a new one
                group = None
            if group is None:
                group = open_groups[key] = _Group(event.username, hit.rule, event.ts, event.ts, hit)
            group.add(event, hit)
    findings.extend(group.finding() for group in open_groups.values())
    return sorted(findings, key=lambda f: (f.username, f.window_start, f.kind))
