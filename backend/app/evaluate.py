"""Detection quality on generated weeks: did every planted attack reach a medium-or-higher
incident, how high did the innocent look-alikes get, and what do attack-free weeks produce?

    uv run python -m app.evaluate                 # 5 seeds, markdown report
    uv run python -m app.evaluate --seeds 1 2 3
    uv run python -m app.evaluate --ai            # also the AI domain classifier (real Claude calls)

Runs the real detection (rules, statistics, correlation) on in-memory generated logs; no database.
Matching uses the answer key's LINE NUMBERS: an incident "covers" a planted line when it is the
same user and the line's time falls inside the incident's window.
Look-alikes are scored on the ATTACK-FREE weeks only: in attack weeks an attacked user's incident
window also covers their ordinary activity (rpatel's Teams polling during his rare-domain incident),
so a "raise" there can't be attributed to the look-alike.
Honest scope: synthetic data. It shows the system finds what was planted and stays quiet on what
was designed to look suspicious but isn't; it can't show real-world precision.
"""

import argparse
import io
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from app.config import Settings
from app.detection.ai_domains import Classifier
from app.detection.correlate import IncidentDraft, parse_hosts
from app.detection.run import detect
from app.generator import Generator, GeneratorConfig
from app.parsing.csv_parser import CsvParser
from app.pipeline.aggregates import duckdb_connection
from app.pipeline.pass1 import PARQUET_SCHEMA, _values

DEFAULT_SEEDS = (42, 7, 123, 2026, 99)
PRIORITIES = ("critical", "high", "medium", "low")
RANK = {p: i for i, p in enumerate(PRIORITIES)}  # lower = worse
APPROVED = parse_hosts(Settings.model_fields["approved_upload_hosts"].default)  # no DB/env needed
# Plants only the AI domain classifier can see (D136): evaluated only when a classifier is given,
# and judged by "an incident covers it" (any priority; a brand look-alike alone is medium, D137).
AI_ONLY_KINDS = {"lookalike_domain"}


@dataclass
class Evaluation:
    seeds: list[int]
    # planted attack kind -> seed -> best priority of an incident covering it (None = not covered)
    attacks: dict[str, dict[int, str | None]] = field(default_factory=dict)
    # benign look-alike kind -> seed -> highest priority it reached in the attack-free week
    lookalikes: dict[str, dict[int, str | None]] = field(default_factory=dict)
    # seed -> incident counts per priority, attack-free week
    clean: dict[int, dict[str, int]] = field(default_factory=dict)
    # AI-only plant kind -> seed -> priority of the covering incident (only with a classifier)
    ai_attacks: dict[str, dict[int, str | None]] = field(default_factory=dict)

    def missed_ai_attacks(self) -> list[tuple[str, int]]:
        return [(kind, seed) for kind, by_seed in self.ai_attacks.items() for seed, p in by_seed.items() if p is None]

    def missed_attacks(self) -> list[tuple[str, int]]:
        return [(kind, seed) for kind, by_seed in self.attacks.items() for seed, p in by_seed.items()
                if p is None or RANK[p] > RANK["medium"]]

    def raised_lookalikes(self) -> list[tuple[str, int, str]]:
        return [(kind, seed, p) for kind, by_seed in self.lookalikes.items() for seed, p in by_seed.items()
                if p is not None and RANK[p] <= RANK["medium"]]

    def clean_false_alarms(self) -> int:
        return sum(c["critical"] + c["high"] + c["medium"] for c in self.clean.values())


def _week(seed: int, clean: bool, workdir: Path, classify: Classifier | None = None,
          ) -> tuple[Generator, dict[int, tuple[str, datetime]], list[IncidentDraft]]:
    """Generate one week, run the real detection, return (generator, line -> (user, ts), incidents)."""
    out = io.StringIO()
    generator = Generator(GeneratorConfig(seed=seed, clean=clean))
    generator.write(out)
    out.seek(0)
    events = list(CsvParser(UTC).parse(out))
    columns = list(zip(*(_values(e) for e in events)))
    path = workdir / f"{seed}-{clean}.parquet"
    pq.write_table(pa.Table.from_arrays(
        [pa.array(c, type=f.type) for c, f in zip(columns, PARQUET_SCHEMA)], schema=PARQUET_SCHEMA), path)
    lines = {e.line_no: (e.username, e.ts) for e in events}
    return generator, lines, detect(duckdb_connection(), path, UTC, APPROVED, classify_domains=classify).incidents


def _worst_covering(line_nos: list[int], lines, incidents: list[IncidentDraft]) -> str | None:
    """Highest priority among incidents that cover any of these lines (None if none do)."""
    best = None
    for line_no in line_nos:
        user, ts = lines[line_no]
        for incident in incidents:
            if incident.username == user and incident.start <= ts <= incident.end:
                if best is None or RANK[incident.priority] < RANK[best]:
                    best = incident.priority
    return best


def evaluate(seeds=DEFAULT_SEEDS, classify: Classifier | None = None) -> Evaluation:
    result = Evaluation(seeds=list(seeds))
    with tempfile.TemporaryDirectory() as tmp:
        for seed in seeds:
            for clean in (False, True):
                generator, lines, incidents = _week(seed, clean, Path(tmp), classify)
                if clean:
                    result.clean[seed] = {p: sum(i.priority == p for i in incidents) for p in PRIORITIES}
                    for lookalike in generator.benign.values():
                        if lookalike.line_nos:  # evening workers are a pattern, not specific lines
                            result.lookalikes.setdefault(lookalike.kind, {})[seed] = _worst_covering(
                                lookalike.line_nos, lines, incidents)
                else:
                    for plant in generator.plants:
                        if plant.kind in AI_ONLY_KINDS:
                            if classify is not None:
                                result.ai_attacks.setdefault(plant.kind, {})[seed] = _worst_covering(
                                    plant.line_nos, lines, incidents)
                            continue
                        result.attacks.setdefault(plant.kind, {})[seed] = _worst_covering(plant.line_nos, lines, incidents)
    return result


def markdown(result: Evaluation) -> str:
    def cell(p: str | None) -> str:
        return p or "—"

    head = "| | " + " | ".join(f"seed {s}" for s in result.seeds) + " |\n|---|" + "---|" * len(result.seeds) + "\n"
    parts = ["**Planted attacks: priority of the incident that covers them** (goal: medium or higher)\n\n" + head
             + "".join(f"| {kind} | " + " | ".join(cell(row.get(s)) for s in result.seeds) + " |\n"
                       for kind, row in result.attacks.items())]
    parts.append("**Innocent look-alikes (attack-free weeks): highest priority they reached** (goal: low or none)\n\n" + head
                 + "".join(f"| {kind} | " + " | ".join(cell(row.get(s)) for s in result.seeds) + " |\n"
                           for kind, row in result.lookalikes.items()))
    parts.append("**Attack-free weeks: incidents per priority** (goal: no medium or higher)\n\n" + head
                 + "".join(f"| {p} | " + " | ".join(str(result.clean[s][p]) for s in result.seeds) + " |\n"
                           for p in PRIORITIES))
    if result.ai_attacks:
        parts.append("**AI-only plants: priority of the covering incident** (goal: covered)\n\n"
                     + head + "".join(f"| {kind} | " + " | ".join(cell(row.get(s)) for s in result.seeds) + " |\n"
                                      for kind, row in result.ai_attacks.items()))
    verdict = (f"Missed attacks: {len(result.missed_attacks())} · look-alikes at medium+: "
               f"{len(result.raised_lookalikes())} · clean-week medium+ incidents: {result.clean_false_alarms()}")
    return "\n".join(parts) + "\n" + verdict + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--ai", action="store_true", help="also run the AI domain classifier (needs ANTHROPIC_API_KEY)")
    args = parser.parse_args()
    print(markdown(evaluate(args.seeds, live_classifier() if args.ai else None)))


def live_classifier() -> Classifier:
    """Real Claude calls with an in-memory cache (domains repeat across seeds)."""
    from app.config import get_settings
    from app.llm.domains import classify_domains

    settings, cache = get_settings(), {}
    if not settings.anthropic_api_key:
        raise SystemExit("--ai needs ANTHROPIC_API_KEY")

    def classify(candidates):
        new = classify_domains([c for c in candidates if c.host not in cache], api_key=settings.anthropic_api_key,
                               model=settings.anthropic_model, timeout=settings.llm_review_timeout_seconds)
        cache.update(new)
        return {c.host: cache[c.host] for c in candidates if c.host in cache}

    return classify


if __name__ == "__main__":
    main()
