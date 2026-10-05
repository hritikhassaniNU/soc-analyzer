"""The statistics layer in one call (stored as anomalies with source='stat' by pass 2)."""

from datetime import UTC, tzinfo
from pathlib import Path

import duckdb

from app.detection.beaconing import detect_beaconing
from app.detection.behavior import detect_behavior
from app.detection.findings import Finding
from app.detection.rare_domains import detect_rare_domains


def detect_statistical(con: duckdb.DuckDBPyConnection, parquet: Path, log_tz: tzinfo = UTC) -> list[Finding]:
    return (detect_behavior(con, parquet, log_tz)  # bursts, large uploads, off-hours
            + detect_beaconing(con, parquet)
            + detect_rare_domains(con, parquet))
