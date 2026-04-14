"""Optional pg_stat_statements snapshot import and correlation.

This module provides LIMITED optional integration with pg_stat_statements:
- Import a snapshot/export from pg_stat_statements
- Correlate with query fingerprints from log analysis
- NO live database connection required for main workflow

The primary workflow remains log-only analysis. This is an optional
enhancement for users who want to correlate log data with cumulative stats.

Usage:
    # Export pg_stat_statements to JSON (run this separately)
    psql -c "SELECT * FROM pg_stat_statements" -o pgss_snapshot.json -t

    # Import and correlate
    pgloglens analyze postgresql.log --pgss-snapshot pgss_snapshot.json
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .analyzer import normalize_query
from .models import AnalysisResult, SlowQuery


@dataclass
class PgssEntry:
    """A single entry from pg_stat_statements."""

    queryid: Optional[int] = None
    query: str = ""
    normalized_query: str = ""
    calls: int = 0
    total_exec_time_ms: float = 0.0
    mean_exec_time_ms: float = 0.0
    min_exec_time_ms: float = 0.0
    max_exec_time_ms: float = 0.0
    stddev_exec_time_ms: float = 0.0
    rows: int = 0
    shared_blks_hit: int = 0
    shared_blks_read: int = 0
    shared_blks_dirtied: int = 0
    shared_blks_written: int = 0
    local_blks_hit: int = 0
    local_blks_read: int = 0
    temp_blks_read: int = 0
    temp_blks_written: int = 0
    blk_read_time_ms: float = 0.0
    blk_write_time_ms: float = 0.0
    wal_records: int = 0
    wal_fpi: int = 0
    wal_bytes: int = 0
    userid: Optional[int] = None
    dbid: Optional[int] = None
    toplevel: bool = True

    # Computed
    cache_hit_ratio: float = 0.0

    def compute_derived(self) -> None:
        """Compute derived metrics."""
        total_blks = self.shared_blks_hit + self.shared_blks_read
        if total_blks > 0:
            self.cache_hit_ratio = self.shared_blks_hit / total_blks * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "queryid": self.queryid,
            "query": self.query[:500],
            "normalized_query": self.normalized_query[:500],
            "calls": self.calls,
            "total_exec_time_ms": round(self.total_exec_time_ms, 2),
            "mean_exec_time_ms": round(self.mean_exec_time_ms, 2),
            "max_exec_time_ms": round(self.max_exec_time_ms, 2),
            "rows": self.rows,
            "cache_hit_ratio": round(self.cache_hit_ratio, 2),
            "temp_blks_read": self.temp_blks_read,
            "temp_blks_written": self.temp_blks_written,
        }


@dataclass
class PgssSnapshot:
    """A snapshot of pg_stat_statements data."""

    entries: List[PgssEntry] = field(default_factory=list)
    snapshot_time: Optional[datetime] = None
    database: Optional[str] = None
    total_queries: int = 0
    total_calls: int = 0
    total_exec_time_ms: float = 0.0

    # Index by normalized query for correlation
    _by_normalized: Dict[str, PgssEntry] = field(default_factory=dict)
    _by_queryid: Dict[int, PgssEntry] = field(default_factory=dict)

    def build_indexes(self) -> None:
        """Build indexes for efficient lookup."""
        self._by_normalized = {}
        self._by_queryid = {}

        for entry in self.entries:
            # Normalize for matching
            if entry.query:
                entry.normalized_query = normalize_query(entry.query)
                self._by_normalized[entry.normalized_query] = entry

            if entry.queryid:
                self._by_queryid[entry.queryid] = entry

        self.total_queries = len(self.entries)
        self.total_calls = sum(e.calls for e in self.entries)
        self.total_exec_time_ms = sum(e.total_exec_time_ms for e in self.entries)

    def lookup_by_normalized(self, normalized_query: str) -> Optional[PgssEntry]:
        """Look up an entry by normalized query."""
        return self._by_normalized.get(normalized_query)

    def lookup_by_queryid(self, queryid: int) -> Optional[PgssEntry]:
        """Look up an entry by queryid."""
        return self._by_queryid.get(queryid)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "snapshot_time": self.snapshot_time.isoformat() if self.snapshot_time else None,
            "database": self.database,
            "total_queries": self.total_queries,
            "total_calls": self.total_calls,
            "total_exec_time_ms": round(self.total_exec_time_ms, 2),
            "entries": [e.to_dict() for e in self.entries[:100]],  # Limit for JSON
        }


@dataclass
class CorrelationResult:
    """Result of correlating log analysis with pg_stat_statements."""

    # Queries found in both log and pgss
    matched_queries: List[Dict[str, Any]] = field(default_factory=list)

    # Queries in log but not in pgss (possibly dynamic SQL)
    log_only_queries: List[str] = field(default_factory=list)

    # Queries in pgss but not in log (below log threshold)
    pgss_only_queries: List[str] = field(default_factory=list)

    # Summary stats
    match_rate: float = 0.0
    total_log_queries: int = 0
    total_pgss_queries: int = 0
    matched_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "match_rate": round(self.match_rate * 100, 1),
            "total_log_queries": self.total_log_queries,
            "total_pgss_queries": self.total_pgss_queries,
            "matched_count": self.matched_count,
            "matched_queries": self.matched_queries[:50],
            "log_only_count": len(self.log_only_queries),
            "pgss_only_count": len(self.pgss_only_queries),
        }


def load_pgss_snapshot(path: str) -> PgssSnapshot:
    """Load a pg_stat_statements snapshot from file.

    Supports multiple formats:
    - JSON (from psql -t or pg_stat_statements_info())
    - CSV (from COPY or psql -c with csv output)
    - Plain text (from psql default output)

    Args:
        path: Path to the snapshot file

    Returns:
        PgssSnapshot object
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"PGSS snapshot not found: {path}")

    content = path_obj.read_text(encoding="utf-8")
    snapshot = PgssSnapshot(snapshot_time=datetime.now())

    # Detect format and parse
    content_stripped = content.strip()

    if content_stripped.startswith("[") or content_stripped.startswith("{"):
        # JSON format
        entries = _parse_pgss_json(content)
    elif "," in content_stripped.split("\n")[0] and content_stripped.count(",") > 5:
        # CSV format
        entries = _parse_pgss_csv(content)
    else:
        # Try to parse as psql output
        entries = _parse_pgss_text(content)

    snapshot.entries = entries

    # Compute derived metrics
    for entry in snapshot.entries:
        entry.compute_derived()

    snapshot.build_indexes()

    return snapshot


def _parse_pgss_json(content: str) -> List[PgssEntry]:
    """Parse JSON format pg_stat_statements output."""
    data = json.loads(content)

    # Handle array of objects
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and "rows" in data:
        rows = data["rows"]
    elif isinstance(data, dict):
        rows = [data]
    else:
        return []

    entries = []
    for row in rows:
        entry = PgssEntry(
            queryid=row.get("queryid"),
            query=row.get("query", ""),
            calls=int(row.get("calls", 0)),
            total_exec_time_ms=float(row.get("total_exec_time", row.get("total_time", 0))) * 1000
                if row.get("total_exec_time") or row.get("total_time") else 0,
            mean_exec_time_ms=float(row.get("mean_exec_time", row.get("mean_time", 0))) * 1000
                if row.get("mean_exec_time") or row.get("mean_time") else 0,
            min_exec_time_ms=float(row.get("min_exec_time", row.get("min_time", 0))) * 1000
                if row.get("min_exec_time") or row.get("min_time") else 0,
            max_exec_time_ms=float(row.get("max_exec_time", row.get("max_time", 0))) * 1000
                if row.get("max_exec_time") or row.get("max_time") else 0,
            rows=int(row.get("rows", 0)),
            shared_blks_hit=int(row.get("shared_blks_hit", 0)),
            shared_blks_read=int(row.get("shared_blks_read", 0)),
            temp_blks_read=int(row.get("temp_blks_read", 0)),
            temp_blks_written=int(row.get("temp_blks_written", 0)),
            blk_read_time_ms=float(row.get("blk_read_time", 0)),
            blk_write_time_ms=float(row.get("blk_write_time", 0)),
        )
        entries.append(entry)

    return entries


def _parse_pgss_csv(content: str) -> List[PgssEntry]:
    """Parse CSV format pg_stat_statements output."""
    import io

    reader = csv.DictReader(io.StringIO(content))
    entries = []

    for row in reader:
        # Handle various column naming conventions
        entry = PgssEntry(
            queryid=int(row.get("queryid", 0)) if row.get("queryid") else None,
            query=row.get("query", ""),
            calls=int(row.get("calls", 0)),
            total_exec_time_ms=float(row.get("total_exec_time", row.get("total_time", 0))) * 1000,
            mean_exec_time_ms=float(row.get("mean_exec_time", row.get("mean_time", 0))) * 1000,
            rows=int(row.get("rows", 0)),
            shared_blks_hit=int(row.get("shared_blks_hit", 0)),
            shared_blks_read=int(row.get("shared_blks_read", 0)),
            temp_blks_read=int(row.get("temp_blks_read", 0)),
            temp_blks_written=int(row.get("temp_blks_written", 0)),
        )
        entries.append(entry)

    return entries


def _parse_pgss_text(content: str) -> List[PgssEntry]:
    """Parse psql text output format."""
    # This is a best-effort parser for psql's default aligned output
    entries = []
    lines = content.strip().split("\n")

    # Skip header rows
    data_started = False
    for line in lines:
        if line.startswith("-") or not line.strip():
            data_started = True
            continue
        if not data_started:
            continue

        # Try to extract query from the line
        # This is fragile but handles common cases
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                entry = PgssEntry(
                    query=parts[1] if len(parts) > 1 else "",
                    calls=int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                )
                entries.append(entry)

    return entries


def correlate_with_pgss(
    result: AnalysisResult,
    snapshot: PgssSnapshot,
) -> CorrelationResult:
    """Correlate log analysis results with pg_stat_statements snapshot.

    Args:
        result: The AnalysisResult from log analysis
        snapshot: The PgssSnapshot to correlate with

    Returns:
        CorrelationResult with matched and unmatched queries
    """
    correlation = CorrelationResult(
        total_log_queries=len(result.slow_queries),
        total_pgss_queries=snapshot.total_queries,
    )

    matched_normalized = set()

    for sq in result.slow_queries:
        pgss_entry = snapshot.lookup_by_normalized(sq.normalized_query)

        if pgss_entry:
            correlation.matched_queries.append({
                "normalized_query": sq.normalized_query[:200],
                "log": {
                    "count": sq.count,
                    "avg_ms": round(sq.avg_duration_ms, 2),
                    "max_ms": round(sq.max_duration_ms, 2),
                    "p95_ms": round(sq.p95_duration_ms, 2),
                    "total_ms": round(sq.total_duration_ms, 2),
                },
                "pgss": {
                    "calls": pgss_entry.calls,
                    "mean_ms": round(pgss_entry.mean_exec_time_ms, 2),
                    "max_ms": round(pgss_entry.max_exec_time_ms, 2),
                    "total_ms": round(pgss_entry.total_exec_time_ms, 2),
                    "cache_hit_ratio": round(pgss_entry.cache_hit_ratio, 1),
                    "temp_blks_read": pgss_entry.temp_blks_read,
                },
                # Comparison
                "call_ratio": round(sq.count / pgss_entry.calls, 2) if pgss_entry.calls else None,
                "time_delta_ms": round(sq.avg_duration_ms - pgss_entry.mean_exec_time_ms, 2),
            })
            matched_normalized.add(sq.normalized_query)
            correlation.matched_count += 1
        else:
            correlation.log_only_queries.append(sq.normalized_query[:200])

    # Find pgss entries not in log
    for entry in snapshot.entries:
        if entry.normalized_query and entry.normalized_query not in matched_normalized:
            correlation.pgss_only_queries.append(entry.normalized_query[:200])

    # Compute match rate
    if correlation.total_log_queries > 0:
        correlation.match_rate = correlation.matched_count / correlation.total_log_queries

    # Sort matched queries by time delta (biggest slowdowns first)
    correlation.matched_queries.sort(
        key=lambda x: x.get("time_delta_ms", 0),
        reverse=True,
    )

    return correlation


def enrich_result_with_pgss(
    result: AnalysisResult,
    snapshot: PgssSnapshot,
) -> None:
    """Enrich AnalysisResult with pg_stat_statements data.

    This modifies the result in-place, adding pgss data to slow queries.

    Args:
        result: The AnalysisResult to enrich
        snapshot: The PgssSnapshot to use
    """
    for sq in result.slow_queries:
        pgss_entry = snapshot.lookup_by_normalized(sq.normalized_query)
        if pgss_entry:
            # Add pgss data as extra attributes
            sq.pgss_calls = pgss_entry.calls
            sq.pgss_total_time_ms = pgss_entry.total_exec_time_ms
            sq.pgss_mean_time_ms = pgss_entry.mean_exec_time_ms
            sq.pgss_cache_hit_ratio = pgss_entry.cache_hit_ratio
            sq.pgss_temp_blks_read = pgss_entry.temp_blks_read
            sq.pgss_temp_blks_written = pgss_entry.temp_blks_written
            sq.pgss_rows = pgss_entry.rows


def export_pgss_query(
    database: str = "postgres",
    output_format: str = "json",
) -> str:
    """Generate SQL query to export pg_stat_statements.

    Args:
        database: Database name to include in query
        output_format: Output format hint (json, csv, text)

    Returns:
        SQL query string
    """
    base_query = """
SELECT
    queryid,
    query,
    calls,
    total_exec_time,
    mean_exec_time,
    min_exec_time,
    max_exec_time,
    stddev_exec_time,
    rows,
    shared_blks_hit,
    shared_blks_read,
    shared_blks_dirtied,
    shared_blks_written,
    temp_blks_read,
    temp_blks_written,
    blk_read_time,
    blk_write_time
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 1000
"""

    if output_format == "json":
        return f"""
COPY (
    SELECT json_agg(row_to_json(t))
    FROM ({base_query}) t
) TO STDOUT;
"""
    elif output_format == "csv":
        return f"""
COPY ({base_query}) TO STDOUT WITH CSV HEADER;
"""
    else:
        return base_query.strip()
