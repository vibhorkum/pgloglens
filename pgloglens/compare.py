"""Diff and comparison functionality for pgloglens.

Compare two log analyses or saved artifacts to identify:
- What got slower
- What got noisier (more errors)
- New errors that appeared
- Errors that disappeared
- Changes in checkpoints, temp files, deadlocks
- Changes in auth failures and cancellations
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import AnalysisResult, ErrorPattern, SlowQuery


@dataclass
class QueryDiff:
    """Difference in a single query pattern."""

    normalized_query: str
    query_type: str = "unknown"

    # Before metrics (None if query is new)
    before_count: Optional[int] = None
    before_avg_ms: Optional[float] = None
    before_max_ms: Optional[float] = None
    before_p95_ms: Optional[float] = None
    before_total_ms: Optional[float] = None

    # After metrics (None if query disappeared)
    after_count: Optional[int] = None
    after_avg_ms: Optional[float] = None
    after_max_ms: Optional[float] = None
    after_p95_ms: Optional[float] = None
    after_total_ms: Optional[float] = None

    # Computed deltas
    count_delta: int = 0
    avg_ms_delta: float = 0.0
    max_ms_delta: float = 0.0
    p95_ms_delta: float = 0.0
    total_ms_delta: float = 0.0

    # Classification
    status: str = "unchanged"  # new, disappeared, faster, slower, unchanged

    def compute_deltas(self) -> None:
        """Compute delta values."""
        if self.before_count is None and self.after_count is not None:
            self.status = "new"
        elif self.after_count is None and self.before_count is not None:
            self.status = "disappeared"
        elif self.before_count is not None and self.after_count is not None:
            self.count_delta = self.after_count - self.before_count
            self.avg_ms_delta = (self.after_avg_ms or 0) - (self.before_avg_ms or 0)
            self.max_ms_delta = (self.after_max_ms or 0) - (self.before_max_ms or 0)
            self.p95_ms_delta = (self.after_p95_ms or 0) - (self.before_p95_ms or 0)
            self.total_ms_delta = (self.after_total_ms or 0) - (self.before_total_ms or 0)

            # Determine if slower or faster (based on p95 change)
            if self.p95_ms_delta > 0 and abs(self.p95_ms_delta) > (self.before_p95_ms or 1) * 0.1:
                self.status = "slower"
            elif self.p95_ms_delta < 0 and abs(self.p95_ms_delta) > (self.before_p95_ms or 1) * 0.1:
                self.status = "faster"
            else:
                self.status = "unchanged"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "normalized_query": self.normalized_query,
            "query_type": self.query_type,
            "status": self.status,
            "before": {
                "count": self.before_count,
                "avg_ms": self.before_avg_ms,
                "max_ms": self.before_max_ms,
                "p95_ms": self.before_p95_ms,
                "total_ms": self.before_total_ms,
            } if self.before_count is not None else None,
            "after": {
                "count": self.after_count,
                "avg_ms": self.after_avg_ms,
                "max_ms": self.after_max_ms,
                "p95_ms": self.after_p95_ms,
                "total_ms": self.after_total_ms,
            } if self.after_count is not None else None,
            "deltas": {
                "count": self.count_delta,
                "avg_ms": round(self.avg_ms_delta, 2),
                "max_ms": round(self.max_ms_delta, 2),
                "p95_ms": round(self.p95_ms_delta, 2),
                "total_ms": round(self.total_ms_delta, 2),
            },
        }


@dataclass
class ErrorDiff:
    """Difference in error patterns."""

    message_pattern: str
    error_code: Optional[str] = None
    category: str = "unknown"

    before_count: Optional[int] = None
    after_count: Optional[int] = None
    count_delta: int = 0
    status: str = "unchanged"  # new, disappeared, increased, decreased, unchanged

    def compute_deltas(self) -> None:
        """Compute delta values."""
        if self.before_count is None and self.after_count is not None:
            self.status = "new"
            self.count_delta = self.after_count
        elif self.after_count is None and self.before_count is not None:
            self.status = "disappeared"
            self.count_delta = -self.before_count
        elif self.before_count is not None and self.after_count is not None:
            self.count_delta = self.after_count - self.before_count
            if self.count_delta > 0 and self.count_delta > self.before_count * 0.2:
                self.status = "increased"
            elif self.count_delta < 0 and abs(self.count_delta) > self.before_count * 0.2:
                self.status = "decreased"
            else:
                self.status = "unchanged"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_pattern": self.message_pattern,
            "error_code": self.error_code,
            "category": self.category,
            "status": self.status,
            "before_count": self.before_count,
            "after_count": self.after_count,
            "count_delta": self.count_delta,
        }


@dataclass
class ComparisonResult:
    """Complete comparison between two analyses."""

    # Metadata
    before_label: str = "before"
    after_label: str = "after"
    before_time_range: Optional[Tuple[datetime, datetime]] = None
    after_time_range: Optional[Tuple[datetime, datetime]] = None

    # Query diffs
    query_diffs: List[QueryDiff] = field(default_factory=list)
    new_queries: List[QueryDiff] = field(default_factory=list)
    disappeared_queries: List[QueryDiff] = field(default_factory=list)
    slower_queries: List[QueryDiff] = field(default_factory=list)
    faster_queries: List[QueryDiff] = field(default_factory=list)

    # Error diffs
    error_diffs: List[ErrorDiff] = field(default_factory=list)
    new_errors: List[ErrorDiff] = field(default_factory=list)
    disappeared_errors: List[ErrorDiff] = field(default_factory=list)
    increased_errors: List[ErrorDiff] = field(default_factory=list)

    # Metric diffs
    total_entries_delta: int = 0
    slow_query_count_delta: int = 0
    error_count_delta: int = 0
    deadlock_delta: int = 0
    lock_event_delta: int = 0
    checkpoint_delta: int = 0
    checkpoint_duration_delta: float = 0.0
    temp_file_delta: int = 0
    temp_file_size_delta: float = 0.0
    auth_failure_delta: int = 0
    cancellation_delta: int = 0
    peak_connections_delta: int = 0

    # Before/after raw values for context
    before_metrics: Dict[str, Any] = field(default_factory=dict)
    after_metrics: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        """Get a summary of changes."""
        return {
            "queries": {
                "new": len(self.new_queries),
                "disappeared": len(self.disappeared_queries),
                "slower": len(self.slower_queries),
                "faster": len(self.faster_queries),
            },
            "errors": {
                "new": len(self.new_errors),
                "disappeared": len(self.disappeared_errors),
                "increased": len(self.increased_errors),
            },
            "metrics": {
                "entries_delta": self.total_entries_delta,
                "slow_queries_delta": self.slow_query_count_delta,
                "errors_delta": self.error_count_delta,
                "deadlocks_delta": self.deadlock_delta,
                "checkpoints_delta": self.checkpoint_delta,
                "temp_files_delta": self.temp_file_delta,
                "auth_failures_delta": self.auth_failure_delta,
                "cancellations_delta": self.cancellation_delta,
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "metadata": {
                "before_label": self.before_label,
                "after_label": self.after_label,
                "before_time_range": (
                    [t.isoformat() for t in self.before_time_range]
                    if self.before_time_range else None
                ),
                "after_time_range": (
                    [t.isoformat() for t in self.after_time_range]
                    if self.after_time_range else None
                ),
            },
            "summary": self.summary(),
            "queries": {
                "new": [q.to_dict() for q in self.new_queries],
                "disappeared": [q.to_dict() for q in self.disappeared_queries],
                "slower": [q.to_dict() for q in self.slower_queries],
                "faster": [q.to_dict() for q in self.faster_queries],
            },
            "errors": {
                "new": [e.to_dict() for e in self.new_errors],
                "disappeared": [e.to_dict() for e in self.disappeared_errors],
                "increased": [e.to_dict() for e in self.increased_errors],
            },
            "before_metrics": self.before_metrics,
            "after_metrics": self.after_metrics,
        }


def compare_results(
    before: AnalysisResult,
    after: AnalysisResult,
    before_label: str = "before",
    after_label: str = "after",
) -> ComparisonResult:
    """Compare two AnalysisResult objects.

    Args:
        before: The baseline analysis
        after: The new analysis to compare
        before_label: Label for the baseline (e.g., "prod-v1.2")
        after_label: Label for the new analysis (e.g., "prod-v1.3")

    Returns:
        ComparisonResult with all diffs
    """
    result = ComparisonResult(
        before_label=before_label,
        after_label=after_label,
    )

    # Time ranges
    if before.time_range_start and before.time_range_end:
        result.before_time_range = (before.time_range_start, before.time_range_end)
    if after.time_range_start and after.time_range_end:
        result.after_time_range = (after.time_range_start, after.time_range_end)

    # Compare queries
    _compare_queries(before, after, result)

    # Compare errors
    _compare_errors(before, after, result)

    # Compare metrics
    _compare_metrics(before, after, result)

    return result


def _compare_queries(
    before: AnalysisResult,
    after: AnalysisResult,
    result: ComparisonResult,
) -> None:
    """Compare slow query patterns."""
    before_queries: Dict[str, SlowQuery] = {
        sq.normalized_query: sq for sq in before.slow_queries
    }
    after_queries: Dict[str, SlowQuery] = {
        sq.normalized_query: sq for sq in after.slow_queries
    }

    all_queries = set(before_queries.keys()) | set(after_queries.keys())

    for nq in all_queries:
        bq = before_queries.get(nq)
        aq = after_queries.get(nq)

        diff = QueryDiff(
            normalized_query=nq,
            query_type=getattr(aq or bq, "query_type", "unknown"),
        )

        if bq:
            diff.before_count = bq.count
            diff.before_avg_ms = bq.avg_duration_ms
            diff.before_max_ms = bq.max_duration_ms
            diff.before_p95_ms = bq.p95_duration_ms
            diff.before_total_ms = bq.total_duration_ms

        if aq:
            diff.after_count = aq.count
            diff.after_avg_ms = aq.avg_duration_ms
            diff.after_max_ms = aq.max_duration_ms
            diff.after_p95_ms = aq.p95_duration_ms
            diff.after_total_ms = aq.total_duration_ms

        diff.compute_deltas()
        result.query_diffs.append(diff)

        # Categorize
        if diff.status == "new":
            result.new_queries.append(diff)
        elif diff.status == "disappeared":
            result.disappeared_queries.append(diff)
        elif diff.status == "slower":
            result.slower_queries.append(diff)
        elif diff.status == "faster":
            result.faster_queries.append(diff)

    # Sort by impact
    result.slower_queries.sort(key=lambda d: d.p95_ms_delta, reverse=True)
    result.faster_queries.sort(key=lambda d: d.p95_ms_delta)
    result.new_queries.sort(key=lambda d: d.after_total_ms or 0, reverse=True)


def _compare_errors(
    before: AnalysisResult,
    after: AnalysisResult,
    result: ComparisonResult,
) -> None:
    """Compare error patterns."""
    before_errors: Dict[str, ErrorPattern] = {
        ep.message_pattern: ep for ep in before.error_patterns
    }
    after_errors: Dict[str, ErrorPattern] = {
        ep.message_pattern: ep for ep in after.error_patterns
    }

    all_patterns = set(before_errors.keys()) | set(after_errors.keys())

    for pattern in all_patterns:
        be = before_errors.get(pattern)
        ae = after_errors.get(pattern)

        diff = ErrorDiff(
            message_pattern=pattern,
            error_code=(ae or be).error_code if (ae or be) else None,
            category=(ae or be).category if (ae or be) else "unknown",
            before_count=be.count if be else None,
            after_count=ae.count if ae else None,
        )

        diff.compute_deltas()
        result.error_diffs.append(diff)

        if diff.status == "new":
            result.new_errors.append(diff)
        elif diff.status == "disappeared":
            result.disappeared_errors.append(diff)
        elif diff.status == "increased":
            result.increased_errors.append(diff)

    # Sort by impact
    result.new_errors.sort(key=lambda d: d.after_count or 0, reverse=True)
    result.increased_errors.sort(key=lambda d: d.count_delta, reverse=True)


def _compare_metrics(
    before: AnalysisResult,
    after: AnalysisResult,
    result: ComparisonResult,
) -> None:
    """Compare aggregate metrics."""
    # Compute deltas
    result.total_entries_delta = after.total_entries - before.total_entries
    result.slow_query_count_delta = len(after.slow_queries) - len(before.slow_queries)
    result.error_count_delta = len(after.error_patterns) - len(before.error_patterns)
    result.deadlock_delta = after.deadlock_count - before.deadlock_count
    result.lock_event_delta = len(after.lock_events) - len(before.lock_events)
    result.checkpoint_delta = after.checkpoint_stats.count - before.checkpoint_stats.count
    result.checkpoint_duration_delta = (
        after.checkpoint_stats.avg_duration_ms - before.checkpoint_stats.avg_duration_ms
    )
    result.temp_file_delta = len(after.temp_files) - len(before.temp_files)
    result.temp_file_size_delta = (
        sum(t.size_mb for t in after.temp_files) -
        sum(t.size_mb for t in before.temp_files)
    )
    result.auth_failure_delta = (
        after.connection_stats.auth_failures - before.connection_stats.auth_failures
    )
    result.cancellation_delta = (
        len(getattr(after, "cancelled_queries", [])) -
        len(getattr(before, "cancelled_queries", []))
    )
    result.peak_connections_delta = (
        after.connection_stats.peak_concurrent - before.connection_stats.peak_concurrent
    )

    # Store raw metrics for context
    result.before_metrics = {
        "total_entries": before.total_entries,
        "slow_queries": len(before.slow_queries),
        "error_patterns": len(before.error_patterns),
        "deadlocks": before.deadlock_count,
        "lock_events": len(before.lock_events),
        "checkpoints": before.checkpoint_stats.count,
        "checkpoint_avg_ms": before.checkpoint_stats.avg_duration_ms,
        "temp_files": len(before.temp_files),
        "temp_file_mb": sum(t.size_mb for t in before.temp_files),
        "auth_failures": before.connection_stats.auth_failures,
        "cancellations": len(getattr(before, "cancelled_queries", [])),
        "peak_connections": before.connection_stats.peak_concurrent,
    }

    result.after_metrics = {
        "total_entries": after.total_entries,
        "slow_queries": len(after.slow_queries),
        "error_patterns": len(after.error_patterns),
        "deadlocks": after.deadlock_count,
        "lock_events": len(after.lock_events),
        "checkpoints": after.checkpoint_stats.count,
        "checkpoint_avg_ms": after.checkpoint_stats.avg_duration_ms,
        "temp_files": len(after.temp_files),
        "temp_file_mb": sum(t.size_mb for t in after.temp_files),
        "auth_failures": after.connection_stats.auth_failures,
        "cancellations": len(getattr(after, "cancelled_queries", [])),
        "peak_connections": after.connection_stats.peak_concurrent,
    }


def save_analysis_artifact(
    result: AnalysisResult,
    path: str,
    label: Optional[str] = None,
) -> None:
    """Save analysis result as a JSON artifact for later comparison.

    Args:
        result: The AnalysisResult to save
        path: File path to save to (should end with .json)
        label: Optional label for the artifact
    """
    artifact = {
        "version": "1.0",
        "label": label or "analysis",
        "created_at": datetime.now().isoformat(),
        "analysis": json.loads(result.model_dump_json()),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, default=str)


def load_analysis_artifact(path: str) -> Tuple[AnalysisResult, Dict[str, Any]]:
    """Load a saved analysis artifact.

    Args:
        path: Path to the JSON artifact

    Returns:
        Tuple of (AnalysisResult, metadata_dict)
    """
    with open(path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    # Reconstruct AnalysisResult
    analysis_data = artifact.get("analysis", artifact)
    result = AnalysisResult.model_validate(analysis_data)

    metadata = {
        "version": artifact.get("version", "unknown"),
        "label": artifact.get("label", "unknown"),
        "created_at": artifact.get("created_at"),
    }

    return result, metadata


def render_comparison_text(comp: ComparisonResult) -> str:
    """Render comparison as plain text."""
    lines = []
    lines.append("=" * 70)
    lines.append("COMPARISON REPORT")
    lines.append(f"  {comp.before_label} → {comp.after_label}")
    lines.append("=" * 70)

    summary = comp.summary()

    # Queries section
    lines.append("\n## SLOW QUERIES\n")
    lines.append(f"  New queries:         {summary['queries']['new']}")
    lines.append(f"  Disappeared queries: {summary['queries']['disappeared']}")
    lines.append(f"  Slower queries:      {summary['queries']['slower']}")
    lines.append(f"  Faster queries:      {summary['queries']['faster']}")

    if comp.slower_queries:
        lines.append("\n  ### Got Slower:")
        for q in comp.slower_queries[:5]:
            lines.append(
                f"    +{q.p95_ms_delta:+.0f}ms p95 | {q.normalized_query[:60]}..."
            )

    if comp.new_queries:
        lines.append("\n  ### New Queries:")
        for q in comp.new_queries[:5]:
            lines.append(
                f"    {q.after_p95_ms:.0f}ms p95 | {q.normalized_query[:60]}..."
            )

    # Errors section
    lines.append("\n## ERRORS\n")
    lines.append(f"  New errors:         {summary['errors']['new']}")
    lines.append(f"  Disappeared errors: {summary['errors']['disappeared']}")
    lines.append(f"  Increased errors:   {summary['errors']['increased']}")

    if comp.new_errors:
        lines.append("\n  ### New Errors:")
        for e in comp.new_errors[:5]:
            lines.append(f"    [{e.error_code or '?'}] {e.after_count}x | {e.message_pattern[:50]}...")

    if comp.increased_errors:
        lines.append("\n  ### Increased Errors:")
        for e in comp.increased_errors[:5]:
            lines.append(
                f"    +{e.count_delta} ({e.before_count}→{e.after_count}) | {e.message_pattern[:50]}..."
            )

    # Metrics section
    lines.append("\n## METRICS DELTA\n")

    def _format_delta(name: str, delta: int | float, unit: str = "") -> str:
        sign = "+" if delta > 0 else ""
        return f"  {name:25s} {sign}{delta:.0f}{unit}"

    lines.append(_format_delta("Total entries:", comp.total_entries_delta))
    lines.append(_format_delta("Slow query patterns:", comp.slow_query_count_delta))
    lines.append(_format_delta("Error patterns:", comp.error_count_delta))
    lines.append(_format_delta("Deadlocks:", comp.deadlock_delta))
    lines.append(_format_delta("Lock events:", comp.lock_event_delta))
    lines.append(_format_delta("Checkpoints:", comp.checkpoint_delta))
    lines.append(_format_delta("Checkpoint avg duration:", comp.checkpoint_duration_delta, "ms"))
    lines.append(_format_delta("Temp files:", comp.temp_file_delta))
    lines.append(_format_delta("Temp file size:", comp.temp_file_size_delta, "MB"))
    lines.append(_format_delta("Auth failures:", comp.auth_failure_delta))
    lines.append(_format_delta("Cancellations:", comp.cancellation_delta))
    lines.append(_format_delta("Peak connections:", comp.peak_connections_delta))

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def render_comparison_markdown(comp: ComparisonResult) -> str:
    """Render comparison as Markdown."""
    lines = []
    lines.append("# Comparison Report\n")
    lines.append(f"**{comp.before_label}** → **{comp.after_label}**\n")

    summary = comp.summary()

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Category | Before | After | Delta |")
    lines.append("|----------|--------|-------|-------|")
    lines.append(
        f"| Slow queries | {comp.before_metrics.get('slow_queries', 0)} | "
        f"{comp.after_metrics.get('slow_queries', 0)} | "
        f"{comp.slow_query_count_delta:+d} |"
    )
    lines.append(
        f"| Error patterns | {comp.before_metrics.get('error_patterns', 0)} | "
        f"{comp.after_metrics.get('error_patterns', 0)} | "
        f"{comp.error_count_delta:+d} |"
    )
    lines.append(
        f"| Deadlocks | {comp.before_metrics.get('deadlocks', 0)} | "
        f"{comp.after_metrics.get('deadlocks', 0)} | "
        f"{comp.deadlock_delta:+d} |"
    )
    lines.append(
        f"| Auth failures | {comp.before_metrics.get('auth_failures', 0)} | "
        f"{comp.after_metrics.get('auth_failures', 0)} | "
        f"{comp.auth_failure_delta:+d} |"
    )
    lines.append("")

    # Slower queries
    if comp.slower_queries:
        lines.append("## Queries That Got Slower\n")
        lines.append("| P95 Delta | Query |")
        lines.append("|-----------|-------|")
        for q in comp.slower_queries[:10]:
            lines.append(f"| +{q.p95_ms_delta:.0f}ms | `{q.normalized_query[:80]}` |")
        lines.append("")

    # New queries
    if comp.new_queries:
        lines.append("## New Slow Queries\n")
        lines.append("| P95 | Count | Query |")
        lines.append("|-----|-------|-------|")
        for q in comp.new_queries[:10]:
            lines.append(
                f"| {q.after_p95_ms:.0f}ms | {q.after_count} | `{q.normalized_query[:60]}` |"
            )
        lines.append("")

    # New errors
    if comp.new_errors:
        lines.append("## New Error Patterns\n")
        lines.append("| SQLSTATE | Count | Pattern |")
        lines.append("|----------|-------|---------|")
        for e in comp.new_errors[:10]:
            lines.append(f"| {e.error_code or '—'} | {e.after_count} | {e.message_pattern[:60]} |")
        lines.append("")

    # Increased errors
    if comp.increased_errors:
        lines.append("## Errors That Increased\n")
        lines.append("| Delta | Before | After | Pattern |")
        lines.append("|-------|--------|-------|---------|")
        for e in comp.increased_errors[:10]:
            lines.append(
                f"| +{e.count_delta} | {e.before_count} | {e.after_count} | "
                f"{e.message_pattern[:50]} |"
            )
        lines.append("")

    return "\n".join(lines)
