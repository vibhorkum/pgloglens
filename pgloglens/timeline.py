"""Incident timeline reconstruction from PostgreSQL logs.

Builds a narrative timeline of events for incident analysis:
- Error bursts
- Deadlocks and lock waves
- Checkpoint spikes
- Autovacuum events
- Connection storms
- OOM/disk-full moments
- Cancellation waves
- Replication lag spikes
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AnalysisResult,
    AutovacuumStats,
    CheckpointEvent,
    ErrorPattern,
    LockEvent,
    LogEntry,
    ReplicationLagEvent,
    TempFileStats,
)


class EventType(str, Enum):
    """Types of timeline events."""
    ERROR_BURST = "error_burst"
    DEADLOCK = "deadlock"
    LOCK_WAVE = "lock_wave"
    CHECKPOINT_SPIKE = "checkpoint_spike"
    AUTOVACUUM = "autovacuum"
    CONNECTION_STORM = "connection_storm"
    OOM = "oom"
    DISK_FULL = "disk_full"
    CANCELLATION_WAVE = "cancellation_wave"
    REPLICATION_LAG = "replication_lag"
    AUTH_FAILURE_SPIKE = "auth_failure_spike"
    SLOW_QUERY_SPIKE = "slow_query_spike"
    FATAL_PANIC = "fatal_panic"


@dataclass
class TimelineEvent:
    """A single event in the incident timeline."""

    event_type: EventType
    timestamp: datetime
    end_timestamp: Optional[datetime] = None
    severity: str = "medium"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    count: int = 1
    affected_objects: List[str] = field(default_factory=list)
    related_queries: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    raw_events: List[Any] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Duration of the event window."""
        if self.end_timestamp and self.timestamp:
            return (self.end_timestamp - self.timestamp).total_seconds()
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "end_timestamp": self.end_timestamp.isoformat() if self.end_timestamp else None,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "count": self.count,
            "duration_seconds": self.duration_seconds,
            "affected_objects": self.affected_objects[:10],
            "related_queries": self.related_queries[:5],
            "metrics": self.metrics,
        }


@dataclass
class IncidentTimeline:
    """Complete incident timeline from log analysis."""

    events: List[TimelineEvent] = field(default_factory=list)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    total_events: int = 0
    critical_events: int = 0
    high_events: int = 0

    def add_event(self, event: TimelineEvent) -> None:
        """Add an event and update counts."""
        self.events.append(event)
        self.total_events += 1
        if event.severity == "critical":
            self.critical_events += 1
        elif event.severity == "high":
            self.high_events += 1

    def sort_by_time(self) -> None:
        """Sort events chronologically."""
        self.events.sort(key=lambda e: e.timestamp or datetime.min)

    def sort_by_severity(self) -> None:
        """Sort events by severity (critical first)."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.events.sort(key=lambda e: (severity_order.get(e.severity, 5), e.timestamp or datetime.min))

    def get_events_in_window(
        self,
        start: datetime,
        end: datetime,
    ) -> List[TimelineEvent]:
        """Get all events within a time window."""
        return [
            e for e in self.events
            if e.timestamp and start <= e.timestamp <= end
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "time_range_start": self.time_range_start.isoformat() if self.time_range_start else None,
            "time_range_end": self.time_range_end.isoformat() if self.time_range_end else None,
            "total_events": self.total_events,
            "critical_events": self.critical_events,
            "high_events": self.high_events,
            "events": [e.to_dict() for e in self.events],
        }


def build_timeline(result: AnalysisResult, window_minutes: int = 5) -> IncidentTimeline:
    """Build an incident timeline from analysis results.

    Args:
        result: The AnalysisResult from log analysis
        window_minutes: Time window for grouping related events

    Returns:
        IncidentTimeline with all detected events
    """
    timeline = IncidentTimeline(
        time_range_start=result.time_range_start,
        time_range_end=result.time_range_end,
    )

    window = timedelta(minutes=window_minutes)

    # Extract events from various sources
    _add_error_burst_events(timeline, result, window)
    _add_deadlock_events(timeline, result)
    _add_lock_wave_events(timeline, result, window)
    _add_checkpoint_events(timeline, result)
    _add_autovacuum_events(timeline, result)
    _add_connection_storm_events(timeline, result, window)
    _add_fatal_panic_events(timeline, result)
    _add_cancellation_events(timeline, result, window)
    _add_replication_lag_events(timeline, result)
    _add_slow_query_spike_events(timeline, result, window)

    # Sort by time
    timeline.sort_by_time()

    return timeline


def _add_error_burst_events(
    timeline: IncidentTimeline,
    result: AnalysisResult,
    window: timedelta,
) -> None:
    """Detect and add error burst events."""
    # Group errors by time buckets
    error_buckets: Dict[datetime, List[ErrorPattern]] = defaultdict(list)

    for ep in result.error_patterns:
        if ep.first_seen:
            bucket_time = ep.first_seen.replace(second=0, microsecond=0)
            error_buckets[bucket_time].append(ep)

    # Find bursts (>10 errors in a bucket)
    for bucket_time, patterns in error_buckets.items():
        total_count = sum(p.count for p in patterns)
        if total_count >= 10:
            severity = "critical" if total_count >= 50 else ("high" if total_count >= 20 else "medium")

            categories = list(set(p.category for p in patterns))
            sample_messages = []
            for p in patterns[:3]:
                if p.sample_messages:
                    sample_messages.append(p.sample_messages[0][:100])

            timeline.add_event(TimelineEvent(
                event_type=EventType.ERROR_BURST,
                timestamp=bucket_time,
                end_timestamp=bucket_time + window,
                severity=severity,
                title=f"Error burst: {total_count} errors",
                description=f"Categories: {', '.join(categories[:5])}",
                count=total_count,
                affected_objects=categories,
                metrics={"error_count": total_count, "patterns": len(patterns)},
                related_queries=sample_messages,
            ))


def _add_deadlock_events(timeline: IncidentTimeline, result: AnalysisResult) -> None:
    """Add deadlock events to timeline."""
    deadlocks = [e for e in result.lock_events if e.is_deadlock]

    for dl in deadlocks:
        if dl.timestamp:
            timeline.add_event(TimelineEvent(
                event_type=EventType.DEADLOCK,
                timestamp=dl.timestamp,
                severity="high",
                title="Deadlock detected",
                description=(
                    f"Process {dl.waiting_pid} deadlocked with {dl.blocking_pid}"
                    if dl.blocking_pid else f"Process {dl.waiting_pid} in deadlock"
                ),
                affected_objects=[
                    f"pid:{dl.waiting_pid}",
                    f"pid:{dl.blocking_pid}" if dl.blocking_pid else "",
                ],
                related_queries=[
                    dl.waiting_query[:200] if dl.waiting_query else "",
                    dl.blocking_query[:200] if dl.blocking_query else "",
                ],
                metrics={
                    "waiting_pid": dl.waiting_pid,
                    "blocking_pid": dl.blocking_pid,
                    "lock_type": dl.lock_type,
                },
            ))


def _add_lock_wave_events(
    timeline: IncidentTimeline,
    result: AnalysisResult,
    window: timedelta,
) -> None:
    """Detect and add lock wave events (multiple lock waits in short time)."""
    lock_waits = [e for e in result.lock_events if not e.is_deadlock and e.timestamp]

    if len(lock_waits) < 3:
        return

    # Sort by timestamp
    lock_waits.sort(key=lambda e: e.timestamp or datetime.min)

    # Group into waves
    waves: List[List[LockEvent]] = []
    current_wave: List[LockEvent] = []

    for lock in lock_waits:
        if not current_wave:
            current_wave.append(lock)
        elif lock.timestamp and current_wave[-1].timestamp:
            if lock.timestamp - current_wave[-1].timestamp <= window:
                current_wave.append(lock)
            else:
                if len(current_wave) >= 3:
                    waves.append(current_wave)
                current_wave = [lock]

    if len(current_wave) >= 3:
        waves.append(current_wave)

    # Add wave events
    for wave in waves:
        first_ts = wave[0].timestamp
        last_ts = wave[-1].timestamp

        blocking_pids = set(e.blocking_pid for e in wave if e.blocking_pid)
        waiting_pids = set(e.waiting_pid for e in wave if e.waiting_pid)

        severity = "high" if len(wave) >= 10 else "medium"

        timeline.add_event(TimelineEvent(
            event_type=EventType.LOCK_WAVE,
            timestamp=first_ts,
            end_timestamp=last_ts,
            severity=severity,
            title=f"Lock wave: {len(wave)} lock waits",
            description=f"{len(blocking_pids)} blocker(s), {len(waiting_pids)} waiting",
            count=len(wave),
            affected_objects=[f"blocker:{p}" for p in list(blocking_pids)[:5]],
            metrics={
                "lock_count": len(wave),
                "blocking_pids": list(blocking_pids)[:10],
                "waiting_pids": list(waiting_pids)[:10],
            },
        ))


def _add_checkpoint_events(timeline: IncidentTimeline, result: AnalysisResult) -> None:
    """Add significant checkpoint events to timeline."""
    for cp in getattr(result, "checkpoint_events", []):
        if not isinstance(cp, CheckpointEvent):
            continue

        # Only add long checkpoints (>60s) or those with warnings
        if cp.duration_ms < 60000:
            continue

        severity = "high" if cp.duration_ms > 300000 else "medium"

        timeline.add_event(TimelineEvent(
            event_type=EventType.CHECKPOINT_SPIKE,
            timestamp=cp.timestamp,
            severity=severity,
            title=f"Long checkpoint: {cp.duration_ms / 1000:.1f}s",
            description=(
                f"Type: {cp.checkpoint_type}, "
                f"Buffers: {cp.buffers_written:,}, "
                f"WAL: +{cp.wal_added}/-{cp.wal_removed}"
            ),
            metrics={
                "duration_ms": cp.duration_ms,
                "buffers_written": cp.buffers_written,
                "wal_added": cp.wal_added,
                "wal_removed": cp.wal_removed,
                "checkpoint_type": cp.checkpoint_type,
            },
        ))


def _add_autovacuum_events(timeline: IncidentTimeline, result: AnalysisResult) -> None:
    """Add significant autovacuum events to timeline."""
    for av in result.autovacuum_stats:
        # Only add long autovacuums (>60s)
        if av.duration_ms < 60000:
            continue

        severity = "medium" if av.duration_ms < 300000 else "high"

        timeline.add_event(TimelineEvent(
            event_type=EventType.AUTOVACUUM,
            timestamp=av.timestamp,
            severity=severity,
            title=f"Long {av.operation}: {av.table} ({av.duration_ms / 1000:.1f}s)",
            description=(
                f"Removed {av.tuples_removed:,} tuples, "
                f"{av.pages_removed:,} pages"
            ),
            affected_objects=[f"{av.table_schema}.{av.table}"],
            metrics={
                "duration_ms": av.duration_ms,
                "tuples_removed": av.tuples_removed,
                "pages_removed": av.pages_removed,
                "operation": av.operation,
            },
        ))


def _add_connection_storm_events(
    timeline: IncidentTimeline,
    result: AnalysisResult,
    window: timedelta,
) -> None:
    """Detect connection storms (many connections in short time)."""
    cs = result.connection_stats

    # Check for high peak concurrent
    if cs.peak_concurrent >= 80:
        severity = "critical" if cs.peak_concurrent >= 150 else "high"

        timeline.add_event(TimelineEvent(
            event_type=EventType.CONNECTION_STORM,
            timestamp=result.time_range_start,
            end_timestamp=result.time_range_end,
            severity=severity,
            title=f"Connection storm: {cs.peak_concurrent} concurrent",
            description=f"Total connections: {cs.total_connections:,}",
            metrics={
                "peak_concurrent": cs.peak_concurrent,
                "total_connections": cs.total_connections,
                "auth_failures": cs.auth_failures,
            },
        ))

    # Check for auth failure spikes
    if cs.auth_failures >= 20:
        severity = "critical" if cs.auth_failures >= 100 else "high"

        timeline.add_event(TimelineEvent(
            event_type=EventType.AUTH_FAILURE_SPIKE,
            timestamp=result.time_range_start,
            severity=severity,
            title=f"Auth failure spike: {cs.auth_failures} failures",
            description="Multiple authentication failures detected",
            count=cs.auth_failures,
            metrics={"auth_failures": cs.auth_failures},
        ))


def _add_fatal_panic_events(timeline: IncidentTimeline, result: AnalysisResult) -> None:
    """Add FATAL/PANIC events to timeline."""
    for entry in result.panic_fatal_events:
        if not entry.timestamp:
            continue

        severity = "critical" if entry.log_level.value == "PANIC" else "high"

        # Detect OOM or disk full
        event_type = EventType.FATAL_PANIC
        msg_lower = entry.message.lower()
        if "out of memory" in msg_lower or "memory exhausted" in msg_lower:
            event_type = EventType.OOM
        elif "no space left" in msg_lower or "disk full" in msg_lower:
            event_type = EventType.DISK_FULL

        timeline.add_event(TimelineEvent(
            event_type=event_type,
            timestamp=entry.timestamp,
            severity=severity,
            title=f"{entry.log_level.value}: {entry.message[:50]}",
            description=entry.message[:200],
            affected_objects=[
                f"db:{entry.database}" if entry.database else "",
                f"user:{entry.user}" if entry.user else "",
            ],
            metrics={"pid": entry.pid},
        ))


def _add_cancellation_events(
    timeline: IncidentTimeline,
    result: AnalysisResult,
    window: timedelta,
) -> None:
    """Detect cancellation waves."""
    cancelled = getattr(result, "cancelled_queries", [])
    if len(cancelled) < 5:
        return

    # Group by time
    cancel_times = []
    for c in cancelled:
        ts = c.get("timestamp")
        if ts:
            if isinstance(ts, str):
                from dateutil import parser as dtparser
                try:
                    ts = dtparser.parse(ts)
                except Exception:
                    continue
            cancel_times.append(ts)

    if len(cancel_times) >= 5:
        severity = "high" if len(cancel_times) >= 20 else "medium"

        timeline.add_event(TimelineEvent(
            event_type=EventType.CANCELLATION_WAVE,
            timestamp=min(cancel_times),
            end_timestamp=max(cancel_times),
            severity=severity,
            title=f"Cancellation wave: {len(cancel_times)} queries cancelled",
            description="Multiple query cancellations detected",
            count=len(cancel_times),
            metrics={"cancelled_count": len(cancel_times)},
        ))


def _add_replication_lag_events(timeline: IncidentTimeline, result: AnalysisResult) -> None:
    """Add replication lag events."""
    for lag in result.replication_lag_events:
        if not lag.timestamp:
            continue

        # Only significant lag (>1MB or >10s)
        if (lag.lag_bytes or 0) < 1024 * 1024 and (lag.lag_seconds or 0) < 10:
            continue

        severity = "critical" if (lag.lag_bytes or 0) > 100 * 1024 * 1024 else "high"

        timeline.add_event(TimelineEvent(
            event_type=EventType.REPLICATION_LAG,
            timestamp=lag.timestamp,
            severity=severity,
            title=f"Replication lag: {(lag.lag_bytes or 0) / (1024 * 1024):.1f}MB",
            description=lag.message[:200] if lag.message else "",
            affected_objects=[lag.standby_host] if lag.standby_host else [],
            metrics={
                "lag_bytes": lag.lag_bytes,
                "lag_seconds": lag.lag_seconds,
            },
        ))


def _add_slow_query_spike_events(
    timeline: IncidentTimeline,
    result: AnalysisResult,
    window: timedelta,
) -> None:
    """Detect slow query spikes."""
    # Check for queries with very high max duration
    for sq in result.slow_queries[:10]:
        if sq.max_duration_ms >= 30000:  # >30s
            severity = "high" if sq.max_duration_ms >= 60000 else "medium"

            timeline.add_event(TimelineEvent(
                event_type=EventType.SLOW_QUERY_SPIKE,
                timestamp=sq.first_seen,
                end_timestamp=sq.last_seen,
                severity=severity,
                title=f"Slow query spike: {sq.max_duration_ms / 1000:.1f}s max",
                description=f"Query executed {sq.count}x, avg {sq.avg_duration_ms:.0f}ms",
                count=sq.count,
                related_queries=[sq.normalized_query[:200]],
                metrics={
                    "max_duration_ms": sq.max_duration_ms,
                    "avg_duration_ms": sq.avg_duration_ms,
                    "count": sq.count,
                },
            ))


def render_timeline_text(timeline: IncidentTimeline) -> str:
    """Render timeline as plain text for terminal output."""
    lines = []
    lines.append("=" * 60)
    lines.append("INCIDENT TIMELINE")
    lines.append("=" * 60)

    if timeline.time_range_start and timeline.time_range_end:
        duration = (timeline.time_range_end - timeline.time_range_start).total_seconds() / 3600
        lines.append(
            f"Period: {timeline.time_range_start.strftime('%Y-%m-%d %H:%M')} → "
            f"{timeline.time_range_end.strftime('%Y-%m-%d %H:%M')} ({duration:.1f}h)"
        )

    lines.append(
        f"Events: {timeline.total_events} total "
        f"({timeline.critical_events} critical, {timeline.high_events} high)"
    )
    lines.append("-" * 60)

    for event in timeline.events:
        ts_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "??:??"
        severity_marker = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "⚪",
        }.get(event.severity, "⚪")

        lines.append(f"\n{ts_str} {severity_marker} [{event.severity.upper()}]")
        lines.append(f"  {event.title}")
        if event.description:
            lines.append(f"  {event.description}")
        if event.duration_seconds > 0:
            lines.append(f"  Duration: {event.duration_seconds:.0f}s")
        if event.related_queries:
            lines.append(f"  Query: {event.related_queries[0][:80]}...")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def render_timeline_markdown(timeline: IncidentTimeline) -> str:
    """Render timeline as Markdown."""
    lines = []
    lines.append("# Incident Timeline\n")

    if timeline.time_range_start and timeline.time_range_end:
        duration = (timeline.time_range_end - timeline.time_range_start).total_seconds() / 3600
        lines.append(
            f"**Period:** {timeline.time_range_start.strftime('%Y-%m-%d %H:%M')} → "
            f"{timeline.time_range_end.strftime('%Y-%m-%d %H:%M')} ({duration:.1f}h)\n"
        )

    lines.append(
        f"**Events:** {timeline.total_events} total "
        f"({timeline.critical_events} critical, {timeline.high_events} high)\n"
    )
    lines.append("---\n")

    severity_emoji = {
        "critical": "🚨",
        "high": "⚠️",
        "medium": "⚡",
        "low": "ℹ️",
        "info": "💡",
    }

    for event in timeline.events:
        ts_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "Unknown"
        emoji = severity_emoji.get(event.severity, "•")

        lines.append(f"### {emoji} {ts_str} — {event.title}\n")
        lines.append(f"**Severity:** {event.severity.upper()}\n")
        if event.description:
            lines.append(f"{event.description}\n")
        if event.duration_seconds > 0:
            lines.append(f"**Duration:** {event.duration_seconds:.0f}s\n")
        if event.related_queries:
            lines.append(f"```sql\n{event.related_queries[0][:500]}\n```\n")
        lines.append("")

    return "\n".join(lines)
