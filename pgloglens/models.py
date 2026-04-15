"""Pydantic data models for pgloglens."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"
    PANIC = "PANIC"
    LOG = "LOG"
    DETAIL = "DETAIL"
    HINT = "HINT"
    CONTEXT = "CONTEXT"
    STATEMENT = "STATEMENT"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class LogEntry(BaseModel):
    """Represents a single parsed log entry from a PostgreSQL log file."""

    timestamp: Optional[datetime] = None
    log_level: LogLevel = LogLevel.LOG
    session_id: Optional[str] = None
    pid: Optional[int] = None
    user: Optional[str] = None
    database: Optional[str] = None
    application_name: Optional[str] = None
    remote_host: Optional[str] = None
    duration_ms: Optional[float] = None
    query: Optional[str] = None
    error_code: Optional[str] = None  # SQLSTATE code
    message: str = ""
    raw_line: str = ""
    line_number: int = 0
    # v2 new fields
    query_type: Optional[str] = None   # select/insert/update/delete/copy/ddl/vacuum/other
    phase: Optional[str] = None        # parse/bind/execute

    model_config = {"arbitrary_types_allowed": True}


class SlowQuery(BaseModel):
    """Aggregated statistics for a slow (or frequent) query pattern."""

    query: str  # Example raw query
    normalized_query: str  # Normalized form with $1, $2 placeholders
    count: int = 0
    total_duration_ms: float = 0.0
    avg_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    min_duration_ms: float = 0.0
    p50_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    p99_duration_ms: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    plans: List[Any] = Field(default_factory=list)
    durations: List[float] = Field(default_factory=list, exclude=True)  # raw samples
    databases: Set[str] = Field(default_factory=set)
    users: Set[str] = Field(default_factory=set)
    # v2 new fields
    applications: Set[str] = Field(default_factory=set)
    query_type: str = "unknown"  # select/insert/update/delete/other
    sample_queries: List[str] = Field(default_factory=list)  # up to 3 examples
    cancellation_count: int = 0
    is_regression: bool = False
    regression_slope: Optional[float] = None
    auto_explain_plans: List[str] = Field(default_factory=list)
    phase_durations: Dict[str, float] = Field(default_factory=dict)  # parse/bind/execute

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        if self.durations:
            self._recalculate()

    def add_sample(
        self,
        duration_ms: float,
        timestamp: Optional[datetime],
        database: Optional[str],
        user: Optional[str],
        query: Optional[str] = None,
        application: Optional[str] = None,
    ) -> None:
        self.durations.append(duration_ms)
        self.count += 1
        self.total_duration_ms += duration_ms
        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp
        if database:
            self.databases.add(database)
        if user:
            self.users.add(user)
        if application:
            self.applications.add(application)
        if query and len(self.sample_queries) < 3:
            if query not in self.sample_queries:
                self.sample_queries.append(query[:2000])
        self._recalculate()

    def _recalculate(self) -> None:
        from .utils import percentile

        d = sorted(self.durations)
        self.avg_duration_ms = sum(d) / len(d)
        self.max_duration_ms = d[-1]
        self.min_duration_ms = d[0]
        self.p50_duration_ms = percentile(d, 50)
        self.p95_duration_ms = percentile(d, 95)
        self.p99_duration_ms = percentile(d, 99)


class ErrorPattern(BaseModel):
    """Aggregated error pattern."""

    error_code: Optional[str] = None  # SQLSTATE
    message_pattern: str = ""
    category: str = "unknown"  # connection/query/disk/replication/lock
    count: int = 0
    sample_messages: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    affected_users: Set[str] = Field(default_factory=set)
    affected_databases: Set[str] = Field(default_factory=set)
    hourly_counts: Dict[int, int] = Field(default_factory=dict)  # hour -> count

    model_config = {"arbitrary_types_allowed": True}

    def add_occurrence(
        self,
        message: str,
        timestamp: Optional[datetime],
        user: Optional[str],
        database: Optional[str],
    ) -> None:
        self.count += 1
        if len(self.sample_messages) < 10:
            self.sample_messages.append(message[:500])
        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp
            hour = timestamp.hour
            self.hourly_counts[hour] = self.hourly_counts.get(hour, 0) + 1
        if user:
            self.affected_users.add(user)
        if database:
            self.affected_databases.add(database)


class LockEvent(BaseModel):
    """Represents a lock wait or deadlock event."""

    waiting_pid: Optional[int] = None
    blocking_pid: Optional[int] = None
    waiting_query: Optional[str] = None
    blocking_query: Optional[str] = None
    wait_duration_ms: Optional[float] = None
    timestamp: Optional[datetime] = None
    lock_type: Optional[str] = None
    relation: Optional[str] = None
    is_deadlock: bool = False

    model_config = {"arbitrary_types_allowed": True}


class ConnectionStats(BaseModel):
    """Connection statistics aggregated from log entries."""

    total_connections: int = 0
    total_disconnections: int = 0
    peak_concurrent: int = 0
    connections_by_hour: Dict[int, int] = Field(default_factory=dict)
    connections_by_user: Dict[str, int] = Field(default_factory=dict)
    connections_by_database: Dict[str, int] = Field(default_factory=dict)
    auth_failures: int = 0
    ssl_errors: int = 0
    connection_refused: int = 0
    avg_session_duration_ms: float = 0.0
    active_pids: Set[int] = Field(default_factory=set)
    # v2 new fields
    connections_by_host: Dict[str, int] = Field(default_factory=dict)
    connections_by_application: Dict[str, int] = Field(default_factory=dict)
    total_sessions: int = 0
    session_durations_ms: List[float] = Field(default_factory=list, exclude=True)

    model_config = {"arbitrary_types_allowed": True}


class CheckpointEvent(BaseModel):
    """A single checkpoint complete event with all parsed fields."""

    timestamp: Optional[datetime] = None
    duration_ms: float = 0.0
    write_s: float = 0.0
    sync_s: float = 0.0
    buffers_written: int = 0
    buffers_pct: float = 0.0   # e.g. 12.4 (percent of shared_buffers)
    wal_added: int = 0
    wal_removed: int = 0
    wal_recycled: int = 0
    distance_kb: Optional[int] = None
    estimate_kb: Optional[int] = None
    checkpoint_type: str = "scheduled"  # scheduled / immediate / shutdown / xlog


class CheckpointStats(BaseModel):
    """Checkpoint statistics."""

    count: int = 0
    avg_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    total_duration_ms: float = 0.0
    buffers_checkpoint_avg: float = 0.0
    total_written_mb: float = 0.0
    warning_count: int = 0  # "checkpoint occurring too frequently"
    by_type: Dict[str, int] = Field(default_factory=dict)  # "scheduled" vs "immediate"
    durations: List[float] = Field(default_factory=list, exclude=True)

    def add_checkpoint(
        self,
        duration_ms: float,
        buffers_written: float = 0,
        written_mb: float = 0,
        checkpoint_type: str = "scheduled",
    ) -> None:
        self.count += 1
        self.durations.append(duration_ms)
        self.total_duration_ms += duration_ms
        self.avg_duration_ms = self.total_duration_ms / self.count
        if duration_ms > self.max_duration_ms:
            self.max_duration_ms = duration_ms
        self.buffers_checkpoint_avg = (
            (self.buffers_checkpoint_avg * (self.count - 1) + buffers_written) / self.count
        )
        self.total_written_mb += written_mb
        self.by_type[checkpoint_type] = self.by_type.get(checkpoint_type, 0) + 1


class AutovacuumStats(BaseModel):
    """Statistics for a single autovacuum run."""

    table: str = ""
    table_schema: str = "public"
    duration_ms: float = 0.0
    pages_removed: int = 0
    pages_hit: int = 0
    tuples_removed: int = 0
    tuples_remain: int = 0
    timestamp: Optional[datetime] = None
    dead_tuples_before: int = 0
    index_scans: int = 0
    is_analyze: bool = False
    # pgBadger v11.4+ extended fields
    buffer_hits: int = 0
    buffer_misses: int = 0
    buffers_dirtied: int = 0
    wal_records: int = 0
    wal_fpi: int = 0
    wal_bytes: int = 0
    cpu_user_s: float = 0.0
    cpu_sys_s: float = 0.0
    skipped_pins: int = 0
    skipped_frozen: int = 0
    # identify it as vacuum or analyze
    operation: str = "vacuum"  # vacuum or analyze

    model_config = {"arbitrary_types_allowed": True}


class TempFileStats(BaseModel):
    """Statistics for a temp file creation event."""

    query: Optional[str] = None
    size_bytes: int = 0
    size_mb: float = 0.0
    session_id: Optional[str] = None
    pid: Optional[int] = None
    timestamp: Optional[datetime] = None
    database: Optional[str] = None
    user: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        if self.size_bytes and not self.size_mb:
            self.size_mb = round(self.size_bytes / (1024 * 1024), 2)
        elif self.size_mb and not self.size_bytes:
            self.size_bytes = int(self.size_mb * 1024 * 1024)


class ReplicationLagEvent(BaseModel):
    """Replication lag event."""

    timestamp: Optional[datetime] = None
    lag_bytes: Optional[int] = None
    lag_seconds: Optional[float] = None
    standby_host: Optional[str] = None
    message: str = ""

    model_config = {"arbitrary_types_allowed": True}


class RCAFinding(BaseModel):
    """A single root cause analysis finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    affected_queries: List[str] = Field(default_factory=list)
    metric_value: Optional[float] = None
    metric_label: Optional[str] = None


# ---------------------------------------------------------------------------
# v2 new models
# ---------------------------------------------------------------------------


class SessionStats(BaseModel):
    """Session analytics (like pgBadger)."""

    total_sessions: int = 0
    peak_concurrent: int = 0
    total_session_duration_ms: float = 0.0
    avg_session_duration_ms: float = 0.0
    total_idle_time_ms: float = 0.0
    avg_queries_per_session: float = 0.0
    sessions_by_database: Dict[str, int] = Field(default_factory=dict)
    sessions_by_user: Dict[str, int] = Field(default_factory=dict)
    sessions_by_host: Dict[str, int] = Field(default_factory=dict)
    sessions_by_application: Dict[str, int] = Field(default_factory=dict)
    session_duration_histogram: Dict[str, int] = Field(default_factory=dict)  # bucket_label -> count
    concurrent_over_time: Dict[str, int] = Field(default_factory=dict)  # hour_str -> max_concurrent


class QueryTypeStats(BaseModel):
    """SELECT/INSERT/UPDATE/DELETE distribution."""

    select_count: int = 0
    insert_count: int = 0
    update_count: int = 0
    delete_count: int = 0
    copy_count: int = 0
    vacuum_count: int = 0
    ddl_count: int = 0
    other_count: int = 0
    cancelled_count: int = 0
    by_database: Dict[str, Dict[str, int]] = Field(default_factory=dict)  # db -> {type: count}
    by_application: Dict[str, Dict[str, int]] = Field(default_factory=dict)  # app -> {type: count}
    by_user: Dict[str, int] = Field(default_factory=dict)  # user -> total_count
    dml_over_time: Dict[str, int] = Field(default_factory=dict)  # hour_str -> dml_count


class PrepareBindExecuteStats(BaseModel):
    """Extended query protocol tracking."""

    total_parse_ms: float = 0.0
    total_bind_ms: float = 0.0
    total_execute_ms: float = 0.0
    parse_count: int = 0
    bind_count: int = 0
    execute_count: int = 0
    top_parse_queries: List[Dict[str, Any]] = Field(default_factory=list)  # {query, total_ms, count}
    top_bind_queries: List[Dict[str, Any]] = Field(default_factory=list)


class AutoExplainPlan(BaseModel):
    """auto_explain log output."""

    query: str = ""
    normalized_query: str = ""
    plan_text: str = ""
    plan_format: str = "text"  # text/json/xml/yaml
    duration_ms: float = 0.0
    timestamp: Optional[datetime] = None
    database: Optional[str] = None
    user: Optional[str] = None
    ai_analysis: Optional[str] = None  # LLM analysis of the plan

    model_config = {"arbitrary_types_allowed": True}


class PgBouncerStats(BaseModel):
    """PgBouncer log statistics."""

    total_requests: int = 0
    avg_query_ms: float = 0.0
    max_query_ms: float = 0.0
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    pool_errors: List[str] = Field(default_factory=list)
    connections_by_db: Dict[str, int] = Field(default_factory=dict)
    connections_by_user: Dict[str, int] = Field(default_factory=dict)
    top_errors: List[Dict[str, Any]] = Field(default_factory=list)


class IncrementalState(BaseModel):
    """Incremental report tracking state."""

    last_parsed_file: str = ""
    last_parsed_line: int = 0
    last_parsed_timestamp: Optional[datetime] = None
    processed_files: List[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}


class AnalysisResult(BaseModel):
    """The complete result of analyzing one or more PostgreSQL log files."""

    log_file_paths: List[str] = Field(default_factory=list)
    analysis_start: Optional[datetime] = None
    analysis_end: Optional[datetime] = None
    total_entries: int = 0
    total_lines: int = 0
    slow_query_threshold_ms: float = 1000.0
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None

    slow_queries: List[SlowQuery] = Field(default_factory=list)
    error_patterns: List[ErrorPattern] = Field(default_factory=list)
    lock_events: List[LockEvent] = Field(default_factory=list)
    connection_stats: ConnectionStats = Field(default_factory=ConnectionStats)
    checkpoint_stats: CheckpointStats = Field(default_factory=CheckpointStats)
    checkpoint_events: List[Any] = Field(default_factory=list)  # List[CheckpointEvent]
    autovacuum_stats: List[AutovacuumStats] = Field(default_factory=list)
    temp_files: List[TempFileStats] = Field(default_factory=list)
    wait_events: Dict[str, int] = Field(default_factory=dict)
    replication_lag_events: List[ReplicationLagEvent] = Field(default_factory=list)
    panic_fatal_events: List[LogEntry] = Field(default_factory=list)

    recommendations: List[str] = Field(default_factory=list)
    rca_findings: List[RCAFinding] = Field(default_factory=list)
    llm_analysis: Optional[str] = None

    # Summary stats
    queries_per_second: float = 0.0
    error_rate_per_minute: float = 0.0
    total_slow_query_time_ms: float = 0.0
    deadlock_count: int = 0

    # v2 new fields
    session_stats: SessionStats = Field(default_factory=SessionStats)
    query_type_stats: QueryTypeStats = Field(default_factory=QueryTypeStats)
    prepare_bind_execute: PrepareBindExecuteStats = Field(default_factory=PrepareBindExecuteStats)
    auto_explain_plans: List[AutoExplainPlan] = Field(default_factory=list)
    pgbouncer_stats: Optional[PgBouncerStats] = None
    cancelled_queries: List[Dict[str, Any]] = Field(default_factory=list)
    connection_by_host: Dict[str, int] = Field(default_factory=dict)
    connection_by_application: Dict[str, int] = Field(default_factory=dict)
    checkpoint_wal_added: int = 0
    checkpoint_wal_removed: int = 0
    checkpoint_wal_recycled: int = 0
    checkpoint_distance_avg: float = 0.0
    checkpoint_estimate_avg: float = 0.0
    log_format_detected: str = "unknown"
    source_platform: str = "postgresql"  # postgresql/rds/redshift/cloudsql/pgbouncer/heroku
    total_query_duration_ms: float = 0.0
    queries_per_minute: float = 0.0
    anonymized: bool = False

    # AI analysis results
    ai_slow_query_analyses: List[Dict[str, Any]] = Field(default_factory=list)
    ai_generated_config: Optional[str] = None
    ai_index_recommendations: List[Dict[str, Any]] = Field(default_factory=list)

    # pg_stat_statements correlation
    pgss_correlation: Optional[Any] = None  # CorrelationResult from pgss module

    # Parse health metrics — set after parsing, used for data-quality warnings
    parse_errors: int = 0
    entries_attempted: int = 0

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        self.deadlock_count = sum(1 for e in self.lock_events if e.is_deadlock)
        if self.slow_queries:
            self.total_slow_query_time_ms = sum(q.total_duration_ms for q in self.slow_queries)
