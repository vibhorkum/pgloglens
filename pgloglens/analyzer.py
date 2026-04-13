"""Statistical analysis engine for pgloglens.

Takes an iterable of LogEntry objects and produces an AnalysisResult containing
aggregated statistics, patterns, and insights.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .utils import percentile, linear_regression_slope

from .models import (
    AnalysisResult,
    AutoExplainPlan,
    AutovacuumStats,
    CheckpointStats,
    ConnectionStats,
    ErrorPattern,
    LockEvent,
    LogEntry,
    LogLevel,
    PrepareBindExecuteStats,
    PgBouncerStats,
    QueryTypeStats,
    ReplicationLagEvent,
    RCAFinding,
    SessionStats,
    SlowQuery,
    TempFileStats,
)
from .parser import (
    extract_autovacuum,
    extract_checkpoint,
    extract_lock_event,
    extract_pgbouncer_event,
    extract_tempfile,
    is_auth_failure,
    is_autovacuum,
    is_cancellation,
    is_checkpoint,
    is_connection_event,
    is_deadlock,
    is_disconnection,
    is_disk_full,
    is_lock_wait,
    is_oom,
    is_replication_event,
    is_slow_query,
    is_tempfile,
    _AUTH_FAIL_RE,
    _CHECKPOINT_WARNING_RE,
    _CHECKPOINT_WAL_RE,
    _CHECKPOINT_DISTANCE_RE,
    _CHECKPOINT_CAUSE_RE,
    _REPL_LAG_RE,
    _DISCONN_DURATION_RE,
    _AUTO_EXPLAIN_START_RE,
    _AUTO_EXPLAIN_PLAN_RE,
    _CANCELLATION_RE,
    detect_query_type,
)

# ---------------------------------------------------------------------------
# Query normalizer
# ---------------------------------------------------------------------------

_STR_LITERAL_RE = re.compile(r"'(?:[^'\\]|\\.)*'", re.DOTALL)
_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_IN_LIST_RE = re.compile(r"\(\s*(\$\d+(?:\s*,\s*\$\d+)+)\s*\)", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")
_PARAM_RE = re.compile(r"\$\d+")


def normalize_query(query: str) -> str:
    """Normalize a SQL query by replacing literals with placeholders.

    Steps:
    1. Collapse whitespace
    2. Replace single-quoted strings with $N
    3. Replace numeric literals with $N
    4. Collapse IN ($N, $N, ...) to IN ($N)
    5. Uppercase SQL keywords
    """
    if not query:
        return query

    q = query.strip()

    # Remove trailing semicolon
    q = q.rstrip(";").strip()

    # Collapse whitespace
    q = _WHITESPACE_RE.sub(" ", q)

    # Replace string literals
    counter = [1]

    def _next_param(_m=None) -> str:
        val = f"${counter[0]}"
        counter[0] += 1
        return val

    q = _STR_LITERAL_RE.sub(lambda m: _next_param(), q)

    # Replace numeric literals (but not $N already placed)
    q = _NUM_RE.sub(lambda m: _next_param(), q)

    # Collapse IN lists
    q = _IN_LIST_RE.sub(lambda m: f"(${counter[0]})", q)

    # Uppercase keywords
    keywords = [
        "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "EXISTS",
        "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS",
        "ON", "GROUP BY", "ORDER BY", "HAVING", "LIMIT", "OFFSET",
        "INSERT INTO", "UPDATE", "DELETE FROM", "SET", "VALUES",
        "RETURNING", "WITH", "UNION", "INTERSECT", "EXCEPT", "ALL",
        "DISTINCT", "AS", "CASE", "WHEN", "THEN", "ELSE", "END",
    ]
    for kw in sorted(keywords, key=len, reverse=True):
        q = re.sub(r"\b" + re.escape(kw) + r"\b", kw, q, flags=re.IGNORECASE)

    return q[:2000]  # cap at 2000 chars


# ---------------------------------------------------------------------------
# Error categorizer
# ---------------------------------------------------------------------------

_ERROR_CATEGORIES = {
    "connection": re.compile(
        r"connection|ssl|tcp|socket|host|timeout|pg_hba|authentication|role.*does not exist",
        re.IGNORECASE,
    ),
    "lock": re.compile(r"\bdeadlock\b|lock wait|\blockout\b", re.IGNORECASE),
    "constraint": re.compile(
        r"unique constraint|foreign key|check constraint|duplicate key|violates",
        re.IGNORECASE,
    ),
    "disk": re.compile(r"no space left|disk full|ENOSPC|could not write to file|could not extend", re.IGNORECASE),
    "replication": re.compile(
        r"replication|standby|wal.*recei|recovery|streaming", re.IGNORECASE
    ),
    "query": re.compile(
        r"syntax|invalid|undefined|column|table.*does not exist|function|type|operator|division by zero|relation.*does not exist",
        re.IGNORECASE,
    ),
    "memory": re.compile(r"out of memory|memory exhausted|shared_buffers", re.IGNORECASE),
    "serialization": re.compile(r"serialize|concurrent update|serialization failure", re.IGNORECASE),
    "autovacuum": re.compile(r"autovacuum|vacuum|bloat", re.IGNORECASE),
}


def categorize_error(message: str) -> str:
    for category, pattern in _ERROR_CATEGORIES.items():
        if pattern.search(message):
            return category
    return "unknown"


def _pattern_key(message: str) -> str:
    """Generate a grouping key for an error message by stripping variable parts."""
    # Truncate at DETAIL/HINT/STATEMENT continuation markers
    for marker in ["\tDETAIL:", " DETAIL:", "\tHINT:", " HINT:", "\tSTATEMENT:", " STATEMENT:"]:
        idx = message.find(marker)
        if idx > 0:
            message = message[:idx]
    s = _STR_LITERAL_RE.sub("?", message)
    s = _NUM_RE.sub("N", s)
    s = re.sub(r'"[^"]{1,80}"', '"X"', s)
    # Strip duplicate key detail (email values differ but same constraint)
    s = re.sub(r"Key \([^)]+\)=\([^)]*\)", "Key (col)=(val)", s)
    s = _WHITESPACE_RE.sub(" ", s).strip()
    return s[:200]


# ---------------------------------------------------------------------------
# Session duration histogram buckets
# ---------------------------------------------------------------------------

def _session_duration_bucket(duration_ms: float) -> str:
    """Return a human-readable histogram bucket label for a session duration."""
    if duration_ms < 500:
        return "<500ms"
    if duration_ms < 1_000:
        return "<1s"
    if duration_ms < 30_000:
        return "<30s"
    if duration_ms < 60_000:
        return "<1m"
    if duration_ms < 600_000:
        return "<10m"
    if duration_ms < 1_800_000:
        return "<30m"
    if duration_ms < 3_600_000:
        return "<1h"
    if duration_ms < 28_800_000:
        return "<8h"
    return ">8h"


def _session_duration_from_time_str(time_str: str) -> float:
    """Convert HH:MM:SS or HH:MM:SS.mmm string to milliseconds."""
    try:
        parts = time_str.split(":")
        if len(parts) == 3:
            h, m, s = parts
            return (int(h) * 3600 + int(m) * 60 + float(s)) * 1000.0
    except (ValueError, IndexError):
        pass
    return 0.0


# ---------------------------------------------------------------------------
# v2 standalone analyzer functions
# ---------------------------------------------------------------------------

def analyze_sessions(entries: Iterable[LogEntry]) -> SessionStats:
    """Analyze session events (connections/disconnections).

    Computes:
    - Total sessions, peak concurrent, avg duration
    - Session duration histogram with buckets: <500ms, <1s, <30s, <1m, <10m, <30m, <1h, <8h, >8h
    - Distribution by database, user, host, application
    - Idle time (total session time - total query time)
    - Concurrent sessions tracked via open_sessions dict {pid -> start_time}

    Returns SessionStats model.
    """
    stats = SessionStats()
    # pid -> (connect_time, database, user, host, application)
    open_sessions: Dict[int, Dict[str, Any]] = {}
    # track max concurrent by hour
    concurrent_by_hour: Dict[str, int] = {}
    all_durations: List[float] = []

    for entry in entries:
        if is_connection_event(entry) and entry.pid is not None:
            open_sessions[entry.pid] = {
                "start": entry.timestamp,
                "database": entry.database,
                "user": entry.user,
                "host": entry.remote_host,
                "application": entry.application_name,
            }
            concurrent = len(open_sessions)
            if concurrent > stats.peak_concurrent:
                stats.peak_concurrent = concurrent
            # Track concurrent by hour
            if entry.timestamp:
                hour_str = entry.timestamp.strftime("%Y-%m-%d %H:00")
                old = concurrent_by_hour.get(hour_str, 0)
                if concurrent > old:
                    concurrent_by_hour[hour_str] = concurrent

        elif is_disconnection(entry) and entry.pid is not None:
            sess = open_sessions.pop(entry.pid, None)

            # Try to extract session duration from disconnection message
            dm = _DISCONN_DURATION_RE.search(entry.message)
            session_dur_ms = 0.0
            if dm:
                session_dur_ms = _session_duration_from_time_str(dm.group(1))

            elif sess and sess.get("start") and entry.timestamp:
                delta = entry.timestamp - sess["start"]
                session_dur_ms = delta.total_seconds() * 1000.0

            if session_dur_ms > 0:
                all_durations.append(session_dur_ms)
                stats.total_session_duration_ms += session_dur_ms
                bucket = _session_duration_bucket(session_dur_ms)
                stats.session_duration_histogram[bucket] = (
                    stats.session_duration_histogram.get(bucket, 0) + 1
                )

            stats.total_sessions += 1

            # Distributions: pull from session dict if available, else from entry
            db = (sess or {}).get("database") or entry.database
            user = (sess or {}).get("user") or entry.user
            host = (sess or {}).get("host") or entry.remote_host
            app = (sess or {}).get("application") or entry.application_name

            if db:
                stats.sessions_by_database[db] = stats.sessions_by_database.get(db, 0) + 1
            if user:
                stats.sessions_by_user[user] = stats.sessions_by_user.get(user, 0) + 1
            if host:
                stats.sessions_by_host[host] = stats.sessions_by_host.get(host, 0) + 1
            if app:
                stats.sessions_by_application[app] = stats.sessions_by_application.get(app, 0) + 1

    # Finalize
    if stats.total_sessions > 0 and stats.total_session_duration_ms > 0:
        stats.avg_session_duration_ms = stats.total_session_duration_ms / stats.total_sessions

    stats.concurrent_over_time = concurrent_by_hour
    return stats


def analyze_query_types(entries: Iterable[LogEntry]) -> QueryTypeStats:
    """Count queries by type (SELECT/INSERT/UPDATE/DELETE/COPY/DDL/VACUUM/other).

    Track by database, user, application.
    Track DML over time (hour buckets).
    Count query cancellations.
    """
    stats = QueryTypeStats()
    _type_attr = {
        "select": "select_count",
        "insert": "insert_count",
        "update": "update_count",
        "delete": "delete_count",
        "copy": "copy_count",
        "vacuum": "vacuum_count",
        "ddl": "ddl_count",
        "other": "other_count",
    }
    _dml_types = {"insert", "update", "delete"}

    for entry in entries:
        # Only process entries with query or duration (i.e. actual queries)
        query_text = entry.query or entry.message
        if not query_text:
            continue

        # Cancellation check
        if is_cancellation(entry):
            stats.cancelled_count += 1
            continue

        qtype = entry.query_type or detect_query_type(query_text)

        # Increment the appropriate type counter
        attr = _type_attr.get(qtype, "other_count")
        setattr(stats, attr, getattr(stats, attr) + 1)

        # Track by database
        db = entry.database
        if db:
            if db not in stats.by_database:
                stats.by_database[db] = {}
            stats.by_database[db][qtype] = stats.by_database[db].get(qtype, 0) + 1

        # Track by application
        app = entry.application_name
        if app:
            if app not in stats.by_application:
                stats.by_application[app] = {}
            stats.by_application[app][qtype] = stats.by_application[app].get(qtype, 0) + 1

        # Track by user (total count)
        user = entry.user
        if user:
            stats.by_user[user] = stats.by_user.get(user, 0) + 1

        # DML over time
        if qtype in _dml_types and entry.timestamp:
            hour_str = entry.timestamp.strftime("%Y-%m-%d %H:00")
            stats.dml_over_time[hour_str] = stats.dml_over_time.get(hour_str, 0) + 1

    return stats


def analyze_prepare_bind_execute(entries: Iterable[LogEntry]) -> PrepareBindExecuteStats:
    """Track prepare/parse, bind, execute phase durations separately.

    Builds top-N most time-consuming parse and bind queries.
    Returns PrepareBindExecuteStats.
    """
    stats = PrepareBindExecuteStats()
    # query -> {total_ms, count} for parse and bind
    parse_map: Dict[str, Dict[str, Any]] = {}
    bind_map: Dict[str, Dict[str, Any]] = {}

    for entry in entries:
        if entry.duration_ms is None:
            continue
        phase = entry.phase
        if phase is None:
            continue

        query_key = (entry.query or entry.message or "")[:200]
        dur = entry.duration_ms

        if phase == "parse":
            stats.total_parse_ms += dur
            stats.parse_count += 1
            if query_key not in parse_map:
                parse_map[query_key] = {"query": query_key, "total_ms": 0.0, "count": 0}
            parse_map[query_key]["total_ms"] += dur
            parse_map[query_key]["count"] += 1

        elif phase == "bind":
            stats.total_bind_ms += dur
            stats.bind_count += 1
            if query_key not in bind_map:
                bind_map[query_key] = {"query": query_key, "total_ms": 0.0, "count": 0}
            bind_map[query_key]["total_ms"] += dur
            bind_map[query_key]["count"] += 1

        elif phase == "execute":
            stats.total_execute_ms += dur
            stats.execute_count += 1

    # Top 25 parse queries by total_ms
    stats.top_parse_queries = sorted(
        parse_map.values(), key=lambda x: x["total_ms"], reverse=True
    )[:25]
    # Top 25 bind queries by total_ms
    stats.top_bind_queries = sorted(
        bind_map.values(), key=lambda x: x["total_ms"], reverse=True
    )[:25]

    return stats


def analyze_auto_explain_plans(
    log_entries: Iterable[LogEntry],
    slow_queries: List[SlowQuery],
) -> List[AutoExplainPlan]:
    """Extract auto_explain plan blocks from log entries.

    Matches plans to normalized queries where possible.
    Returns list of AutoExplainPlan objects.
    """
    plans: List[AutoExplainPlan] = []
    # Build a lookup from normalized query to SlowQuery
    slow_map: Dict[str, SlowQuery] = {sq.normalized_query[:100]: sq for sq in slow_queries}

    # We need to accumulate lines for multi-line plan detection
    current_query: Optional[str] = None
    current_entry: Optional[LogEntry] = None
    plan_lines: List[str] = []
    in_plan = False

    entries_list = list(log_entries)

    i = 0
    while i < len(entries_list):
        entry = entries_list[i]
        msg = entry.message

        m = _AUTO_EXPLAIN_START_RE.search(msg)
        if m:
            # Flush previous plan if any
            if current_query is not None and plan_lines:
                plan_text = "\n".join(plan_lines)
                plan_format = _detect_plan_format(plan_text)
                norm_q = normalize_query(current_query)
                plans.append(AutoExplainPlan(
                    query=current_query,
                    normalized_query=norm_q,
                    plan_text=plan_text,
                    plan_format=plan_format,
                    duration_ms=current_entry.duration_ms or 0.0 if current_entry else 0.0,
                    timestamp=current_entry.timestamp if current_entry else None,
                    database=current_entry.database if current_entry else None,
                    user=current_entry.user if current_entry else None,
                ))

            current_query = m.group(1).strip()
            current_entry = entry
            plan_lines = []
            in_plan = True
            i += 1
            continue

        if in_plan:
            stripped = msg.strip()
            if not stripped:
                # End of plan block on blank line
                if current_query is not None and plan_lines:
                    plan_text = "\n".join(plan_lines)
                    plan_format = _detect_plan_format(plan_text)
                    norm_q = normalize_query(current_query)
                    plans.append(AutoExplainPlan(
                        query=current_query,
                        normalized_query=norm_q,
                        plan_text=plan_text,
                        plan_format=plan_format,
                        duration_ms=current_entry.duration_ms or 0.0 if current_entry else 0.0,
                        timestamp=current_entry.timestamp if current_entry else None,
                        database=current_entry.database if current_entry else None,
                        user=current_entry.user if current_entry else None,
                    ))
                    current_query = None
                    plan_lines = []
                    in_plan = False
            elif (
                _AUTO_EXPLAIN_PLAN_RE.search(stripped)
                or stripped.startswith("->")
                or stripped.startswith("  ")
                or stripped.startswith("Plan")
                or stripped.startswith("{")
                or stripped.startswith("<")
            ):
                plan_lines.append(stripped)
            else:
                # Non-plan line ends the plan block
                if current_query is not None and plan_lines:
                    plan_text = "\n".join(plan_lines)
                    plan_format = _detect_plan_format(plan_text)
                    norm_q = normalize_query(current_query)
                    plans.append(AutoExplainPlan(
                        query=current_query,
                        normalized_query=norm_q,
                        plan_text=plan_text,
                        plan_format=plan_format,
                        duration_ms=current_entry.duration_ms or 0.0 if current_entry else 0.0,
                        timestamp=current_entry.timestamp if current_entry else None,
                        database=current_entry.database if current_entry else None,
                        user=current_entry.user if current_entry else None,
                    ))
                    current_query = None
                    plan_lines = []
                in_plan = False

        i += 1

    # Flush any remaining plan
    if current_query is not None and plan_lines:
        plan_text = "\n".join(plan_lines)
        plan_format = _detect_plan_format(plan_text)
        norm_q = normalize_query(current_query)
        plans.append(AutoExplainPlan(
            query=current_query,
            normalized_query=norm_q,
            plan_text=plan_text,
            plan_format=plan_format,
            duration_ms=current_entry.duration_ms or 0.0 if current_entry else 0.0,
            timestamp=current_entry.timestamp if current_entry else None,
            database=current_entry.database if current_entry else None,
            user=current_entry.user if current_entry else None,
        ))

    return plans


def _detect_plan_format(plan_text: str) -> str:
    """Detect auto_explain plan format (text/json/xml/yaml)."""
    stripped = plan_text.lstrip()
    if stripped.startswith("{"):
        return "json"
    if stripped.startswith("<"):
        return "xml"
    if stripped.startswith("---") or (stripped.startswith("!") and "!!" in stripped):
        return "yaml"
    return "text"


def analyze_pgbouncer(entries: Iterable[LogEntry]) -> PgBouncerStats:
    """Analyze PgBouncer log entries.

    Computes:
    - Connection stats by db/user
    - Query duration stats
    - Top errors
    - Bytes in/out if available
    """
    stats = PgBouncerStats()
    error_counts: Dict[str, int] = {}
    total_query_ms = 0.0
    query_count = 0

    for entry in entries:
        ev = extract_pgbouncer_event(entry)

        # Connection tracking
        db = ev.get("database") or entry.database
        user = ev.get("user") or entry.user
        if db:
            stats.connections_by_db[db] = stats.connections_by_db.get(db, 0) + 1
        if user:
            stats.connections_by_user[user] = stats.connections_by_user.get(user, 0) + 1

        # Query stats
        dur = ev.get("duration_ms")
        if dur is not None:
            stats.total_requests += 1
            total_query_ms += dur
            query_count += 1
            if dur > stats.max_query_ms:
                stats.max_query_ms = dur

        # Bytes
        bi = ev.get("bytes_in")
        if bi:
            stats.total_bytes_in += bi
        bo = ev.get("bytes_out")
        if bo:
            stats.total_bytes_out += bo

        # Errors
        error_text = ev.get("error")
        if error_text:
            error_counts[error_text] = error_counts.get(error_text, 0) + 1
            if error_text not in stats.pool_errors:
                stats.pool_errors.append(error_text)

    # Compute average
    if query_count > 0:
        stats.avg_query_ms = total_query_ms / query_count

    # Top errors
    stats.top_errors = [
        {"error": err, "count": cnt}
        for err, cnt in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    return stats


def analyze_connection_distribution(
    entries: Iterable[LogEntry],
    existing_stats: ConnectionStats,
) -> ConnectionStats:
    """Extend existing ConnectionStats with host/application distribution and session tracking.

    Returns the updated ConnectionStats.
    """
    session_durations: List[float] = []
    open_sessions: Dict[int, Dict[str, Any]] = {}

    for entry in entries:
        if is_connection_event(entry):
            # by_host
            host = entry.remote_host
            if host:
                existing_stats.connections_by_host[host] = (
                    existing_stats.connections_by_host.get(host, 0) + 1
                )

            # by_application
            app = entry.application_name
            if app:
                existing_stats.connections_by_application[app] = (
                    existing_stats.connections_by_application.get(app, 0) + 1
                )

            # Track open sessions for duration
            if entry.pid is not None:
                open_sessions[entry.pid] = {
                    "start": entry.timestamp,
                    "host": host,
                    "app": app,
                }

        elif is_disconnection(entry):
            existing_stats.total_sessions += 1
            if entry.pid and entry.pid in open_sessions:
                sess = open_sessions.pop(entry.pid)
                dm = _DISCONN_DURATION_RE.search(entry.message)
                if dm:
                    dur_ms = _session_duration_from_time_str(dm.group(1))
                else:
                    start = sess.get("start")
                    if start and entry.timestamp:
                        dur_ms = (entry.timestamp - start).total_seconds() * 1000.0
                    else:
                        dur_ms = 0.0
                if dur_ms > 0:
                    session_durations.append(dur_ms)
                    existing_stats.session_durations_ms.append(dur_ms)

    # Update avg_session_duration_ms
    all_durs = existing_stats.session_durations_ms
    if all_durs:
        existing_stats.avg_session_duration_ms = sum(all_durs) / len(all_durs)

    return existing_stats


def _session_duration_from_time_str(time_str: str) -> float:
    """Convert HH:MM:SS or HH:MM:SS.mmm string to milliseconds."""
    try:
        parts = time_str.split(":")
        if len(parts) == 3:
            h, m, s = parts
            return (int(h) * 3600 + int(m) * 60 + float(s)) * 1000.0
    except (ValueError, IndexError):
        pass
    return 0.0


def detect_query_regression(slow_queries: List[SlowQuery]) -> List[SlowQuery]:
    """For each slow query with >= 5 samples, compute OLS slope.

    Marks is_regression=True and sets regression_slope if slope > 1% of mean per occurrence.
    Returns updated list (modifies in place and returns it).
    """
    for sq in slow_queries:
        if len(sq.durations) < 5:
            continue
        slope = linear_regression_slope(sq.durations)
        if slope > sq.avg_duration_ms * 0.01:
            sq.is_regression = True
            sq.regression_slope = float(slope)
        else:
            sq.is_regression = False
            sq.regression_slope = None
    return slow_queries


def analyze_checkpoint_extended(
    entries: Iterable[LogEntry],
    existing_stats: CheckpointStats,
) -> Tuple[CheckpointStats, int, int, int, float, float]:
    """Parse checkpoint lines for WAL files added/removed/recycled, distance, estimate, cause.

    Returns:
        (updated_CheckpointStats, wal_added, wal_removed, wal_recycled, avg_distance, avg_estimate)
    """
    wal_added_total = 0
    wal_removed_total = 0
    wal_recycled_total = 0
    distances: List[float] = []
    estimates: List[float] = []

    for entry in entries:
        if not is_checkpoint(entry):
            continue

        msg = entry.message

        # WAL file counts from checkpoint complete line
        wm = _CHECKPOINT_WAL_RE.search(msg)
        if wm:
            wal_added_total += int(wm.group(1))
            wal_removed_total += int(wm.group(2))
            wal_recycled_total += int(wm.group(3))

        # Distance / estimate
        dm = _CHECKPOINT_DISTANCE_RE.search(msg)
        if dm:
            distances.append(float(dm.group(1)))
            estimates.append(float(dm.group(2)))

        # Cause
        cm = _CHECKPOINT_CAUSE_RE.search(msg)
        if cm:
            cause = cm.group(1).lower()
            # normalize
            if cause in ("immediate", "requested"):
                ctype = "immediate"
            elif cause in ("timed", "xlog"):
                ctype = "scheduled"
            elif cause == "shutdown":
                ctype = "shutdown"
            else:
                ctype = cause
            existing_stats.by_type[ctype] = existing_stats.by_type.get(ctype, 0) + 1

    avg_distance = sum(distances) / len(distances) if distances else 0.0
    avg_estimate = sum(estimates) / len(estimates) if estimates else 0.0

    return (
        existing_stats,
        wal_added_total,
        wal_removed_total,
        wal_recycled_total,
        avg_distance,
        avg_estimate,
    )


def build_hourly_timeline(
    entries: Iterable[LogEntry],
) -> Dict[str, Dict[str, int]]:
    """Build a complete hourly timeline dict for all event types.

    Returns:
        {hour_str -> {queries: N, errors: N, locks: N, checkpoints: N,
                      autovacuums: N, temp_files: N, connections: N}}
    hour_str format: "YYYY-MM-DD HH:00"
    """
    from .parser import (
        is_slow_query as _is_slow,
        is_lock_wait as _is_lock,
        is_deadlock as _is_deadlock,
        is_checkpoint as _is_cp,
        is_autovacuum as _is_av,
        is_tempfile as _is_tf,
        is_connection_event as _is_conn,
    )

    timeline: Dict[str, Dict[str, int]] = {}

    def _get_hour(entry: LogEntry) -> Optional[str]:
        if entry.timestamp:
            return entry.timestamp.strftime("%Y-%m-%d %H:00")
        return None

    def _inc(hour: str, key: str) -> None:
        if hour not in timeline:
            timeline[hour] = {
                "queries": 0,
                "errors": 0,
                "locks": 0,
                "checkpoints": 0,
                "autovacuums": 0,
                "temp_files": 0,
                "connections": 0,
            }
        timeline[hour][key] = timeline[hour].get(key, 0) + 1

    for entry in entries:
        hour = _get_hour(entry)
        if hour is None:
            continue

        # Queries (any entry with a duration counts)
        if entry.duration_ms is not None:
            _inc(hour, "queries")

        # Errors/warnings
        if entry.log_level in (LogLevel.ERROR, LogLevel.FATAL, LogLevel.PANIC, LogLevel.WARNING):
            _inc(hour, "errors")

        # Locks
        if _is_lock(entry) or _is_deadlock(entry):
            _inc(hour, "locks")

        # Checkpoints
        if _is_cp(entry):
            _inc(hour, "checkpoints")

        # Autovacuums
        if _is_av(entry):
            _inc(hour, "autovacuums")

        # Temp files
        if _is_tf(entry):
            _inc(hour, "temp_files")

        # Connections
        if _is_conn(entry):
            _inc(hour, "connections")

    return timeline


def compute_queries_per_minute(
    slow_queries: List[SlowQuery],
    time_range_minutes: float,
) -> float:
    """Return total query count divided by time range in minutes."""
    if time_range_minutes <= 0:
        return 0.0
    total = sum(sq.count for sq in slow_queries)
    return round(total / time_range_minutes, 4)


def find_cancelled_queries(entries: Iterable[LogEntry]) -> List[Dict[str, Any]]:
    """Find all cancelled query events.

    Returns list of dicts with: timestamp, query, reason, database, user.
    """
    cancelled: List[Dict[str, Any]] = []
    for entry in entries:
        if not is_cancellation(entry):
            continue
        reason = "unknown"
        m = _CANCELLATION_RE.search(entry.message)
        if m:
            reason = m.group(1).strip()
        cancelled.append({
            "timestamp": entry.timestamp,
            "query": entry.query or entry.message[:500],
            "reason": reason,
            "database": entry.database,
            "user": entry.user,
            "pid": entry.pid,
        })
    return cancelled


# ---------------------------------------------------------------------------
# Main Analyzer class
# ---------------------------------------------------------------------------

class Analyzer:
    """Analyzes a stream of LogEntry objects and produces an AnalysisResult."""

    def __init__(
        self,
        log_file_paths: List[str],
        slow_query_threshold_ms: float = 1000.0,
        top_queries: int = 25,
        top_errors: int = 20,
    ):
        self.log_file_paths = log_file_paths
        self.slow_query_threshold_ms = slow_query_threshold_ms
        self.top_queries = top_queries
        self.top_errors = top_errors

        # Internal state
        self._slow_query_map: Dict[str, SlowQuery] = {}
        self._error_map: Dict[str, ErrorPattern] = {}
        self._lock_events: List[LockEvent] = []
        self._autovacuum: List[AutovacuumStats] = []
        self._temp_files: List[TempFileStats] = []
        self._repl_events: List[ReplicationLagEvent] = []
        self._panic_fatal: List[LogEntry] = []
        self._wait_events: Dict[str, int] = {}
        self._conn_stats = ConnectionStats()
        self._checkpoint_stats = CheckpointStats()
        self._checkpoint_events: list = []
        self._all_timestamps: List[datetime] = []
        self._total_entries = 0
        self._total_lines = 0
        self._concurrent_tracker: Dict[int, datetime] = {}  # pid -> connect_time

        # v2 state
        self._pgbouncer_entries: List[LogEntry] = []
        self._checkpoint_wal_added = 0
        self._checkpoint_wal_removed = 0
        self._checkpoint_wal_recycled = 0
        self._checkpoint_distances: List[float] = []
        self._checkpoint_estimates: List[float] = []

    # ------------------------------------------------------------------
    def process_entries(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        """Process an iterable of LogEntry objects and return an AnalysisResult.

        Collects all entries into a list for multi-pass analysis, then runs
        all analyzers to populate the full AnalysisResult.
        """
        start = datetime.now()

        # Collect all entries (needed for multi-pass analyzers)
        all_entries: List[LogEntry] = []
        for entry in entries:
            all_entries.append(entry)
            self._total_entries += 1
            self._total_lines += 1

            if entry.timestamp:
                self._all_timestamps.append(entry.timestamp)

            # Single-pass handlers
            self._handle_slow_query(entry)
            self._handle_error(entry)
            self._handle_lock(entry)
            self._handle_checkpoint(entry)
            self._handle_autovacuum(entry)
            self._handle_tempfile(entry)
            self._handle_connection(entry)
            self._handle_replication(entry)
            self._handle_fatal_panic(entry)

        end = datetime.now()
        return self._build_result_v2(start, end, all_entries)

    # ------------------------------------------------------------------
    def _handle_slow_query(self, entry: LogEntry) -> None:
        if not is_slow_query(entry, self.slow_query_threshold_ms):
            return
        query = entry.query or entry.message
        norm = normalize_query(query)
        if not norm:
            return
        key = norm[:500]
        if key not in self._slow_query_map:
            self._slow_query_map[key] = SlowQuery(
                query=query[:2000],
                normalized_query=norm,
            )
        sq = self._slow_query_map[key]
        sq.add_sample(
            duration_ms=entry.duration_ms,
            timestamp=entry.timestamp,
            database=entry.database,
            user=entry.user,
            query=query[:2000],
            application=entry.application_name,
        )
        # Set query_type on the SlowQuery if not already set
        if sq.query_type == "unknown" and entry.query_type:
            sq.query_type = entry.query_type
        # Track cancellations
        if is_cancellation(entry):
            sq.cancellation_count += 1
        # Track phase durations
        if entry.phase and entry.duration_ms is not None:
            current = sq.phase_durations.get(entry.phase, 0.0)
            sq.phase_durations[entry.phase] = current + entry.duration_ms

    def _handle_error(self, entry: LogEntry) -> None:
        if entry.log_level not in (
            LogLevel.ERROR, LogLevel.FATAL, LogLevel.PANIC,
            LogLevel.WARNING,
        ):
            return
        key = _pattern_key(entry.message)
        if key not in self._error_map:
            category = categorize_error(entry.message)
            self._error_map[key] = ErrorPattern(
                error_code=entry.error_code,
                message_pattern=key,
                category=category,
            )
        self._error_map[key].add_occurrence(
            message=entry.message,
            timestamp=entry.timestamp,
            user=entry.user,
            database=entry.database,
        )

    def _handle_lock(self, entry: LogEntry) -> None:
        if is_lock_wait(entry) or is_deadlock(entry):
            ev = extract_lock_event(entry)
            if ev:
                self._lock_events.append(ev)

    def _handle_checkpoint(self, entry: LogEntry) -> None:
        if not is_checkpoint(entry):
            return
        if _CHECKPOINT_WARNING_RE.search(entry.message):
            self._checkpoint_stats.warning_count += 1
            return
        cp = extract_checkpoint(entry)
        if cp:
            self._checkpoint_stats.add_checkpoint(
                duration_ms=cp["duration_ms"],
                buffers_written=cp["buffers"],
                checkpoint_type=cp.get("type", "scheduled"),
            )
            # v2 WAL tracking
            self._checkpoint_wal_added += cp.get("wal_added", 0)
            self._checkpoint_wal_removed += cp.get("wal_removed", 0)
            self._checkpoint_wal_recycled += cp.get("wal_recycled", 0)
            if cp.get("distance") is not None:
                self._checkpoint_distances.append(cp["distance"])
            if cp.get("estimate") is not None:
                self._checkpoint_estimates.append(cp["estimate"])
            # Store per-event detail for HTML report
            from .models import CheckpointEvent as _CPEvent
            # Parse buffers pct from original message  e.g. "wrote 259579 buffers (12.4%)"
            import re as _re
            _pct_m = _re.search(r'wrote\s+\d+\s+buffers\s+\(([\d.]+)%\)', entry.message)
            _pct = float(_pct_m.group(1)) if _pct_m else 0.0
            self._checkpoint_events.append(_CPEvent(
                timestamp=entry.timestamp,
                duration_ms=cp["duration_ms"],
                write_s=cp.get("write_s", 0.0),
                sync_s=cp.get("sync_s", 0.0),
                buffers_written=cp["buffers"],
                buffers_pct=_pct,
                wal_added=cp.get("wal_added", 0),
                wal_removed=cp.get("wal_removed", 0),
                wal_recycled=cp.get("wal_recycled", 0),
                distance_kb=cp.get("distance"),
                estimate_kb=cp.get("estimate"),
                checkpoint_type=cp.get("type", "scheduled"),
            ))

    def _handle_autovacuum(self, entry: LogEntry) -> None:
        if not is_autovacuum(entry):
            return
        av = extract_autovacuum(entry)
        if av:
            self._autovacuum.append(av)

    def _handle_tempfile(self, entry: LogEntry) -> None:
        if not is_tempfile(entry):
            return
        tf = extract_tempfile(entry)
        if tf:
            if entry.query:
                tf.query = entry.query[:1000]
            self._temp_files.append(tf)

    def _handle_connection(self, entry: LogEntry) -> None:
        msg = entry.message
        if is_connection_event(entry):
            self._conn_stats.total_connections += 1
            hour = entry.timestamp.hour if entry.timestamp else 0
            self._conn_stats.connections_by_hour[hour] = (
                self._conn_stats.connections_by_hour.get(hour, 0) + 1
            )
            if entry.user:
                self._conn_stats.connections_by_user[entry.user] = (
                    self._conn_stats.connections_by_user.get(entry.user, 0) + 1
                )
            if entry.database:
                self._conn_stats.connections_by_database[entry.database] = (
                    self._conn_stats.connections_by_database.get(entry.database, 0) + 1
                )
            if entry.remote_host:
                self._conn_stats.connections_by_host[entry.remote_host] = (
                    self._conn_stats.connections_by_host.get(entry.remote_host, 0) + 1
                )
            if entry.application_name:
                self._conn_stats.connections_by_application[entry.application_name] = (
                    self._conn_stats.connections_by_application.get(entry.application_name, 0) + 1
                )
            if entry.pid:
                self._concurrent_tracker[entry.pid] = entry.timestamp or datetime.now()
                current = len(self._concurrent_tracker)
                if current > self._conn_stats.peak_concurrent:
                    self._conn_stats.peak_concurrent = current

        elif is_disconnection(entry):
            self._conn_stats.total_disconnections += 1
            self._conn_stats.total_sessions += 1
            if entry.pid and entry.pid in self._concurrent_tracker:
                del self._concurrent_tracker[entry.pid]
            # Track session duration
            dm = _DISCONN_DURATION_RE.search(msg)
            if dm:
                dur_ms = _session_duration_from_time_str(dm.group(1))
                if dur_ms > 0:
                    self._conn_stats.session_durations_ms.append(dur_ms)

        elif is_auth_failure(entry):
            self._conn_stats.auth_failures += 1

    def _handle_replication(self, entry: LogEntry) -> None:
        m = _REPL_LAG_RE.search(entry.message)
        if m:
            lag_val = float(m.group(1))
            unit = (m.group(2) or "bytes").lower()
            lag_bytes = None
            lag_sec = None
            if "byte" in unit:
                lag_bytes = int(lag_val)
            elif "mb" in unit:
                lag_bytes = int(lag_val * 1024 * 1024)
            elif "gb" in unit:
                lag_bytes = int(lag_val * 1024 * 1024 * 1024)
            else:
                lag_sec = lag_val
            self._repl_events.append(
                ReplicationLagEvent(
                    timestamp=entry.timestamp,
                    lag_bytes=lag_bytes,
                    lag_seconds=lag_sec,
                    message=entry.message[:500],
                )
            )

    def _handle_fatal_panic(self, entry: LogEntry) -> None:
        if entry.log_level in (LogLevel.FATAL, LogLevel.PANIC):
            self._panic_fatal.append(entry)

    # ------------------------------------------------------------------
    def _build_result_v2(
        self,
        start: datetime,
        end: datetime,
        all_entries: List[LogEntry],
    ) -> AnalysisResult:
        """Build the full v2 AnalysisResult using all collected state."""
        # Sort slow queries by total duration desc, keep top N
        sorted_sq = sorted(
            self._slow_query_map.values(),
            key=lambda q: q.total_duration_ms,
            reverse=True,
        )[: self.top_queries]

        # Sort error patterns by count desc, keep top N
        sorted_ep = sorted(
            self._error_map.values(),
            key=lambda e: e.count,
            reverse=True,
        )[: self.top_errors]

        # Calculate QPS and error rate
        time_range_start = min(self._all_timestamps) if self._all_timestamps else None
        time_range_end = max(self._all_timestamps) if self._all_timestamps else None

        duration_sec = 1.0
        if time_range_start and time_range_end:
            delta = (time_range_end - time_range_start).total_seconds()
            if delta > 0:
                duration_sec = delta

        total_queries = sum(sq.count for sq in self._slow_query_map.values())
        total_errors = sum(ep.count for ep in self._error_map.values())

        # Update avg_session_duration from collected data
        if self._conn_stats.session_durations_ms:
            self._conn_stats.avg_session_duration_ms = (
                sum(self._conn_stats.session_durations_ms)
                / len(self._conn_stats.session_durations_ms)
            )

        # Detect query regression
        detect_query_regression(sorted_sq)

        # v2 multi-pass analyzers
        session_stats = analyze_sessions(iter(all_entries))
        query_type_stats = analyze_query_types(iter(all_entries))
        prepare_bind_execute = analyze_prepare_bind_execute(iter(all_entries))
        auto_explain_plans = analyze_auto_explain_plans(iter(all_entries), sorted_sq)
        cancelled_queries = find_cancelled_queries(iter(all_entries))

        # PgBouncer: only process if any entries look like pgbouncer
        pgbouncer_stats = None
        pgbouncer_entries = [e for e in all_entries if "pgbouncer" in (e.raw_line or "").lower()
                             or "pgbouncer" in (e.message or "").lower()]
        if pgbouncer_entries:
            pgbouncer_stats = analyze_pgbouncer(iter(pgbouncer_entries))

        # Checkpoint WAL averages
        ckpt_dist_avg = (
            sum(self._checkpoint_distances) / len(self._checkpoint_distances)
            if self._checkpoint_distances else 0.0
        )
        ckpt_est_avg = (
            sum(self._checkpoint_estimates) / len(self._checkpoint_estimates)
            if self._checkpoint_estimates else 0.0
        )

        # Total query duration
        total_query_duration_ms = sum(sq.total_duration_ms for sq in self._slow_query_map.values())

        # QPM
        duration_minutes = duration_sec / 60.0
        qpm = compute_queries_per_minute(sorted_sq, duration_minutes)

        # Connection by host/application from conn_stats
        connection_by_host = dict(self._conn_stats.connections_by_host)
        connection_by_application = dict(self._conn_stats.connections_by_application)

        return AnalysisResult(
            log_file_paths=self.log_file_paths,
            analysis_start=start,
            analysis_end=end,
            total_entries=self._total_entries,
            total_lines=self._total_lines,
            slow_query_threshold_ms=self.slow_query_threshold_ms,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            slow_queries=sorted_sq,
            error_patterns=sorted_ep,
            lock_events=self._lock_events,
            connection_stats=self._conn_stats,
            checkpoint_stats=self._checkpoint_stats,
            checkpoint_events=self._checkpoint_events,
            autovacuum_stats=self._autovacuum,
            temp_files=sorted(self._temp_files, key=lambda t: t.size_bytes, reverse=True),
            wait_events=self._wait_events,
            replication_lag_events=self._repl_events,
            panic_fatal_events=self._panic_fatal[:50],
            queries_per_second=round(total_queries / duration_sec, 4),
            error_rate_per_minute=round(total_errors / (duration_sec / 60), 4),
            # v2 fields
            session_stats=session_stats,
            query_type_stats=query_type_stats,
            prepare_bind_execute=prepare_bind_execute,
            auto_explain_plans=auto_explain_plans,
            pgbouncer_stats=pgbouncer_stats,
            cancelled_queries=cancelled_queries,
            connection_by_host=connection_by_host,
            connection_by_application=connection_by_application,
            checkpoint_wal_added=self._checkpoint_wal_added,
            checkpoint_wal_removed=self._checkpoint_wal_removed,
            checkpoint_wal_recycled=self._checkpoint_wal_recycled,
            checkpoint_distance_avg=ckpt_dist_avg,
            checkpoint_estimate_avg=ckpt_est_avg,
            total_query_duration_ms=total_query_duration_ms,
            queries_per_minute=qpm,
        )


# ---------------------------------------------------------------------------
# Regression detector (standalone, for backward compatibility)
# ---------------------------------------------------------------------------

def detect_query_regression_single(slow_query: SlowQuery) -> Optional[float]:
    """Return slope (ms per occurrence) if query is getting slower over time.

    Returns None if insufficient data or no regression detected.
    (Deprecated: use detect_query_regression(list) instead.)
    """
    durations = slow_query.durations
    if len(durations) < 5:
        return None
    slope = linear_regression_slope(durations)
    # Return slope only if it's meaningfully positive (>1% of mean per occurrence)
    if slope > slow_query.avg_duration_ms * 0.01:
        return float(slope)
    return None


# ---------------------------------------------------------------------------
# Error storm detector
# ---------------------------------------------------------------------------

def detect_error_storms(
    error_patterns: List[ErrorPattern],
    window_minutes: int = 5,
    threshold: int = 50,
) -> List[Tuple[str, int]]:
    """Return list of (pattern, peak_rate) for patterns that exceed threshold per window."""
    storms = []
    for ep in error_patterns:
        peak_hourly = max(ep.hourly_counts.values(), default=0)
        # Scale to window_minutes
        estimated_window = int(peak_hourly * window_minutes / 60)
        if estimated_window >= threshold:
            storms.append((ep.message_pattern, estimated_window))
    return storms


# ---------------------------------------------------------------------------
# Autovacuum table frequency analysis
# ---------------------------------------------------------------------------

def analyze_autovacuum_frequency(
    autovacuum_stats: List[AutovacuumStats],
) -> List[Tuple[str, int, float]]:
    """Return list of (table, count, avg_duration_ms) sorted by count desc."""
    table_counts: Dict[str, List[float]] = defaultdict(list)
    for av in autovacuum_stats:
        key = f"{av.table_schema}.{av.table}"
        table_counts[key].append(av.duration_ms)
    result = [
        (table, len(durs), sum(durs) / len(durs))
        for table, durs in table_counts.items()
    ]
    return sorted(result, key=lambda x: x[1], reverse=True)


# ---------------------------------------------------------------------------
# Connection pool efficiency
# ---------------------------------------------------------------------------

def connection_pool_efficiency(conn_stats: ConnectionStats) -> float:
    """Return a 0-100 score of connection reuse efficiency.

    High = good (few connections handling many queries), Low = bad (many short connections).
    """
    if conn_stats.total_connections == 0:
        return 100.0
    # Rough heuristic: peak concurrent / total connections
    ratio = conn_stats.peak_concurrent / conn_stats.total_connections
    # Ideal: ratio near 1 (connections are long-lived and reused)
    score = min(100.0, ratio * 100.0)
    return round(score, 1)
