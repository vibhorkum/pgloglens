"""Rule-based Root Cause Analysis engine for pgloglens v2.

Each rule is a deterministic check that inspects the AnalysisResult and
emits zero or more RCAFinding objects.  Rules are applied in priority order
(CRITICAL first) so the most urgent issues surface at the top.

v2 additions:
  - 8 new rules (Rules 15-22)
  - AI-enhanced RCA functions: ai_analyze_slow_queries, ai_analyze_explain_plan,
    ai_generate_postgresql_config, ai_generate_index_recommendations
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

from .analyzer import (
    analyze_autovacuum_frequency,
    connection_pool_efficiency,
    detect_error_storms,
    detect_query_regression,
)
from .models import AnalysisResult, AutoExplainPlan, RCAFinding, Severity, SlowQuery


# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------

@dataclass
class RCAConfig:
    """Configurable thresholds for all RCA rules.

    Override defaults via ~/.pgloglens.yaml under the ``rca_thresholds`` key,
    or pass an instance directly to ``run_rca()``.  All fields are optional —
    omitted keys fall back to the class defaults.

    Example yaml section::

        rca_thresholds:
          connection_warn: 50        # warn at 50 connections (not 80)
          connection_critical: 100   # critical at 100 (not 150)
          temp_file_mb: 50           # flag temp files >= 50 MB
    """
    # Connections
    connection_warn: int = 80
    connection_critical: int = 150
    # Checkpoint
    checkpoint_freq_warn: int = 3
    checkpoint_slow_ms: float = 60_000.0
    # Locks
    lock_warn: int = 10
    lock_critical: int = 50
    # Deadlocks
    deadlock_warn: int = 2
    # Temp files
    temp_file_mb: float = 100.0
    temp_file_high_mb: float = 1_024.0
    # Auth failures
    auth_fail_warn: int = 5
    auth_fail_critical: int = 50
    # Autovacuum
    autovac_freq_warn: int = 10
    autovac_freq_high: int = 20
    # Replication lag
    repl_lag_critical_mb: float = 100.0
    # Long-running transactions
    long_tx_warn_ms: float = 300_000.0    # 5 minutes
    long_tx_critical_ms: float = 3_600_000.0  # 1 hour
    # Session idle time
    idle_ratio_warn: float = 0.70
    # Query type imbalance
    dml_ratio_warn: float = 0.40
    dml_lock_events_warn: int = 5
    # Parse/plan phase overhead
    parse_ratio_warn: float = 0.20
    # Error storm (errors per 5-minute window)
    error_storm_threshold: int = 50
    # Query cancellation storm
    cancelled_query_storm: int = 20


# Module-level context set by run_rca() before executing rules
_rca_config: RCAConfig = RCAConfig()


def get_rca_config() -> RCAConfig:
    """Return the currently active RCA configuration."""
    return _rca_config


# ---------------------------------------------------------------------------
# Rule type
# ---------------------------------------------------------------------------

RuleFunc = Callable[[AnalysisResult], List[RCAFinding]]

_REGISTERED_RULES: List[RuleFunc] = []


def rule(fn: RuleFunc) -> RuleFunc:
    """Decorator that registers a function as an RCA rule."""
    _REGISTERED_RULES.append(fn)
    return fn


# ---------------------------------------------------------------------------
# Rules 1–14 (original)
# ---------------------------------------------------------------------------

@rule
def rule_high_checkpoint_frequency(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    cp = result.checkpoint_stats

    if cp.warning_count >= cfg.checkpoint_freq_warn:
        findings.append(
            RCAFinding(
                rule_id="HIGH_CHECKPOINT_FREQUENCY",
                severity=Severity.HIGH,
                title="Checkpoint occurring too frequently",
                description=(
                    f"PostgreSQL emitted {cp.warning_count} checkpoint-frequency warnings. "
                    "This indicates WAL is filling up faster than checkpoints can process it, "
                    "causing excessive I/O spikes and increased recovery time."
                ),
                evidence=[f"{cp.warning_count} 'checkpoint occurring too frequently' warnings"],
                recommendations=[
                    "Increase max_wal_size (current default 1GB is often too small). "
                    "Try: ALTER SYSTEM SET max_wal_size = '4GB'; SELECT pg_reload_conf();",
                    "Increase checkpoint_completion_target to 0.9 to spread I/O: "
                    "ALTER SYSTEM SET checkpoint_completion_target = '0.9';",
                    "If using SSDs, consider reducing checkpoint_warning = 0 to suppress noise "
                    "and tuning based on I/O throughput instead.",
                ],
                metric_value=float(cp.warning_count),
                metric_label="checkpoint warnings",
            )
        )

    if cp.count > 0 and cp.avg_duration_ms > cfg.checkpoint_slow_ms:
        findings.append(
            RCAFinding(
                rule_id="SLOW_CHECKPOINTS",
                severity=Severity.MEDIUM,
                title="Checkpoints are taking abnormally long",
                description=(
                    f"Average checkpoint duration is {cp.avg_duration_ms / 1000:.1f}s "
                    f"(max: {cp.max_duration_ms / 1000:.1f}s). "
                    "Slow checkpoints indicate disk I/O bottleneck or dirty buffer pressure."
                ),
                evidence=[
                    f"avg checkpoint duration: {cp.avg_duration_ms / 1000:.1f}s",
                    f"max checkpoint duration: {cp.max_duration_ms / 1000:.1f}s",
                    f"total checkpoints: {cp.count}",
                ],
                recommendations=[
                    "Move PostgreSQL WAL directory to a faster disk (NVMe).",
                    "Tune bgwriter_lru_maxpages and bgwriter_delay to reduce dirty buffer spikes.",
                    "Ensure checkpoint_completion_target = 0.9 to spread writes.",
                ],
                metric_value=cp.avg_duration_ms / 1000,
                metric_label="avg checkpoint seconds",
            )
        )
    return findings


@rule
def rule_connection_exhaustion(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    cs = result.connection_stats

    if cs.peak_concurrent >= cfg.connection_warn:
        severity = Severity.CRITICAL if cs.peak_concurrent >= cfg.connection_critical else Severity.HIGH
        findings.append(
            RCAFinding(
                rule_id="CONNECTION_EXHAUSTION",
                severity=severity,
                title="High connection count detected",
                description=(
                    f"Peak concurrent connections reached {cs.peak_concurrent}. "
                    "PostgreSQL has a hard cap (max_connections, default 100). "
                    "Approaching this limit causes 'FATAL: remaining connection slots are reserved' errors."
                ),
                evidence=[
                    f"Peak concurrent connections: {cs.peak_concurrent}",
                    f"Total connections observed: {cs.total_connections}",
                ],
                recommendations=[
                    "Deploy PgBouncer in transaction mode: "
                    "pool_mode = transaction; max_client_conn = 1000; default_pool_size = 25",
                    "Alternatively, use pg_pool-II for session-level pooling.",
                    "Short-term: ALTER SYSTEM SET max_connections = 200; — requires restart.",
                    "Review application code for connection leaks.",
                ],
                metric_value=float(cs.peak_concurrent),
                metric_label="peak concurrent connections",
            )
        )
    return findings


@rule
def rule_lock_storms(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    lock_events = [e for e in result.lock_events if not e.is_deadlock]

    if len(lock_events) >= cfg.lock_warn:
        severity = Severity.CRITICAL if len(lock_events) >= cfg.lock_critical else Severity.HIGH

        durations = [e.wait_duration_ms for e in lock_events if e.wait_duration_ms]
        avg_wait = sum(durations) / len(durations) if durations else 0

        findings.append(
            RCAFinding(
                rule_id="LOCK_STORMS",
                severity=severity,
                title="Application-level lock contention detected",
                description=(
                    f"{len(lock_events)} lock wait events observed. "
                    f"Average wait time: {avg_wait:.1f}ms. "
                    "This pattern indicates serialization bottlenecks in application transaction logic."
                ),
                evidence=[
                    f"{len(lock_events)} lock wait events",
                    f"Average lock wait: {avg_wait:.1f}ms",
                ],
                recommendations=[
                    "Identify the most-blocking queries using pg_stat_activity and pg_locks.",
                    "Set lock_timeout to fail fast: SET lock_timeout = '5s';",
                    "Review application transaction boundaries — keep transactions short.",
                    "Consider advisory locks for application-level serialization instead of row locks.",
                    "Use SELECT ... FOR UPDATE SKIP LOCKED for queue-like patterns.",
                ],
                affected_queries=[
                    e.waiting_query[:200] for e in lock_events[:5] if e.waiting_query
                ],
                metric_value=float(len(lock_events)),
                metric_label="lock wait events",
            )
        )
    return findings


@rule
def rule_deadlock_pattern(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    deadlocks = [e for e in result.lock_events if e.is_deadlock]

    if len(deadlocks) >= cfg.deadlock_warn:
        findings.append(
            RCAFinding(
                rule_id="DEADLOCK_PATTERN",
                severity=Severity.HIGH,
                title="Recurring deadlock pattern detected",
                description=(
                    f"{len(deadlocks)} deadlock events detected. "
                    "Recurring deadlocks indicate a transaction ordering issue in application code "
                    "where two or more transactions acquire locks in different orders."
                ),
                evidence=[f"{len(deadlocks)} deadlock events detected"],
                recommendations=[
                    "Ensure all transactions acquire locks in the same canonical order "
                    "(e.g., always lock table A before table B).",
                    "Use explicit SELECT ... FOR UPDATE to pre-declare lock intent.",
                    "Consider using SERIALIZABLE isolation level for correctness-critical transactions.",
                    "Enable log_lock_waits = on and deadlock_timeout = '1s' to capture full context.",
                ],
                metric_value=float(len(deadlocks)),
                metric_label="deadlock events",
            )
        )
    return findings


@rule
def rule_temp_file_abuse(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    large_temps = [t for t in result.temp_files if t.size_mb >= cfg.temp_file_mb]

    if large_temps:
        total_mb = sum(t.size_mb for t in large_temps)
        max_mb = max(t.size_mb for t in large_temps)
        severity = Severity.HIGH if max_mb >= cfg.temp_file_high_mb else Severity.MEDIUM

        findings.append(
            RCAFinding(
                rule_id="TEMP_FILE_ABUSE",
                severity=severity,
                title="Queries generating large temporary files",
                description=(
                    f"{len(large_temps)} queries generated temp files ≥ 100MB "
                    f"(total: {total_mb:.0f}MB, max: {max_mb:.0f}MB). "
                    "This means work_mem is insufficient, causing PostgreSQL to spill to disk."
                ),
                evidence=[
                    f"{len(large_temps)} large temp files (≥100MB)",
                    f"Largest temp file: {max_mb:.0f}MB",
                    f"Total temp file I/O: {total_mb:.0f}MB",
                ],
                recommendations=[
                    f"Increase work_mem for sessions running these queries: "
                    f"SET work_mem = '{max(int(max_mb * 1.5), 256)}MB';",
                    "Target: ALTER SYSTEM SET work_mem = '64MB'; — applies globally.",
                    "Caution: work_mem is per-sort-operation × connections. Calculate: "
                    f"{max(int(max_mb * 1.5), 256)}MB × 10 sorts × {result.connection_stats.peak_concurrent or 20} conns "
                    f"= {max(int(max_mb * 1.5), 256) * 10 * (result.connection_stats.peak_concurrent or 20) // 1024}GB RAM",
                    "Add indexes to avoid large sort operations.",
                ],
                affected_queries=[t.query[:200] for t in large_temps[:5] if t.query],
                metric_value=max_mb,
                metric_label="max temp file MB",
            )
        )
    return findings


@rule
def rule_autovacuum_lagging(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    if not result.autovacuum_stats:
        return findings

    freq_data = analyze_autovacuum_frequency(result.autovacuum_stats)
    high_freq = [(t, c, avg) for t, c, avg in freq_data if c >= cfg.autovac_freq_warn]

    if high_freq:
        top_table, top_count, top_avg = high_freq[0]
        severity = Severity.HIGH if top_count >= cfg.autovac_freq_high else Severity.MEDIUM

        findings.append(
            RCAFinding(
                rule_id="AUTOVACUUM_LAGGING",
                severity=severity,
                title="Tables with excessive autovacuum frequency",
                description=(
                    f"Table '{top_table}' was autovacuumed {top_count} times "
                    f"(avg {top_avg / 1000:.1f}s per run). "
                    "Excessive autovacuum frequency indicates table bloat accumulation "
                    "or autovacuum settings that are too aggressive."
                ),
                evidence=[
                    f"Top table: {top_table} — {top_count} autovacuum runs",
                    f"Avg autovacuum duration: {top_avg / 1000:.1f}s",
                    f"Total tables with >10 runs: {len(high_freq)}",
                ],
                recommendations=[
                    f"Consider increasing fillfactor for '{top_table}': "
                    f"ALTER TABLE {top_table} SET (fillfactor = 70);",
                    "Enable HOT updates by lowering fillfactor on high-UPDATE tables.",
                    "Tune autovacuum_vacuum_scale_factor and autovacuum_vacuum_threshold "
                    "per-table for better control.",
                    "Check for missing indexes causing full table scans that generate dead tuples.",
                ],
                metric_value=float(top_count),
                metric_label=f"autovacuum runs on {top_table}",
            )
        )
    return findings


@rule
def rule_auth_failures_spike(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    failures = result.connection_stats.auth_failures

    if failures >= cfg.auth_fail_warn:
        severity = Severity.CRITICAL if failures >= cfg.auth_fail_critical else Severity.HIGH
        findings.append(
            RCAFinding(
                rule_id="AUTH_FAILURES_SPIKE",
                severity=severity,
                title="Authentication failure spike detected",
                description=(
                    f"{failures} authentication failures observed. "
                    "This may indicate misconfigured application credentials, credential rotation issues, "
                    "or a brute-force attack."
                ),
                evidence=[f"{failures} authentication failures"],
                recommendations=[
                    "Check pg_hba.conf for correct client authentication method.",
                    "Verify all application connection strings have correct credentials.",
                    "Consider fail2ban or pg_activity to block brute-force sources.",
                    "Enable log_connections = on and log_disconnections = on for full audit trail.",
                    "Review host-based authentication entries: SELECT * FROM pg_hba_file_rules();",
                ],
                metric_value=float(failures),
                metric_label="auth failures",
            )
        )
    return findings


@rule
def rule_replication_lag(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    if not result.replication_lag_events:
        return findings

    lag_bytes = [e.lag_bytes for e in result.replication_lag_events if e.lag_bytes]
    if lag_bytes:
        cfg = get_rca_config()
        max_lag_bytes = max(lag_bytes)
        max_lag_mb = max_lag_bytes / (1024 * 1024)
        severity = Severity.CRITICAL if max_lag_mb >= cfg.repl_lag_critical_mb else Severity.HIGH

        findings.append(
            RCAFinding(
                rule_id="REPLICATION_LAG",
                severity=severity,
                title="Replication standby falling behind",
                description=(
                    f"Replication lag reached {max_lag_mb:.1f}MB. "
                    "The standby is unable to keep up with the primary, "
                    "risking data loss on failover and increased recovery time."
                ),
                evidence=[
                    f"Max observed replication lag: {max_lag_mb:.1f}MB",
                    f"Total replication lag events: {len(result.replication_lag_events)}",
                ],
                recommendations=[
                    "Check standby disk I/O — it may not be able to apply WAL fast enough.",
                    "Check network bandwidth between primary and standby.",
                    "Increase wal_sender_timeout and wal_receiver_timeout if network is slow.",
                    "Consider using synchronous_commit = local for performance on primary.",
                    "Use pg_replication_slots to prevent WAL from being recycled too early.",
                ],
                metric_value=max_lag_mb,
                metric_label="max replication lag MB",
            )
        )
    return findings


@rule
def rule_oom_killer(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    oom_events = [e for e in result.panic_fatal_events
                  if re.search(r"out of memory|memory exhausted|could not resize", e.message, re.IGNORECASE)]

    if oom_events:
        findings.append(
            RCAFinding(
                rule_id="OOM_KILLER",
                severity=Severity.CRITICAL,
                title="Out-of-memory events detected",
                description=(
                    f"{len(oom_events)} out-of-memory events detected. "
                    "PostgreSQL is exceeding available RAM, which will cause crashes and data corruption."
                ),
                evidence=[e.message[:200] for e in oom_events[:3]],
                recommendations=[
                    "Reduce shared_buffers — typically 25% of RAM: "
                    "ALTER SYSTEM SET shared_buffers = '2GB';",
                    "Reduce work_mem — set conservatively and tune per-session.",
                    "Reduce max_connections — fewer connections = less memory pressure.",
                    "Enable huge_pages = try to reduce OS page table overhead.",
                    "Consider adding swap as a last resort to prevent OOM kills.",
                ],
                metric_value=float(len(oom_events)),
                metric_label="OOM events",
            )
        )
    return findings


@rule
def rule_slow_query_regression(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    regressed = []
    for sq in result.slow_queries:
        slope = detect_query_regression(sq)
        if slope is not None:
            regressed.append((sq, slope))

    if regressed:
        regressed.sort(key=lambda x: x[1], reverse=True)
        top_sq, top_slope = regressed[0]
        findings.append(
            RCAFinding(
                rule_id="SLOW_QUERY_REGRESSION",
                severity=Severity.HIGH,
                title="Query performance regression detected",
                description=(
                    f"{len(regressed)} query patterns are getting progressively slower over time. "
                    f"The worst regression is +{top_slope:.1f}ms per execution. "
                    "This typically indicates index degradation, stale statistics, or table bloat."
                ),
                evidence=[
                    f"Regression rate: +{top_slope:.1f}ms/execution for: {top_sq.normalized_query[:150]}",
                    f"Total regressing queries: {len(regressed)}",
                ],
                recommendations=[
                    "Run ANALYZE on affected tables to update statistics.",
                    "REINDEX tables with bloated indexes.",
                    "Run VACUUM to remove dead tuples and improve index efficiency.",
                    "Check for table size growth that has outpaced query plans.",
                    "Use pg_stat_statements to confirm and correlate with plan changes.",
                ],
                affected_queries=[sq.normalized_query[:200] for sq, _ in regressed[:5]],
                metric_value=top_slope,
                metric_label="max regression ms/execution",
            )
        )
    return findings


@rule
def rule_error_storm(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    storms = detect_error_storms(result.error_patterns, window_minutes=5, threshold=cfg.error_storm_threshold)

    if storms:
        worst_pattern, worst_rate = max(storms, key=lambda x: x[1])
        findings.append(
            RCAFinding(
                rule_id="ERROR_STORM",
                severity=Severity.CRITICAL,
                title="Error storm / cascading failure pattern detected",
                description=(
                    f"Peak error rate of approximately {worst_rate} errors/5min detected. "
                    "This indicates a cascading failure — likely one component (DB, app, network) "
                    "failing and causing error amplification."
                ),
                evidence=[
                    f"Peak rate: ~{worst_rate} errors/5min",
                    f"Pattern: {worst_pattern[:150]}",
                    f"Total error storms: {len(storms)}",
                ],
                recommendations=[
                    "Identify the root trigger: check error timestamps relative to deployments.",
                    "Implement circuit breakers in application code to prevent amplification.",
                    "Review all error patterns for a common underlying cause.",
                    "Check for cascading failures between microservices.",
                ],
                metric_value=float(worst_rate),
                metric_label="peak errors per 5min window",
            )
        )
    return findings


@rule
def rule_fatal_ssl_errors(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    ssl_errors = [e for e in result.panic_fatal_events
                  if re.search(r"ssl|tls|certificate", e.message, re.IGNORECASE)]
    if ssl_errors:
        findings.append(
            RCAFinding(
                rule_id="SSL_FATAL_ERRORS",
                severity=Severity.HIGH,
                title="SSL/TLS connection errors",
                description=(
                    f"{len(ssl_errors)} SSL/TLS fatal errors detected. "
                    "Clients are failing to establish secure connections, "
                    "indicating certificate expiry, misconfiguration, or protocol mismatch."
                ),
                evidence=[e.message[:200] for e in ssl_errors[:3]],
                recommendations=[
                    "Check SSL certificate expiry: openssl x509 -in server.crt -noout -dates",
                    "Verify ssl_cert_file and ssl_key_file point to valid certificates in postgresql.conf",
                    "Ensure clients support the PostgreSQL SSL protocol version (TLS 1.2+).",
                    "Check ssl_ca_file if using client certificate authentication.",
                ],
                metric_value=float(len(ssl_errors)),
                metric_label="SSL fatal events",
            )
        )
    return findings


@rule
def rule_disk_full(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    disk_errors = [e for e in result.panic_fatal_events
                   if re.search(r"no space left|disk full|ENOSPC|could not write to file|could not extend", e.message, re.IGNORECASE)]
    disk_patterns = [ep for ep in result.error_patterns
                     if ep.category == "disk"
                     and ep.count >= 3
                     and re.search(r"no space left|disk full|ENOSPC|could not write", ep.message_pattern, re.IGNORECASE)]

    total = len(disk_errors) + sum(ep.count for ep in disk_patterns)
    if total >= 3:
        findings.append(
            RCAFinding(
                rule_id="DISK_FULL",
                severity=Severity.CRITICAL,
                title="Disk space critically low — write failures detected",
                description=(
                    f"{total} disk write failure events detected. "
                    "PostgreSQL cannot write WAL or data files. This will cause crashes, "
                    "data loss, and inability to recover."
                ),
                evidence=[e.message[:200] for e in disk_errors[:3]],
                recommendations=[
                    "IMMEDIATELY free disk space — remove old WAL files, logs, core dumps.",
                    "Use pg_archivecleanup to remove archived WAL segments.",
                    "Move data directory to larger volume (requires planned downtime).",
                    "Enable pg_tblspc tablespace on larger mount point for overflow.",
                    "Set up disk space monitoring (e.g., >85% → alert).",
                ],
                metric_value=float(total),
                metric_label="disk error events",
            )
        )
    return findings


@rule
def rule_long_running_transactions(result: AnalysisResult) -> List[RCAFinding]:
    findings = []
    cfg = get_rca_config()
    very_slow = [sq for sq in result.slow_queries if sq.max_duration_ms >= cfg.long_tx_warn_ms]

    if very_slow:
        worst = max(very_slow, key=lambda q: q.max_duration_ms)
        severity = Severity.CRITICAL if worst.max_duration_ms >= cfg.long_tx_critical_ms else Severity.HIGH

        findings.append(
            RCAFinding(
                rule_id="LONG_RUNNING_TRANSACTIONS",
                severity=severity,
                title="Long-running transactions blocking autovacuum and causing lock contention",
                description=(
                    f"{len(very_slow)} query patterns with max duration ≥ 5 minutes detected. "
                    f"Worst: {worst.max_duration_ms / 60000:.1f} minutes. "
                    "Long transactions block autovacuum, accumulate dead tuples, "
                    "and hold locks that starve other sessions."
                ),
                evidence=[
                    f"Max duration: {worst.max_duration_ms / 60000:.1f} minutes",
                    f"Query: {worst.normalized_query[:200]}",
                    f"Queries with max >5min: {len(very_slow)}",
                ],
                recommendations=[
                    "Set statement_timeout: ALTER SYSTEM SET statement_timeout = '300000'; -- 5 min",
                    "Set idle_in_transaction_session_timeout = '60000'; to kill idle transactions.",
                    "Break large batch operations into smaller chunks using LIMIT/OFFSET.",
                    "Move analytical queries to read replicas.",
                    "Monitor pg_stat_activity for long-running transactions in production.",
                ],
                affected_queries=[sq.normalized_query[:200] for sq in very_slow[:5]],
                metric_value=worst.max_duration_ms / 60000,
                metric_label="max duration minutes",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rules 15–22 (v2 new rules)
# ---------------------------------------------------------------------------

@rule
def rule_high_session_idle_time(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 15: High session idle time — connection pool not used efficiently."""
    findings = []
    cfg = get_rca_config()
    ss = result.session_stats

    if ss.total_session_duration_ms <= 0:
        return findings

    idle_ratio = ss.total_idle_time_ms / ss.total_session_duration_ms if ss.total_session_duration_ms > 0 else 0.0

    if idle_ratio > cfg.idle_ratio_warn:
        pct = idle_ratio * 100
        findings.append(
            RCAFinding(
                rule_id="HIGH_SESSION_IDLE_TIME",
                severity=Severity.MEDIUM,
                title="Connections idle too long — connection pool underutilized",
                description=(
                    f"Average idle time is {pct:.1f}% of total session duration. "
                    "Connections are being held open without work, wasting max_connections slots "
                    "and preventing efficient resource sharing."
                ),
                evidence=[
                    f"Total session duration: {ss.total_session_duration_ms / 1000:.0f}s",
                    f"Total idle time: {ss.total_idle_time_ms / 1000:.0f}s",
                    f"Idle ratio: {pct:.1f}%",
                ],
                recommendations=[
                    "Connection pool not being used efficiently — connections idle too long. "
                    "Deploy PgBouncer transaction mode.",
                    "Configure PgBouncer: pool_mode = transaction; server_idle_timeout = 600",
                    "Set idle_in_transaction_session_timeout to reclaim stuck sessions.",
                    "Review application connection management — close connections when idle.",
                ],
                metric_value=pct,
                metric_label="idle time percentage",
            )
        )
    return findings


@rule
def rule_query_type_imbalance(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 16: Heavy DML (DELETE/UPDATE > 40%) combined with high lock events."""
    findings = []
    cfg = get_rca_config()
    qt = result.query_type_stats
    lock_events = [e for e in result.lock_events if not e.is_deadlock]

    total_queries = (
        qt.select_count + qt.insert_count + qt.update_count
        + qt.delete_count + qt.copy_count + qt.ddl_count + qt.other_count
    )
    if total_queries == 0:
        return findings

    dml_count = qt.delete_count + qt.update_count
    dml_ratio = dml_count / total_queries

    if dml_ratio > cfg.dml_ratio_warn and len(lock_events) >= cfg.dml_lock_events_warn:
        pct = dml_ratio * 100
        findings.append(
            RCAFinding(
                rule_id="QUERY_TYPE_IMBALANCE",
                severity=Severity.HIGH,
                title="Heavy DML contention pattern — DELETE/UPDATE dominant with lock events",
                description=(
                    f"DELETE and UPDATE queries account for {pct:.1f}% of all queries "
                    f"({dml_count:,} out of {total_queries:,}), combined with "
                    f"{len(lock_events)} lock wait events. "
                    "This pattern indicates batch DML operations are causing serialization bottlenecks."
                ),
                evidence=[
                    f"DELETE count: {qt.delete_count:,}",
                    f"UPDATE count: {qt.update_count:,}",
                    f"DML ratio: {pct:.1f}%",
                    f"Lock wait events: {len(lock_events)}",
                ],
                recommendations=[
                    "Heavy DML contention pattern — review batch operation scheduling.",
                    "Schedule large batch DELETE/UPDATE operations during off-peak hours.",
                    "Use row-level batching: DELETE ... WHERE id IN (SELECT id ... LIMIT 1000).",
                    "Consider SKIP LOCKED for concurrent queue-like DELETE patterns.",
                    "Add covering indexes to reduce lock scope on heavily updated tables.",
                ],
                metric_value=pct,
                metric_label="DML percentage",
            )
        )
    return findings


@rule
def rule_prepare_phase_bottleneck(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 17: Excessive time in parse/plan phase."""
    findings = []
    cfg = get_rca_config()
    pb = result.prepare_bind_execute

    if pb.total_execute_ms <= 0:
        return findings

    parse_ratio = pb.total_parse_ms / pb.total_execute_ms if pb.total_execute_ms > 0 else 0.0

    if parse_ratio > cfg.parse_ratio_warn:
        pct = parse_ratio * 100
        findings.append(
            RCAFinding(
                rule_id="PREPARE_PHASE_BOTTLENECK",
                severity=Severity.MEDIUM,
                title="Excessive time in query parse/plan phase",
                description=(
                    f"Parse/plan phase consumes {pct:.1f}% of total execute time "
                    f"({pb.total_parse_ms:,.0f}ms parse vs {pb.total_execute_ms:,.0f}ms execute). "
                    "This indicates queries are being planned on every execution rather than using cached plans."
                ),
                evidence=[
                    f"Total parse time: {pb.total_parse_ms:,.0f}ms",
                    f"Total execute time: {pb.total_execute_ms:,.0f}ms",
                    f"Parse ratio: {pct:.1f}%",
                    f"Parse count: {pb.parse_count:,}",
                ],
                recommendations=[
                    "Excessive time in query parse/plan phase. Consider prepared statements "
                    "or pg_stat_statements for plan cache analysis.",
                    "Use prepared statements in application code: PREPARE stmt AS SELECT ...",
                    "Enable plan_cache_mode = force_generic_plan for stable parameterized queries.",
                    "Review pg_stat_statements for queries with high planning time ratios.",
                    "Set pg_stat_statements.track = all to capture planning metrics.",
                ],
                metric_value=pct,
                metric_label="parse/execute time ratio %",
            )
        )
    return findings


@rule
def rule_autovacuum_wal_amplification(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 18: Autovacuum generating excessive WAL (>100MB)."""
    findings = []
    if not result.autovacuum_stats:
        return findings

    _100MB = 100 * 1024 * 1024
    heavy = [av for av in result.autovacuum_stats if av.wal_bytes > _100MB]

    if heavy:
        max_wal_mb = max(av.wal_bytes for av in heavy) / (1024 * 1024)
        total_wal_mb = sum(av.wal_bytes for av in heavy) / (1024 * 1024)
        worst = max(heavy, key=lambda av: av.wal_bytes)

        findings.append(
            RCAFinding(
                rule_id="AUTOVACUUM_WAL_AMPLIFICATION",
                severity=Severity.HIGH,
                title="Autovacuum generating excessive WAL — possible dead tuple accumulation",
                description=(
                    f"{len(heavy)} autovacuum run(s) generated >100MB of WAL each. "
                    f"Worst: {max_wal_mb:.0f}MB on table '{worst.table}'. "
                    "Excessive autovacuum WAL indicates large tables with very high dead tuple rates, "
                    "which also slows replication standbys."
                ),
                evidence=[
                    f"Runs with >100MB WAL: {len(heavy)}",
                    f"Max WAL per run: {max_wal_mb:.0f}MB (table: {worst.table})",
                    f"Total excess WAL from autovacuum: {total_wal_mb:.0f}MB",
                ],
                recommendations=[
                    "Autovacuum generating excessive WAL — check for large tables with "
                    "high dead tuple rates. Consider pg_repack.",
                    f"Run pg_repack on '{worst.table}' to reclaim space without heavy locking: "
                    f"pg_repack -t {worst.table}",
                    "Lower autovacuum_vacuum_scale_factor for the affected table to vacuum more frequently "
                    "with smaller batches.",
                    "Check UPDATE/DELETE rate on the table and add HOT-friendly fillfactor.",
                    "Consider partitioning large tables to reduce per-partition bloat.",
                ],
                metric_value=max_wal_mb,
                metric_label="max autovacuum WAL MB",
            )
        )
    return findings


@rule
def rule_connection_storm_by_host(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 19: Single host accounts for >60% of connections."""
    findings = []
    conn_by_host = result.connection_by_host or result.connection_stats.connections_by_host

    if not conn_by_host:
        return findings

    total = sum(conn_by_host.values())
    if total == 0:
        return findings

    top_host, top_count = max(conn_by_host.items(), key=lambda x: x[1])
    ratio = top_count / total

    if ratio > 0.60:
        pct = ratio * 100
        findings.append(
            RCAFinding(
                rule_id="CONNECTION_STORM_BY_HOST",
                severity=Severity.HIGH,
                title=f"Single client IP generating connection storm ({top_host})",
                description=(
                    f"Host '{top_host}' is responsible for {pct:.1f}% of all connections "
                    f"({top_count:,} out of {total:,} total). "
                    "This indicates a misconfigured or misbehaving client that is not pooling connections."
                ),
                evidence=[
                    f"Top host: {top_host} — {top_count:,} connections ({pct:.1f}%)",
                    f"Total connections: {total:,}",
                    f"Other hosts: {len(conn_by_host) - 1}",
                ],
                recommendations=[
                    "Single client IP generating connection storm — check connection pooling on that host.",
                    f"Investigate the application deployed at {top_host} for connection leaks.",
                    "Deploy PgBouncer on the client host to pool connections locally.",
                    "Set connection_limit per user/database in pg_hba.conf to cap impact.",
                    "Use pg_stat_activity to inspect what that host is doing: "
                    f"SELECT * FROM pg_stat_activity WHERE client_addr = '{top_host}';",
                ],
                metric_value=pct,
                metric_label="connection share from single host %",
            )
        )
    return findings


@rule
def rule_redshift_rds_specific(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 20: Managed PostgreSQL platform-specific advice."""
    findings = []
    platform = getattr(result, "source_platform", "postgresql")

    if platform in ("rds", "redshift"):
        platform_name = "Amazon RDS" if platform == "rds" else "Amazon Redshift"
        findings.append(
            RCAFinding(
                rule_id="MANAGED_PLATFORM_DETECTED",
                severity=Severity.INFO,
                title=f"Running on managed PostgreSQL ({platform_name}) — platform-specific considerations apply",
                description=(
                    f"Log analysis detected source platform: {platform_name}. "
                    "Managed PostgreSQL platforms have restrictions on certain parameters "
                    "and provide additional monitoring tools that should be leveraged."
                ),
                evidence=[f"Detected source_platform: {platform}"],
                recommendations=[
                    "Running on managed PostgreSQL — ensure parameter group changes and "
                    "consider RDS Performance Insights for additional metrics.",
                    "Use RDS Performance Insights to identify top wait events and top SQL.",
                    "Parameter changes require modifying the DB Parameter Group (not postgresql.conf).",
                    "Enable Enhanced Monitoring (1-second granularity) for OS-level metrics.",
                    "Consider RDS Proxy for connection pooling instead of direct PgBouncer.",
                    "Use CloudWatch Logs Insights for log analysis at scale.",
                ],
                metric_value=None,
                metric_label=None,
            )
        )
    return findings


@rule
def rule_pgbouncer_pool_exhaustion(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 21: PgBouncer pool exhaustion detected."""
    findings = []
    pgb = result.pgbouncer_stats

    if pgb is None:
        return findings

    pool_error_count = len(pgb.pool_errors)
    if pool_error_count > 10:
        findings.append(
            RCAFinding(
                rule_id="PGBOUNCER_POOL_EXHAUSTION",
                severity=Severity.CRITICAL,
                title="PgBouncer pool exhaustion detected",
                description=(
                    f"{pool_error_count} PgBouncer pool errors detected. "
                    "Clients are being rejected because all connection pool slots are in use. "
                    "This causes application errors and request failures."
                ),
                evidence=[
                    f"Pool errors: {pool_error_count}",
                    *[e[:150] for e in pgb.pool_errors[:3]],
                ],
                recommendations=[
                    "PgBouncer pool exhaustion detected — increase pool_size or max_client_conn.",
                    "Increase default_pool_size in pgbouncer.ini (current is likely too small).",
                    "Increase max_client_conn to allow more clients to queue.",
                    "Switch to transaction pooling mode if using session mode: pool_mode = transaction",
                    "Add more PgBouncer instances behind a load balancer for horizontal scaling.",
                    "Investigate which databases/users are consuming the most pool slots.",
                ],
                metric_value=float(pool_error_count),
                metric_label="PgBouncer pool errors",
            )
        )
    return findings


@rule
def rule_cancelled_query_storm(result: AnalysisResult) -> List[RCAFinding]:
    """Rule 22: Query cancellation storm (>20 cancelled queries)."""
    findings = []
    cancelled = result.cancelled_queries

    cfg = get_rca_config()
    if len(cancelled) > cfg.cancelled_query_storm:
        # Check for short window (all within 5 minutes)
        timestamps = []
        for c in cancelled:
            ts = c.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    try:
                        from datetime import datetime
                        ts = datetime.fromisoformat(ts)
                        timestamps.append(ts)
                    except Exception:
                        pass
                else:
                    timestamps.append(ts)

        window_label = ""
        if len(timestamps) >= 2:
            span = (max(timestamps) - min(timestamps)).total_seconds()
            window_label = f" within {span / 60:.1f} minutes"

        findings.append(
            RCAFinding(
                rule_id="CANCELLED_QUERY_STORM",
                severity=Severity.HIGH,
                title="Query cancellation storm detected",
                description=(
                    f"{len(cancelled)} query cancellations detected{window_label}. "
                    "Mass query cancellations indicate statement_timeout is too low, "
                    "or client disconnects are triggering cascading cancellations across dependent queries."
                ),
                evidence=[
                    f"Total cancelled queries: {len(cancelled)}",
                    f"Window: {window_label.strip() if window_label else 'unknown'}",
                ],
                recommendations=[
                    "Query cancellation storm — likely statement_timeout too low or client "
                    "disconnects causing cascading cancellations.",
                    "Review statement_timeout setting: SHOW statement_timeout;",
                    "Set lock_timeout separately from statement_timeout for more control.",
                    "Investigate client-side timeout settings and connection stability.",
                    "Check for long-running transactions that trigger dependent cancellations.",
                    "Enable log_min_error_statement = error to capture cancelled query text.",
                ],
                metric_value=float(len(cancelled)),
                metric_label="cancelled queries",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# AI-enhanced RCA functions
# ---------------------------------------------------------------------------

async def ai_analyze_slow_queries(
    slow_queries: List[SlowQuery],
    llm_provider,
    top_n: int = 5,
) -> List[Dict[str, Any]]:
    """
    For the top N slowest queries, send each to the LLM and ask:
    1. What is this query likely doing?
    2. What indexes might help?
    3. What PostgreSQL config changes would reduce its impact?
    4. Is there a rewrite suggestion?

    Returns list of {normalized_query, ai_suggestions, index_recommendations, rewrite_suggestion}
    """
    from .llm import SLOW_QUERY_ANALYSIS_PROMPT

    results = []
    top_queries = sorted(slow_queries, key=lambda q: q.avg_duration_ms, reverse=True)[:top_n]

    for sq in top_queries:
        prompt = SLOW_QUERY_ANALYSIS_PROMPT.format(
            query=sq.normalized_query,
            count=sq.count,
            avg_ms=round(sq.avg_duration_ms, 1),
            p95_ms=round(sq.p95_duration_ms, 1),
            total_ms=round(sq.total_duration_ms, 1),
        )

        try:
            raw_analysis = await llm_provider.analyze(prompt)
        except Exception as exc:
            raw_analysis = f"LLM analysis failed: {exc}"

        # Extract structured sections from the response
        index_recs = _extract_section(raw_analysis, "Index recommendation", "CREATE INDEX")
        rewrite = _extract_section(raw_analysis, "Query rewrite", "SELECT")

        results.append({
            "normalized_query": sq.normalized_query,
            "avg_duration_ms": sq.avg_duration_ms,
            "count": sq.count,
            "ai_suggestions": raw_analysis,
            "index_recommendations": index_recs,
            "rewrite_suggestion": rewrite,
        })

    return results


async def ai_analyze_explain_plan(
    plan: AutoExplainPlan,
    llm_provider,
) -> str:
    """
    Send an auto_explain plan to the LLM.
    Ask: identify the most expensive node, suggest index improvements,
    identify any sequential scans that should be index scans,
    estimate the impact of proposed changes.

    Returns the AI analysis as a string.
    """
    from .llm import EXPLAIN_PLAN_PROMPT

    prompt = EXPLAIN_PLAN_PROMPT.format(
        query=plan.query[:500] if plan.query else "(unknown)",
        duration_ms=round(plan.duration_ms, 1),
        plan_text=plan.plan_text[:4000] if plan.plan_text else "(no plan)",
    )

    try:
        analysis = await llm_provider.analyze(prompt)
        return analysis
    except Exception as exc:
        return f"LLM explain plan analysis failed: {exc}"


async def ai_generate_postgresql_config(
    analysis_result: AnalysisResult,
    llm_provider,
) -> str:
    """
    Based on the full analysis, generate a complete suggested postgresql.conf
    section with specific parameter values and explanations.
    Focus on: shared_buffers, work_mem, maintenance_work_mem, max_connections,
    checkpoint_completion_target, max_wal_size, wal_buffers, autovacuum settings.

    Returns a formatted postgresql.conf snippet with comments.
    """
    from .llm import CONFIG_GENERATION_PROMPT, build_analysis_context

    summary = build_analysis_context(analysis_result, max_tokens=4000)

    prompt = CONFIG_GENERATION_PROMPT.format(analysis_summary=summary)

    try:
        config_text = await llm_provider.analyze(prompt)
        return config_text
    except Exception as exc:
        return f"LLM config generation failed: {exc}"


async def ai_generate_index_recommendations(
    slow_queries: List[SlowQuery],
    llm_provider,
) -> List[Dict[str, Any]]:
    """
    Analyze top slow queries and generate concrete CREATE INDEX statements.

    Returns list of {query, create_index_sql, rationale, estimated_speedup}
    """
    from .llm import INDEX_RECOMMENDATION_PROMPT

    top_queries = sorted(slow_queries, key=lambda q: q.total_duration_ms, reverse=True)[:10]

    queries_text = "\n\n".join(
        f"Query {i+1} (avg={sq.avg_duration_ms:.0f}ms, count={sq.count}):\n{sq.normalized_query}"
        for i, sq in enumerate(top_queries)
    )

    context = ""
    if top_queries:
        dbs = set()
        for sq in top_queries:
            dbs.update(sq.databases)
        context = f"Databases: {', '.join(sorted(dbs))}"

    prompt = INDEX_RECOMMENDATION_PROMPT.format(
        queries=queries_text,
        context=context,
    )

    try:
        raw_response = await llm_provider.analyze(prompt)
    except Exception as exc:
        return [{"error": f"LLM index recommendation failed: {exc}"}]

    # Parse the response into structured recommendations
    recommendations = _parse_index_recommendations(raw_response, top_queries)
    return recommendations


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_section(text: str, *section_hints: str) -> str:
    """Extract a specific section from LLM output using heuristics."""
    if not text:
        return ""
    lines = text.split("\n")
    for hint in section_hints:
        hint_lower = hint.lower()
        capturing = False
        section_lines = []
        for line in lines:
            if hint_lower in line.lower() and ("**" in line or "#" in line or line.strip().endswith(":")):
                capturing = True
                continue
            if capturing:
                # Stop at the next section header
                if line.strip().startswith("**") or line.strip().startswith("#"):
                    break
                if line.strip():
                    section_lines.append(line)
        if section_lines:
            return "\n".join(section_lines).strip()
    # Fallback: look for CREATE INDEX or relevant SQL
    for hint in section_hints:
        if hint.upper() in text.upper():
            idx = text.upper().index(hint.upper())
            return text[idx:idx + 500].strip()
    return ""


def _parse_index_recommendations(text: str, queries: List[SlowQuery]) -> List[Dict[str, Any]]:
    """Parse LLM index recommendation output into structured dicts."""
    recommendations = []

    # Find all CREATE INDEX statements
    create_index_pattern = re.compile(
        r"CREATE\s+INDEX(?:\s+CONCURRENTLY)?\s+\w+\s+ON\s+\w+.*?(?:;|$)",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = list(create_index_pattern.finditer(text))

    if not matches:
        # Return the whole response as one recommendation
        return [{
            "query": queries[0].normalized_query[:200] if queries else "",
            "create_index_sql": "",
            "rationale": text[:1000],
            "estimated_speedup": "unknown",
        }]

    for i, match in enumerate(matches):
        sql = match.group(0).strip()
        # Extract surrounding context for rationale
        start = max(0, match.start() - 300)
        end = min(len(text), match.end() + 300)
        context_text = text[start:end]

        # Try to find speedup estimate
        speedup_match = re.search(r"(\d+[x×%]|\d+[-–]\d+[x×%]?)\s*(?:speedup|faster|improvement)", context_text, re.IGNORECASE)
        speedup = speedup_match.group(0) if speedup_match else "estimated 2-10x"

        # Associate with query by index
        associated_query = queries[min(i, len(queries) - 1)].normalized_query[:200] if queries else ""

        recommendations.append({
            "query": associated_query,
            "create_index_sql": sql,
            "rationale": context_text.replace(sql, "").strip()[:400],
            "estimated_speedup": speedup,
        })

    return recommendations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_rca(result: AnalysisResult, config: Optional[RCAConfig] = None) -> List[RCAFinding]:
    """Run all registered RCA rules and return sorted findings.

    Args:
        result: The analysis result to inspect.
        config: Optional threshold overrides. Defaults to ``RCAConfig()`` (built-in values).
                Load from ``~/.pgloglens.yaml`` under ``rca_thresholds`` and pass here.
    """
    global _rca_config
    _rca_config = config if config is not None else RCAConfig()

    all_findings: List[RCAFinding] = []
    for rule_fn in _REGISTERED_RULES:
        try:
            findings = rule_fn(result)
            all_findings.extend(findings)
        except Exception:
            # Rules must not crash the analysis
            pass

    # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # Attach findings to the result
    result.rca_findings = all_findings

    # Build plain-text recommendations list
    result.recommendations = []
    for finding in all_findings:
        for rec in finding.recommendations:
            if rec not in result.recommendations:
                result.recommendations.append(rec)

    return all_findings
