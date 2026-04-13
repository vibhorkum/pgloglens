"""Multi-format PostgreSQL log file parser.

Supports:
  - stderr (default): YYYY-MM-DD HH:MM:SS.mmm TZ [PID] user@database LEVEL: message
  - syslog: month day time host postgres[PID]: [line-N] user=X,db=Y LEVEL: message
  - syslog2: <PRI>Mmm DD HH:MM:SS hostname postgres[PID]: [line-N] message
  - csvlog: CSV with all PostgreSQL CSV log columns
  - jsonlog: PostgreSQL 15+ JSON logging format
  - pgbouncer: PgBouncer log format
  - rds: AWS RDS/CloudWatch stderr variant
  - logplex: Heroku logplex format
  - redshift: AWS Redshift log format
  - cloudsql: GCP CloudSQL JSON-encapsulated format

The parser uses a streaming / generator approach so large files are never
fully loaded into memory.  Gzip-compressed files (.gz) are handled
transparently, as well as bz2, lz4, zstd, xz, and zip.
"""

from __future__ import annotations

import bz2
import csv
import gzip
import io
import json
import lzma
import re
import subprocess
import urllib.request
import zipfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, Iterator, List, Optional, Tuple

from dateutil import parser as dateutil_parser

from .models import LogEntry, LogLevel

# ---------------------------------------------------------------------------
# Log format detection
# ---------------------------------------------------------------------------

_STDERR_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s*(?:UTC|[A-Z]{2,5}[+-]\d{0,2})?)"
    r"\s+\[(\d+)\]"
)
_SYSLOG_RE = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)
_SYSLOG2_RE = re.compile(
    r"^<\d+>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)
_CSVLOG_RE = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+.*,"')
_JSONLOG_RE = re.compile(r"^\s*\{.*\"timestamp\"")
# PgBouncer lines have format: TIMESTAMP UTC [PID] LOG message (NO colon after level)
# PostgreSQL stderr has: TIMESTAMP UTC [PID] user@db LEVEL: message (colon after level)
_PGBOUNCER_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+UTC\s+\[\d+\]\s+(?:LOG|WARNING|ERROR|NOTICE|FATAL)(?!:)\s"
)
_RDS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?:[\d.]+\(\d+\):\w+@\w+:\[\d+\]:"
)
_LOGPLEX_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}\s+app\[postgres"
)
_REDSHIFT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+\[\d+\]\s+(?:LOG|ERROR|WARNING|FATAL|INFO|DEBUG)"
)
_CLOUDSQL_JSON_RE = re.compile(r"^\s*\{.*(?:textPayload|cloudsql_database)")


class LogFormat(str, Enum):
    STDERR = "stderr"
    SYSLOG = "syslog"
    SYSLOG2 = "syslog2"
    CSVLOG = "csvlog"
    JSONLOG = "jsonlog"
    PGBOUNCER = "pgbouncer"
    RDS = "rds"
    LOGPLEX = "logplex"
    REDSHIFT = "redshift"
    CLOUDSQL = "cloudsql"
    UNKNOWN = "unknown"


def detect_format(sample_lines: List[str]) -> LogFormat:
    """Detect PostgreSQL log format from up to 20 sample lines."""
    for line in sample_lines[:20]:
        line = line.strip()
        if not line:
            continue
        # JSON-based formats first
        if _JSONLOG_RE.match(line):
            return LogFormat.JSONLOG
        if _CLOUDSQL_JSON_RE.match(line):
            return LogFormat.CLOUDSQL
        if _CSVLOG_RE.match(line):
            return LogFormat.CSVLOG
        # RDS must be checked before STDERR (more specific prefix with user@db:[pid]:)
        if _RDS_RE.match(line):
            return LogFormat.RDS
        # STDERR before PGBOUNCER — PostgreSQL stderr has 'LEVEL:' (with colon)
        if _STDERR_RE.match(line) and not _PGBOUNCER_RE.match(line):
            return LogFormat.STDERR
        if _PGBOUNCER_RE.match(line):
            return LogFormat.PGBOUNCER
        if _LOGPLEX_RE.match(line):
            return LogFormat.LOGPLEX
        if _REDSHIFT_RE.match(line):
            return LogFormat.REDSHIFT
        if _SYSLOG2_RE.match(line):
            return LogFormat.SYSLOG2
        if _SYSLOG_RE.match(line):
            return LogFormat.SYSLOG
        if _STDERR_RE.match(line):
            return LogFormat.STDERR
    return LogFormat.STDERR  # default


# ---------------------------------------------------------------------------
# Regex patterns for specific message types
# ---------------------------------------------------------------------------

# Duration line: "duration: 1234.567 ms"
_DURATION_RE = re.compile(r"duration:\s+([\d.]+)\s*ms", re.IGNORECASE)
# Duration + statement: "duration: X ms  statement: SELECT ..."
_DURATION_STMT_RE = re.compile(
    r"duration:\s+([\d.]+)\s*ms\s+(?:statement|execute[^:]*|parse[^:]*):\s+(.*?)(?:\s*$)", re.IGNORECASE
)
# SQLSTATE error code
_SQLSTATE_RE = re.compile(r"SQLSTATE[:\s]+([A-Z0-9]{5})", re.IGNORECASE)
_ERROR_CODE_RE = re.compile(r"\(([A-Z0-9]{5})\)")

# Connection established
_CONN_RE = re.compile(
    r"connection (?:received|authorized):\s+host=(\S+).*?(?:user=(\S+))?.*?(?:database=(\S+))?",
    re.IGNORECASE,
)
_CONN_CLOSE_RE = re.compile(r"disconnection:\s+session time:", re.IGNORECASE)

# Lock waits
_LOCK_WAIT_RE = re.compile(
    r"process\s+(\d+)\s+(?:still\s+)?waiting for\s+(\S+Lock)\s+on\s+(.+?);\s+blocking process(?:es)?:\s+([\d, ]+)",
    re.IGNORECASE,
)
_LOCK_ACQUIRED_RE = re.compile(
    r"process\s+(\d+)\s+acquired\s+(\S+)\s+on\s+(.+?)\s+after\s+([\d.]+)\s*ms",
    re.IGNORECASE,
)
_DEADLOCK_RE = re.compile(r"deadlock detected", re.IGNORECASE)

# Checkpoint
_CHECKPOINT_RE = re.compile(
    r"checkpoint complete:\s+wrote\s+(\d+)\s+buffers\s+\(([\d.]+)%\);\s+"
    r"(\d+)\s+WAL file\(s\) added,\s+(\d+)\s+removed,\s+(\d+)\s+recycled;\s+"
    r"write=([\d.]+)\s*s,\s+sync=([\d.]+)\s*s,\s+total=([\d.]+)\s*s",
    re.IGNORECASE,
)
_CHECKPOINT_START_RE = re.compile(
    r"(checkpoint|restartpoint)\s+(?:starting|complete)", re.IGNORECASE
)
_CHECKPOINT_WARNING_RE = re.compile(
    r"checkpoint\s+(?:request\s+)?occurring\s+too\s+frequently", re.IGNORECASE
)

# Autovacuum
_AUTOVACUUM_RE = re.compile(
    r"automatic\s+(?:vacuum|analyze)\s+of\s+table\s+"
    r'"?([^"]+)"?\s*:\s+'
    r"(?:index scans:\s*(\d+),?\s*)?"
    r"(?:pages:\s*(\d+)\s+removed,\s*(\d+)\s+remain.*?)?"
    r"(?:tuples:\s*([\d.]+)\s+removed,\s*([\d.]+)\s+remain)?",
    re.IGNORECASE | re.DOTALL,
)
_AUTOVACUUM_DURATION_RE = re.compile(
    r"automatic\s+(vacuum|analyze)\s+of\s+table\s+(.+?):\s+.*?"
    r"(?:elapsed\s+time|duration):\s+([\d.]+)\s*s",
    re.IGNORECASE | re.DOTALL,
)

# Temp files
_TEMPFILE_RE = re.compile(
    r"temporary\s+file:\s+path\s+\"(.+?)\",\s+size\s+(\d+)", re.IGNORECASE
)

# Replication lag
_REPL_LAG_RE = re.compile(
    r"replication\s+slot\s+\S+.*?lag\s*[=:]\s*([\d.]+)\s*(bytes?|MB|GB)?",
    re.IGNORECASE,
)
_WAL_RECEIVER_RE = re.compile(
    r"started\s+streaming\s+WAL|replication\s+terminated|standby\s+message\s+timeout",
    re.IGNORECASE,
)

# Auth failures
_AUTH_FAIL_RE = re.compile(
    r"(?:password authentication failed|authentication failed|no pg_hba\.conf entry|"
    r"Ident authentication failed|peer authentication failed|"
    r"SCRAM authentication failed|md5 authentication failed)",
    re.IGNORECASE,
)

# OOM
_OOM_RE = re.compile(r"out of memory|memory exhausted|could not resize shared memory", re.IGNORECASE)

# Disk full
_DISK_FULL_RE = re.compile(
    r"could not write to file|no space left on device|disk full|ENOSPC", re.IGNORECASE
)

# Stderr-format header
# Handles:
#   [PID] user@database LEVEL: msg
#   [PID] user LEVEL: msg  (no database, e.g. autovacuum)
#   [PID] LEVEL: msg       (no user/database)
_STDERR_HEADER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(?:UTC|[A-Z]{2,5}[+-]\d{0,2}|[A-Z]{3,5})?\s+"
    r"\[(\d+)\]\s+"
    r"(?:([^@\s]+)@([^\s]+)\s+|([a-zA-Z_][a-zA-Z0-9_]*)\s+)?"
    r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG|DETAIL|HINT|CONTEXT|STATEMENT):\s*(.*)"
)

# Syslog-format header
# Syslog format comes in two sub-variants:
#
# VARIANT A (simple): the postgres log_line_prefix fields appear directly after
# the syslog header and optional [line-N] marker:
#   Apr 10 18:11:23 host postgres[PID]: [N] user=X,db=Y LOG:  msg
#
# VARIANT B (double-header / EDB): PostgreSQL's own prefix is embedded INSIDE
# the syslog message field, repeating timestamp+pid+line, then key=value fields:
#   Apr 10 18:11:23 host postgres[PID]: [N] YYYY-MM-DD HH:MM:SS TZ [PID]: [L-1] user=X,db=Y,sessid=S LOG: msg
#
# We match variant B first (more specific), then fall through to variant A.

# Variant B: syslog wrapping a full PG prefix  (EDB / EnterpriseDB style)
_SYSLOG_EDB_RE = re.compile(
    r"^(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(?:postgres|postgresql|edb|postmaster)\[\d+\]:\s+"
    r"\[\d+\]\s+"                                          # syslog sequence [N]
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+UTC|\s+[A-Z]{2,5})?)\s+"  # PG ts
    r"\[(\d+)\]:\s+"                                       # [PID]:
    r"\[[\d]+-\d+\]\s+"                                    # [L-1]
    r"user=([^,]*),db=([^,]*),(?:app=([^,]*),)?"          # user=,db=,app= (may be empty)
    r"(?:[^\s]+\s+)?"                                      # sessid= or other key=value (skip)
    r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG):\s+(.*)",
    re.DOTALL,
)

# Variant A (classic syslog — simple prefix after syslog header)
_SYSLOG_HEADER_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(?:postgres|postgresql|edb|postmaster)\[(\d+)\]:\s+"
    r"(?:\[[\d-]+\]\s+)?"
    r"(?:user=([^,]*),db=([^,]*),(?:app=([^,]*),)?(?:client=([^,\s]*),?)?\s*)?"
    r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG):\s*(.*)",
    re.DOTALL,
)

# Syslog2 header: <PRI>Mmm DD HH:MM:SS hostname postgres[PID]: [line-N] message
_SYSLOG2_HEADER_RE = re.compile(
    r"^<\d+>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(?:postgres|postgresql)\[(\d+)\]:\s+"
    r"(?:\[[\d-]+\]\s+)?"
    r"(?:user=([^,]+),db=([^,]+),(?:app=([^,]+),)?(?:client=([^,]+),)?\s*)?"
    r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG):\s*(.*)"
)

# RDS format: 2024-01-15 14:23:01 UTC:192.168.1.1(54321):myuser@mydb:[1234]:LOG: msg
_RDS_HEADER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s+UTC)?"
    r":([\d.]+)\((\d+)\):(\w+)@(\w+):\[(\d+)\]:"
    r"(LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG):\s*(.*)"
)

# Logplex / Heroku: 2024-01-15T14:23:01+00:00 app[postgres.XXXXXX]: [1-1] user=app,db=app,...
_LOGPLEX_HEADER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2})\s+"
    r"app\[postgres[^\]]*\]:\s+"
    r"(?:\[[\d-]+\]\s+)?"
    r"(?:user=([^,]+),db=([^,]+),(?:app=([^,]+),)?(?:client=([^,]*))?[,\s]*)?"
    r"(LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG):\s*(.*)"
)

# Redshift: 2024-01-15 14:23:01.234 [12345] LOG: msg
_REDSHIFT_HEADER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\[(\d+)\]\s+"
    r"(LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG):\s*(.*)"
)

# PgBouncer: 2024-01-15 14:23:01.234 UTC [1234] LOG severity message
_PGBOUNCER_HEADER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+UTC\s+"
    r"\[(\d+)\]\s+"
    r"(LOG|WARNING|ERROR|NOTICE|FATAL|DEBUG)\s+(.*)"
)

# CSV log columns (PostgreSQL CSV log format has 23+ columns)
_CSV_COLUMNS = [
    "log_time", "user_name", "database_name", "process_id", "connection_from",
    "session_id", "session_line_num", "command_tag", "session_start_time",
    "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code",
    "message", "detail", "hint", "internal_query", "internal_query_pos",
    "context", "query", "query_pos", "location", "application_name",
    "backend_type",  # PG13+
]

# ---------------------------------------------------------------------------
# v2 new regex patterns
# ---------------------------------------------------------------------------

# PgBouncer patterns
_PGBOUNCER_CONN_RE = re.compile(
    r'(login attempt|client login|client disconnect|server connect|server disconnect).*?db=(\S+).*?user=(\S+)',
    re.IGNORECASE,
)
_PGBOUNCER_QUERY_RE = re.compile(r'query=(.*?)(?:\s+ms=(\d+))?$', re.IGNORECASE)
_PGBOUNCER_ERROR_RE = re.compile(r'(ERROR|WARNING|FATAL):\s*(.*)', re.IGNORECASE)

# Prepare/Bind/Execute
_PARSE_PHASE_RE = re.compile(r'parse\s+(\S+):\s+(.+?)(?:\s*$)', re.IGNORECASE)
_BIND_PHASE_RE = re.compile(r'bind\s+(\S+):\s+(.+?)(?:\s*$)', re.IGNORECASE)
_EXECUTE_PHASE_RE = re.compile(r'execute\s+(\S+):\s+(.+?)(?:\s*$)', re.IGNORECASE)
_PARSE_DURATION_RE = re.compile(r'duration:\s*([\d.]+)\s*ms\s+parse\s+', re.IGNORECASE)
_BIND_DURATION_RE = re.compile(r'duration:\s*([\d.]+)\s*ms\s+bind\s+', re.IGNORECASE)
_EXECUTE_DURATION_RE = re.compile(r'duration:\s*([\d.]+)\s*ms\s+(?:statement|execute)', re.IGNORECASE)

# auto_explain patterns
_AUTO_EXPLAIN_START_RE = re.compile(r'Query Text:\s*(.*)', re.IGNORECASE)
_AUTO_EXPLAIN_PLAN_RE = re.compile(
    r'(?:Seq Scan|Index Scan|Hash Join|Nested Loop|Merge Join|Bitmap|Sort|Aggregate|Limit|Result)',
    re.IGNORECASE,
)

# Query type detection
_SELECT_RE = re.compile(r'^\s*(?:WITH\s+.+?\s+)?SELECT\b', re.IGNORECASE | re.DOTALL)
_INSERT_RE = re.compile(r'^\s*INSERT\s+INTO\b', re.IGNORECASE)
_UPDATE_RE = re.compile(r'^\s*UPDATE\s+\b', re.IGNORECASE)
_DELETE_RE = re.compile(r'^\s*DELETE\s+FROM\b', re.IGNORECASE)
_COPY_RE = re.compile(r'^\s*COPY\b', re.IGNORECASE)
_DDL_RE = re.compile(r'^\s*(?:CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COMMENT)\b', re.IGNORECASE)
_VACUUM_RE = re.compile(r'^\s*VACUUM\b', re.IGNORECASE)
_CANCEL_RE = re.compile(r'canceling statement due to|ERROR.*canceling', re.IGNORECASE)

# Extended autovacuum metrics (PG11.4+)
_AUTOVAC_BUFFERS_RE = re.compile(
    r'buffer usage:\s+(\d+)\s+hits,\s+(\d+)\s+misses,\s+(\d+)\s+dirtied', re.IGNORECASE
)
_AUTOVAC_WAL_RE = re.compile(
    r'WAL usage:\s+(\d+)\s+records,\s+(\d+)\s+full page images?,\s+(\d+)\s+bytes', re.IGNORECASE
)
_AUTOVAC_CPU_RE = re.compile(r'CPU:\s+user:\s+([\d.]+)s,\s+system:\s+([\d.]+)s', re.IGNORECASE)
_AUTOVAC_FROZEN_RE = re.compile(
    r'skipped\s+(\d+)\s+pages\s+due\s+to\s+pins.*?(\d+)\s+frozen', re.IGNORECASE
)

# Checkpoint distance/estimate (PG9.2+)
_CHECKPOINT_DISTANCE_RE = re.compile(r'distance=(\d+)\s+estimate=(\d+)', re.IGNORECASE)
# Checkpoint WAL files
_CHECKPOINT_WAL_RE = re.compile(
    r'(\d+)\s+WAL file\(s\)\s+added,\s+(\d+)\s+removed,\s+(\d+)\s+recycled', re.IGNORECASE
)
# Checkpoint cause (requested/timed/xlog)
_CHECKPOINT_CAUSE_RE = re.compile(r'checkpoint\s+starting:\s+(\w+)', re.IGNORECASE)

# Connection with session tracking for concurrent session measurement
_CONN_AUTH_RE = re.compile(
    r'connection\s+(?:received|authorized).*?(?:host=(\S+)|client=(\S+)).*?(?:user=(\S+))?.*?(?:database=(\S+))?',
    re.IGNORECASE,
)
_DISCONN_DURATION_RE = re.compile(
    r'disconnection.*?session\s+time:\s+([\d:]+)\s+user=(.*?)\s+database=(.*?)\s+host=(\S+)',
    re.IGNORECASE,
)

# Cancellation
_CANCELLATION_RE = re.compile(
    r'canceling\s+statement\s+due\s+to\s+(.*?)(?:\s*$)', re.IGNORECASE
)

# Anonymize patterns
_ANON_STR_RE = re.compile(r"'(?:[^'\\]|\\.)*'", re.DOTALL)
_ANON_NUM_RE = re.compile(r"(?<!\$)\b\d+(?:\.\d+)?\b")
_ANON_IN_RE = re.compile(r"\(\s*(\$\d+(?:\s*,\s*\$\d+)+)\s*\)", re.IGNORECASE)


def _safe_parse_dt(s: str) -> Optional[datetime]:
    """Parse a datetime string, returning None on failure."""
    if not s:
        return None
    try:
        return dateutil_parser.parse(s)
    except Exception:
        return None


def _map_level(s: str) -> LogLevel:
    s = s.upper().rstrip("0123456789")  # strip DEBUG1, DEBUG2, etc.
    try:
        return LogLevel(s)
    except ValueError:
        return LogLevel.LOG


# ---------------------------------------------------------------------------
# Per-format parsers
# ---------------------------------------------------------------------------

def _parse_stderr_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a single stderr-format log line."""
    m = _STDERR_HEADER_RE.match(line)
    if not m:
        return None
    # groups: ts_str, pid_str, user_with_db, database, user_only, level_str, message
    ts_str, pid_str, user_with_db, database, user_only, level_str, message = m.groups()
    user = user_with_db or user_only
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        user=user,
        database=database,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _decode_syslog_escapes(text: str) -> str:
    """Decode syslog octal escapes: #012 -> newline, #011 -> tab, etc.

    Only digits 0-7 are valid octal; sequences like #359 are NOT octal escapes
    and must be passed through unchanged to avoid ValueError.
    """
    import re as _re

    def _safe_octal(m: "re.Match") -> str:  # type: ignore[name-defined]
        digits = m.group(1)
        # Valid octal: every digit must be 0-7
        if all(c in '01234567' for c in digits):
            return chr(int(digits, 8))
        # Not a real octal escape — return the original token unchanged
        return m.group(0)

    return _re.sub(r'#(\d{3})', _safe_octal, text)


def _parse_syslog_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a syslog-format log line (variant A simple or variant B EDB double-header)."""
    session_id = None

    # Try variant B first: EDB / double-header (syslog outer + full PG prefix inside)
    m = _SYSLOG_EDB_RE.match(line)
    if m:
        ts_str, pid_str, user, database, app, level_str, message = m.groups()
        # Extract sessid from the raw line (between last key=value before the level)
        sessid_m = re.search(r'sessid=([^,\s]+)', line)
        if sessid_m:
            session_id = sessid_m.group(1)
        # Normalize empty string fields to None
        user = user.strip() or None
        database = database.strip() or None
        app = app.strip() if app else None
        message = _decode_syslog_escapes(message.strip())
        entry = LogEntry(
            timestamp=_safe_parse_dt(ts_str.strip()),
            pid=int(pid_str) if pid_str else None,
            user=user,
            database=database,
            application_name=app,
            session_id=session_id,
            log_level=_map_level(level_str),
            message=message,
            raw_line=line,
            line_number=line_number,
        )
        _enrich_entry(entry)
        return entry

    # Fall through to variant A (classic syslog)
    m = _SYSLOG_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, pid_str, user, database, app, client, level_str, message = m.groups()
    user = user.strip() if user else None
    database = database.strip() if database else None
    message = _decode_syslog_escapes(message.strip())
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        user=user or None,
        database=database or None,
        application_name=app,
        remote_host=client,
        log_level=_map_level(level_str),
        message=message,
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_syslog2_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a syslog2 (<PRI>...) format log line."""
    m = _SYSLOG2_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, pid_str, user, database, app, client, level_str, message = m.groups()
    user = user.strip() if user else None
    database = database.strip() if database else None
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        user=user or None,
        database=database or None,
        application_name=app,
        remote_host=client,
        log_level=_map_level(level_str),
        message=_decode_syslog_escapes(message.strip()),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_rds_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse an AWS RDS log line."""
    m = _RDS_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, host, port, user, database, pid_str, level_str, message = m.groups()
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        user=user,
        database=database,
        remote_host=f"{host}:{port}" if host else None,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_logplex_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a Heroku logplex log line."""
    m = _LOGPLEX_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, user, database, app, client, level_str, message = m.groups()
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        user=user,
        database=database,
        application_name=app,
        remote_host=client if client and client.strip() else None,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_redshift_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse an AWS Redshift log line."""
    m = _REDSHIFT_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, pid_str, level_str, message = m.groups()
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_pgbouncer_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a PgBouncer log line."""
    m = _PGBOUNCER_HEADER_RE.match(line)
    if not m:
        return None
    ts_str, pid_str, level_str, message = m.groups()
    entry = LogEntry(
        timestamp=_safe_parse_dt(ts_str),
        pid=int(pid_str) if pid_str else None,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    # Try to extract db/user from pgbouncer message
    cm = _PGBOUNCER_CONN_RE.search(message)
    if cm:
        entry.database = cm.group(2)
        entry.user = cm.group(3)
    return entry


def _parse_cloudsql_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a GCP CloudSQL JSON-encapsulated log line."""
    try:
        obj = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    # Try to get the inner text payload
    text_payload = obj.get("textPayload", "")
    if not text_payload:
        # Try jsonPayload
        jp = obj.get("jsonPayload", {})
        text_payload = jp.get("message", "") if isinstance(jp, dict) else ""

    if not text_payload:
        return None

    # Now parse the inner text as a stderr line
    inner = _parse_stderr_line(text_payload, line_number)
    if inner:
        inner.raw_line = line.strip()
        return inner

    # Fallback: create a basic entry from the JSON wrapper
    resource = obj.get("resource", {})
    labels = resource.get("labels", {}) if isinstance(resource, dict) else {}
    entry = LogEntry(
        timestamp=_safe_parse_dt(obj.get("timestamp", "")),
        database=labels.get("database_id", "").split(":")[-1] or None,
        message=text_payload,
        raw_line=line.strip(),
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_csv_row(row: List[str], line_number: int) -> Optional[LogEntry]:
    """Parse a CSV log row."""
    if len(row) < 14:
        return None
    # Map by position
    col = dict(zip(_CSV_COLUMNS, row + [""] * max(0, len(_CSV_COLUMNS) - len(row))))
    level_str = col.get("error_severity", "LOG")
    message = col.get("message", "")
    entry = LogEntry(
        timestamp=_safe_parse_dt(col.get("log_time", "")),
        pid=int(col["process_id"]) if col.get("process_id", "").isdigit() else None,
        session_id=col.get("session_id"),
        user=col.get("user_name") or None,
        database=col.get("database_name") or None,
        application_name=col.get("application_name") or None,
        remote_host=col.get("connection_from") or None,
        error_code=col.get("sql_state_code") or None,
        log_level=_map_level(level_str),
        message=message,
        query=col.get("query") or None,
        raw_line=",".join(row),
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _parse_json_line(line: str, line_number: int) -> Optional[LogEntry]:
    """Parse a JSON log line (PostgreSQL 15+)."""
    try:
        obj = json.loads(line.strip())
    except json.JSONDecodeError:
        return None
    level_str = obj.get("error_severity", obj.get("level", "LOG"))
    message = obj.get("message", "")
    pid = obj.get("process_id") or obj.get("pid")
    entry = LogEntry(
        timestamp=_safe_parse_dt(obj.get("timestamp", "")),
        pid=int(pid) if pid else None,
        session_id=obj.get("session_id"),
        user=obj.get("user") or obj.get("user_name") or None,
        database=obj.get("dbname") or obj.get("database_name") or None,
        application_name=obj.get("application_name") or None,
        remote_host=obj.get("remote_host") or obj.get("connection_from") or None,
        error_code=obj.get("sql_state_code") or None,
        log_level=_map_level(level_str),
        message=message,
        query=obj.get("query") or None,
        raw_line=line.strip(),
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


def _enrich_entry(entry: LogEntry) -> None:
    """Enrich a log entry with derived fields (duration, query, error_code, query_type, phase)."""
    msg = entry.message

    # Duration
    dm = _DURATION_STMT_RE.search(msg)
    if dm:
        entry.duration_ms = float(dm.group(1))
        if not entry.query:
            entry.query = dm.group(2).strip()
    else:
        dm2 = _DURATION_RE.search(msg)
        if dm2:
            entry.duration_ms = float(dm2.group(1))

    # SQLSTATE
    if not entry.error_code:
        sm = _SQLSTATE_RE.search(msg) or _ERROR_CODE_RE.search(msg)
        if sm:
            entry.error_code = sm.group(1)

    # Parse/bind/execute phase detection
    if _PARSE_DURATION_RE.search(msg):
        entry.phase = "parse"
    elif _BIND_DURATION_RE.search(msg):
        entry.phase = "bind"
    elif _EXECUTE_DURATION_RE.search(msg):
        entry.phase = "execute"
    elif _PARSE_PHASE_RE.search(msg):
        entry.phase = "parse"
    elif _BIND_PHASE_RE.search(msg):
        entry.phase = "bind"
    elif _EXECUTE_PHASE_RE.search(msg):
        entry.phase = "execute"

    # Query type detection
    query_text = entry.query or msg
    if query_text:
        entry.query_type = detect_query_type(query_text)

    # Extended autovacuum metrics — applied here for in-line enrichment
    # (full extraction happens in extract_autovacuum)


# ---------------------------------------------------------------------------
# Is-continuation line detection
# ---------------------------------------------------------------------------

_CONTINUATION_RE = re.compile(
    r"^\t|^DETAIL:|^HINT:|^CONTEXT:|^QUERY:|^STATEMENT:|^LOCATION:|^WHERE:"
)


def _is_continuation(line: str, log_format: LogFormat) -> bool:
    """Return True if the line is a continuation of the previous log entry."""
    if log_format == LogFormat.CSVLOG:
        return False  # CSV handles multi-line via quoting
    if log_format == LogFormat.JSONLOG:
        return False
    if log_format == LogFormat.CLOUDSQL:
        return False
    stripped = line.rstrip("\n\r")
    if not stripped:
        return False
    # Lines starting with TAB or known PostgreSQL detail keywords are continuations
    if _CONTINUATION_RE.match(stripped):
        return True
    return False


# ---------------------------------------------------------------------------
# Utility / extractor functions
# ---------------------------------------------------------------------------

def detect_query_type(query_text: str) -> str:
    """Return 'select'/'insert'/'update'/'delete'/'copy'/'ddl'/'vacuum'/'other'."""
    t = query_text.strip()
    if _SELECT_RE.match(t):
        return "select"
    if _INSERT_RE.match(t):
        return "insert"
    if _UPDATE_RE.match(t):
        return "update"
    if _DELETE_RE.match(t):
        return "delete"
    if _COPY_RE.match(t):
        return "copy"
    if _DDL_RE.match(t):
        return "ddl"
    if _VACUUM_RE.match(t):
        return "vacuum"
    return "other"


def is_cancellation(entry: LogEntry) -> bool:
    """Return True if this entry represents a cancelled query."""
    return bool(_CANCELLATION_RE.search(entry.message) or _CANCEL_RE.search(entry.message))


def is_prepare_phase(entry: LogEntry) -> bool:
    """Return True if this entry is a parse/prepare phase log line."""
    return entry.phase == "parse" or bool(_PARSE_PHASE_RE.search(entry.message))


def is_bind_phase(entry: LogEntry) -> bool:
    """Return True if this entry is a bind phase log line."""
    return entry.phase == "bind" or bool(_BIND_PHASE_RE.search(entry.message))


def is_execute_phase(entry: LogEntry) -> bool:
    """Return True if this entry is an execute phase log line."""
    return entry.phase == "execute" or bool(_EXECUTE_PHASE_RE.search(entry.message))


def extract_pgbouncer_event(entry: LogEntry) -> Dict[str, Any]:
    """Return PgBouncer-specific data dict from a log entry."""
    result: Dict[str, Any] = {
        "event_type": None,
        "database": entry.database,
        "user": entry.user,
        "query": None,
        "duration_ms": entry.duration_ms,
        "error": None,
        "bytes_in": None,
        "bytes_out": None,
    }
    msg = entry.message

    cm = _PGBOUNCER_CONN_RE.search(msg)
    if cm:
        result["event_type"] = cm.group(1).lower().replace(" ", "_")
        result["database"] = cm.group(2)
        result["user"] = cm.group(3)

    qm = _PGBOUNCER_QUERY_RE.search(msg)
    if qm:
        result["query"] = qm.group(1).strip()
        if qm.group(2):
            result["duration_ms"] = float(qm.group(2))

    em = _PGBOUNCER_ERROR_RE.search(msg)
    if em:
        result["event_type"] = em.group(1).lower()
        result["error"] = em.group(2).strip()

    # bytes_in / bytes_out if present in message
    bm = re.search(r'bytes_in=(\d+)', msg)
    if bm:
        result["bytes_in"] = int(bm.group(1))
    bom = re.search(r'bytes_out=(\d+)', msg)
    if bom:
        result["bytes_out"] = int(bom.group(1))

    return result


def extract_auto_explain(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract auto_explain plan blocks from a list of log lines.

    Returns a list of dicts with keys: query, plan_text, plan_format.
    """
    plans: List[Dict[str, Any]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _AUTO_EXPLAIN_START_RE.search(line)
        if m:
            query_text = m.group(1).strip()
            plan_lines: List[str] = []
            i += 1
            # Collect subsequent plan lines until we hit a non-plan line or blank
            while i < len(lines):
                pl = lines[i]
                stripped = pl.strip()
                if not stripped:
                    i += 1
                    break
                # Plan lines start with whitespace or contain plan node keywords
                if _AUTO_EXPLAIN_PLAN_RE.search(stripped) or pl.startswith(" ") or pl.startswith("\t") or stripped.startswith("->") or stripped.startswith("Plan"):
                    plan_lines.append(stripped)
                    i += 1
                else:
                    break
            if plan_lines:
                plan_text = "\n".join(plan_lines)
                # Detect JSON/XML/YAML plan format
                plan_format = "text"
                if plan_text.lstrip().startswith("{"):
                    plan_format = "json"
                elif plan_text.lstrip().startswith("<"):
                    plan_format = "xml"
                elif plan_text.lstrip().startswith("---") or "!!" in plan_text:
                    plan_format = "yaml"
                plans.append({
                    "query": query_text,
                    "plan_text": plan_text,
                    "plan_format": plan_format,
                })
        else:
            i += 1
    return plans


def anonymize_query(query: str, use_random: bool = False) -> str:
    """Replace string literals, numbers, and IN-list values with $N placeholders.

    If use_random=True, replace with random 4-digit numbers for compliance.
    """
    import random

    if not query:
        return query

    counter = [1]

    def _next_placeholder(_m=None) -> str:
        if use_random:
            val = str(random.randint(1000, 9999))
        else:
            val = f"${counter[0]}"
        counter[0] += 1
        return val

    # Replace string literals first
    q = _ANON_STR_RE.sub(lambda m: _next_placeholder(), query)
    # Replace numeric literals (not $N)
    q = _ANON_NUM_RE.sub(lambda m: _next_placeholder() if not m.group().startswith("$") else m.group(), q)
    # Collapse IN ($N, $N, ...) to IN ($N)
    q = _ANON_IN_RE.sub(lambda m: f"(${counter[0]})", q)
    return q


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------

# Level pattern used by the prefix engine
_LEVEL_PATTERN = re.compile(
    r'(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG|DETAIL|HINT|CONTEXT|STATEMENT):\s*(.*)',
    re.IGNORECASE | re.DOTALL,
)


class LogParser:
    """Streaming PostgreSQL log parser."""

    def __init__(
        self,
        slow_query_threshold_ms: float = 1000.0,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        filter_database: Optional[str] = None,
        filter_user: Optional[str] = None,
        log_format: Optional[str] = None,
        log_line_prefix: Optional[str] = None,
        filter_application: Optional[str] = None,
        filter_host: Optional[str] = None,
        filter_pids: Optional[List[int]] = None,
        filter_session_ids: Optional[List[str]] = None,
        exclude_query_re: Optional[List[str]] = None,
        include_query_re: Optional[List[str]] = None,
        select_only: bool = False,
        anonymize: bool = False,
    ):
        self.slow_query_threshold_ms = slow_query_threshold_ms
        self.from_time = from_time
        self.to_time = to_time
        self.filter_database = filter_database
        self.filter_user = filter_user
        self.filter_application = filter_application
        self.filter_host = filter_host
        self.filter_pids = set(filter_pids) if filter_pids else None
        self.filter_session_ids = set(filter_session_ids) if filter_session_ids else None
        self.select_only = select_only
        self.anonymize = anonymize
        self._forced_format: Optional[LogFormat] = (
            LogFormat(log_format) if log_format else None
        )
        # Compile exclude/include query regexes
        self._exclude_query_re = [
            re.compile(p, re.IGNORECASE) for p in (exclude_query_re or [])
        ]
        self._include_query_re = [
            re.compile(p, re.IGNORECASE) for p in (include_query_re or [])
        ]
        # Compile the log_line_prefix engine if provided
        self._prefix_compiler = None
        if log_line_prefix:
            from .prefix import PrefixCompiler
            self._prefix_compiler = PrefixCompiler(log_line_prefix)
            self._prefix_compiler.compile()
            warnings = self._prefix_compiler.validate()
            if warnings:
                import sys
                for w in warnings:
                    print(f'[pgloglens] prefix warning: {w}', file=sys.stderr)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def parse_file(
        self, path: str | Path, show_progress: bool = True
    ) -> Generator[LogEntry, None, None]:
        """Parse a log file, yielding LogEntry objects one at a time.

        Supports: plain text, .gz, .bz2, .lz4, .zst/.zstd, .xz, .zip
        """
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == ".gz":
            opener = gzip.open
            yield from self._parse_with_opener(path, opener, show_progress)
        elif suffix == ".bz2":
            opener = bz2.open
            yield from self._parse_with_opener(path, opener, show_progress)
        elif suffix == ".xz":
            opener = lzma.open
            yield from self._parse_with_opener(path, opener, show_progress)
        elif suffix == ".zip":
            yield from self._parse_zip_file(path, show_progress)
        elif suffix == ".lz4":
            yield from self._parse_lz4_file(path, show_progress)
        elif suffix in (".zst", ".zstd"):
            yield from self._parse_zst_file(path, show_progress)
        else:
            opener = open
            yield from self._parse_with_opener(path, opener, show_progress)

    def _parse_with_opener(
        self, path: Path, opener, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        """Common path: open file with given opener, detect format, parse."""
        # Read first 30 lines for format detection
        sample: List[str] = []
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    sample.append(line)
                    if i >= 29:
                        break
        except Exception:
            return

        log_format = self._forced_format or detect_format(sample)

        if log_format == LogFormat.CSVLOG:
            yield from self._parse_csv_file(path, opener, show_progress)
            return

        if log_format == LogFormat.JSONLOG:
            yield from self._parse_json_file(path, opener, show_progress)
            return

        if log_format == LogFormat.CLOUDSQL:
            yield from self._parse_cloudsql_file(path, opener, show_progress)
            return

        # Stderr / syslog / syslog2 / rds / logplex / redshift / pgbouncer
        yield from self._parse_text_file(path, opener, log_format, show_progress)

    def _parse_lz4_file(
        self, path: Path, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        """Parse an lz4-compressed log file."""
        try:
            import lz4.frame as lz4frame
            with lz4frame.open(str(path), "rt", encoding="utf-8", errors="replace") as fh:
                yield from self._parse_stream_inner(fh, show_progress, str(path))
        except ImportError:
            # Fall back to lz4cat subprocess
            try:
                proc = subprocess.Popen(
                    ["lz4cat", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                stream = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace")
                yield from self._parse_stream_inner(stream, show_progress, str(path))
                proc.wait()
            except FileNotFoundError:
                raise RuntimeError(
                    "lz4 Python package and lz4cat binary not found. "
                    "Install lz4 package: pip install lz4"
                )

    def _parse_zst_file(
        self, path: Path, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        """Parse a zstandard-compressed log file."""
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            with open(path, "rb") as fh:
                stream = io.TextIOWrapper(
                    dctx.stream_reader(fh), encoding="utf-8", errors="replace"
                )
                yield from self._parse_stream_inner(stream, show_progress, str(path))
        except ImportError:
            # Fall back to zstdcat subprocess
            try:
                proc = subprocess.Popen(
                    ["zstdcat", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                stream = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace")
                yield from self._parse_stream_inner(stream, show_progress, str(path))
                proc.wait()
            except FileNotFoundError:
                raise RuntimeError(
                    "zstandard Python package and zstdcat binary not found. "
                    "Install: pip install zstandard"
                )

    def _parse_zip_file(
        self, path: Path, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        """Parse the first file inside a zip archive."""
        with zipfile.ZipFile(str(path), "r") as zf:
            names = zf.namelist()
            if not names:
                return
            first = names[0]
            with zf.open(first) as raw:
                stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                yield from self._parse_stream_inner(stream, show_progress, first)

    def _parse_stream_inner(
        self, stream: Any, show_progress: bool, name: str
    ) -> Generator[LogEntry, None, None]:
        """Parse a text stream without seeking (used for compressed streams)."""
        sample_lines: List[str] = []
        buffered: List[str] = []
        for line in stream:
            buffered.append(line)
            sample_lines.append(line)
            if len(sample_lines) >= 30:
                break

        log_format = self._forced_format or detect_format(sample_lines)

        # Re-create a combined iterator: already-buffered lines + rest of stream
        def _combined():
            for l in buffered:
                yield l
            for l in stream:
                yield l

        if log_format == LogFormat.CSVLOG:
            yield from self._parse_csv_stream(_combined(), 1)
            return
        if log_format == LogFormat.JSONLOG:
            yield from self._parse_json_stream(_combined(), 1)
            return
        if log_format == LogFormat.CLOUDSQL:
            yield from self._parse_cloudsql_stream(_combined(), 1)
            return
        yield from self._parse_text_stream(_combined(), log_format)

    # ------------------------------------------------------------------
    # Stdin / pipe support
    # ------------------------------------------------------------------

    def parse_stream(
        self,
        stream: Any,
        format: Optional[str] = None,
    ) -> Generator[LogEntry, None, None]:
        """Parse any file-like object (e.g. sys.stdin).

        format: optional format name string (e.g. 'csvlog', 'jsonlog', etc.)
        """
        forced = LogFormat(format) if format else self._forced_format

        # Buffer sample lines for detection
        sample_lines: List[str] = []
        buffered: List[str] = []
        for line in stream:
            buffered.append(line)
            sample_lines.append(line)
            if len(sample_lines) >= 30:
                break

        log_format = forced or detect_format(sample_lines)

        def _combined():
            for l in buffered:
                yield l
            for l in stream:
                yield l

        if log_format == LogFormat.CSVLOG:
            yield from self._parse_csv_stream(_combined(), 1)
            return
        if log_format == LogFormat.JSONLOG:
            yield from self._parse_json_stream(_combined(), 1)
            return
        if log_format == LogFormat.CLOUDSQL:
            yield from self._parse_cloudsql_stream(_combined(), 1)
            return
        yield from self._parse_text_stream(_combined(), log_format)

    # ------------------------------------------------------------------
    # SSH remote support
    # ------------------------------------------------------------------

    def parse_remote_ssh(
        self,
        host: str,
        path: str,
        user: Optional[str] = None,
        port: int = 22,
        identity: Optional[str] = None,
    ) -> Generator[LogEntry, None, None]:
        """Parse a remote log file via SSH (runs `ssh host cat path`).

        Args:
            host: remote hostname or IP
            path: remote file path
            user: SSH username (optional)
            port: SSH port (default 22)
            identity: path to SSH private key file (optional)
        """
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port)]
        if identity:
            cmd += ["-i", identity]
        target = f"{user}@{host}" if user else host
        cmd.append(target)

        # Choose decompressor based on extension
        ext = Path(path).suffix.lower()
        if ext == ".gz":
            cmd += ["zcat", path]
        elif ext == ".bz2":
            cmd += ["bzcat", path]
        elif ext in (".zst", ".zstd"):
            cmd += ["zstdcat", path]
        elif ext == ".lz4":
            cmd += ["lz4cat", path]
        elif ext == ".xz":
            cmd += ["xzcat", path]
        else:
            cmd += ["cat", path]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        stream = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace")
        try:
            yield from self.parse_stream(stream)
        finally:
            proc.wait()

    # ------------------------------------------------------------------
    # HTTP remote support
    # ------------------------------------------------------------------

    def parse_remote_http(self, url: str) -> Generator[LogEntry, None, None]:
        """Parse a log file served over HTTP/HTTPS.

        Streams the response body through the parser without buffering
        the entire file in memory.
        """
        req = urllib.request.Request(url, headers={"User-Agent": "pgloglens/2.0"})
        with urllib.request.urlopen(req) as response:
            # Detect content-type / url extension for compressed streams
            ext = Path(url.split("?")[0]).suffix.lower()
            raw = response  # file-like binary stream

            if ext == ".gz":
                stream = io.TextIOWrapper(
                    gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="replace"
                )
            elif ext == ".bz2":
                data = raw.read()
                stream = io.StringIO(bz2.decompress(data).decode("utf-8", errors="replace"))
            elif ext == ".xz":
                data = raw.read()
                stream = io.StringIO(lzma.decompress(data).decode("utf-8", errors="replace"))
            else:
                stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")

            yield from self.parse_stream(stream)

    # ------------------------------------------------------------------
    # Text-format (stderr / syslog / syslog2 / rds / logplex / redshift / pgbouncer) parser
    # ------------------------------------------------------------------

    def _parse_text_file(
        self, path: Path, opener, log_format: LogFormat, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        file_size = path.stat().st_size if path.exists() else 0
        try:
            from tqdm import tqdm
            progress_cm = tqdm(
                total=file_size,
                unit="B",
                unit_scale=True,
                desc=f"Parsing {path.name}",
                disable=not show_progress,
            )
        except ImportError:
            progress_cm = None

        pending_lines: List[str] = []
        line_number = 0
        current_line_start = 0

        prefix_compiler = self._prefix_compiler  # capture in closure

        def flush(lines: List[str], lnum: int) -> Optional[LogEntry]:
            if not lines:
                return None
            full = " ".join(l.rstrip("\n\r").strip() for l in lines)
            if prefix_compiler and log_format == LogFormat.STDERR:
                return _parse_with_prefix(full, lnum, prefix_compiler)
            return _dispatch_text_line(full, lnum, log_format)

        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line_number += 1
                if progress_cm:
                    progress_cm.update(len(raw_line.encode("utf-8", errors="replace")))

                if _is_continuation(raw_line, log_format):
                    if pending_lines:
                        pending_lines.append(raw_line)
                    continue

                # New entry — flush previous
                entry = flush(pending_lines, current_line_start)
                if entry is not None and self._passes_filter(entry):
                    yield entry

                pending_lines = [raw_line]
                current_line_start = line_number

        # Flush final entry
        entry = flush(pending_lines, current_line_start)
        if entry is not None and self._passes_filter(entry):
            yield entry

        if progress_cm:
            progress_cm.close()

    def _parse_text_stream(
        self, lines_iter: Any, log_format: LogFormat
    ) -> Generator[LogEntry, None, None]:
        """Parse a text-format stream (no seeking, no progress bar)."""
        pending_lines: List[str] = []
        line_number = 0
        current_line_start = 0

        def flush(lines: List[str], lnum: int) -> Optional[LogEntry]:
            if not lines:
                return None
            full = " ".join(l.rstrip("\n\r").strip() for l in lines)
            return _dispatch_text_line(full, lnum, log_format)

        for raw_line in lines_iter:
            line_number += 1
            if _is_continuation(raw_line, log_format):
                if pending_lines:
                    pending_lines.append(raw_line)
                continue
            entry = flush(pending_lines, current_line_start)
            if entry is not None and self._passes_filter(entry):
                yield entry
            pending_lines = [raw_line]
            current_line_start = line_number

        entry = flush(pending_lines, current_line_start)
        if entry is not None and self._passes_filter(entry):
            yield entry

    # ------------------------------------------------------------------
    # CSV parser
    # ------------------------------------------------------------------

    def _parse_csv_file(
        self, path: Path, opener, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        file_size = path.stat().st_size if path.exists() else 0
        try:
            from tqdm import tqdm
            progress = tqdm(
                total=file_size,
                unit="B",
                unit_scale=True,
                desc=f"Parsing {path.name}",
                disable=not show_progress,
            )
        except ImportError:
            progress = None

        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for entry in self._parse_csv_stream(fh, 1, progress=progress):
                yield entry

        if progress:
            progress.close()

    def _parse_csv_stream(
        self, line_iter: Any, start_line: int, progress=None
    ) -> Generator[LogEntry, None, None]:
        reader = csv.reader(line_iter)
        for i, row in enumerate(reader):
            if progress:
                progress.update(sum(len(c) for c in row))
            entry = _parse_csv_row(row, start_line + i)
            if entry and self._passes_filter(entry):
                yield entry

    # ------------------------------------------------------------------
    # JSON parser
    # ------------------------------------------------------------------

    def _parse_json_file(
        self, path: Path, opener, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        file_size = path.stat().st_size if path.exists() else 0
        try:
            from tqdm import tqdm
            progress = tqdm(
                total=file_size,
                unit="B",
                unit_scale=True,
                desc=f"Parsing {path.name}",
                disable=not show_progress,
            )
        except ImportError:
            progress = None

        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for entry in self._parse_json_stream(fh, 1, progress=progress):
                yield entry

        if progress:
            progress.close()

    def _parse_json_stream(
        self, line_iter: Any, start_line: int, progress=None
    ) -> Generator[LogEntry, None, None]:
        for i, line in enumerate(line_iter):
            if progress:
                progress.update(len(line.encode("utf-8", errors="replace")))
            line = line.strip()
            if not line:
                continue
            entry = _parse_json_line(line, start_line + i)
            if entry and self._passes_filter(entry):
                yield entry

    # ------------------------------------------------------------------
    # CloudSQL parser
    # ------------------------------------------------------------------

    def _parse_cloudsql_file(
        self, path: Path, opener, show_progress: bool
    ) -> Generator[LogEntry, None, None]:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            yield from self._parse_cloudsql_stream(fh, 1)

    def _parse_cloudsql_stream(
        self, line_iter: Any, start_line: int
    ) -> Generator[LogEntry, None, None]:
        for i, line in enumerate(line_iter):
            line = line.strip()
            if not line:
                continue
            entry = _parse_cloudsql_line(line, start_line + i)
            if entry and self._passes_filter(entry):
                yield entry

    # ------------------------------------------------------------------
    # Filter helpers
    # ------------------------------------------------------------------

    def _passes_filter(self, entry: LogEntry) -> bool:
        if self.from_time and entry.timestamp and entry.timestamp < self.from_time:
            return False
        if self.to_time and entry.timestamp and entry.timestamp > self.to_time:
            return False
        if self.filter_database and entry.database and entry.database != self.filter_database:
            return False
        if self.filter_user and entry.user and entry.user != self.filter_user:
            return False
        if self.filter_application and entry.application_name and entry.application_name != self.filter_application:
            return False
        if self.filter_host and entry.remote_host and entry.remote_host != self.filter_host:
            return False
        if self.filter_pids and entry.pid and entry.pid not in self.filter_pids:
            return False
        if self.filter_session_ids and entry.session_id and entry.session_id not in self.filter_session_ids:
            return False
        # select-only mode
        if self.select_only and entry.query and not entry.query.lstrip().upper().startswith('SELECT'):
            return False
        # query regex filters
        q = entry.query or entry.message
        if self._include_query_re and not any(r.search(q) for r in self._include_query_re):
            return False
        if self._exclude_query_re and any(r.search(q) for r in self._exclude_query_re):
            return False
        return True


# ---------------------------------------------------------------------------
# Prefix-engine dispatcher
# ---------------------------------------------------------------------------

def _parse_with_prefix(line: str, line_number: int, compiler) -> Optional[LogEntry]:
    """
    Parse a log line using a compiled PrefixCompiler.
    Maps extracted fields onto a LogEntry and enriches it.
    """
    from .prefix import build_entry_from_prefix
    result = build_entry_from_prefix(line, compiler, _LEVEL_PATTERN)
    if result is None:
        return None
    fields, level_str, message = result

    # Resolve timestamp — prefer ms-precision
    ts = None
    for ts_key in ('timestamp_ms', 'timestamp', 'timestamp_epoch'):
        if fields.get(ts_key):
            ts = _safe_parse_dt(fields[ts_key])
            break

    # Resolve PID
    pid = None
    pid_raw = fields.get('pid') or fields.get('parallel_leader_pid')
    if pid_raw and pid_raw.isdigit():
        pid = int(pid_raw)

    # Resolve host — prefer %r (host:port) over %h
    host = fields.get('remote_host') or fields.get('remote_host_port')
    if host and '(' in host:  # strip port from host(port) format
        host = host.split('(')[0]

    entry = LogEntry(
        timestamp=ts,
        pid=pid,
        session_id=fields.get('session_id'),
        user=fields.get('user') or None,
        database=fields.get('database') or None,
        application_name=fields.get('application_name') or None,
        remote_host=host or None,
        error_code=fields.get('sql_state') or None,
        log_level=_map_level(level_str),
        message=message.strip(),
        raw_line=line,
        line_number=line_number,
    )
    _enrich_entry(entry)
    return entry


# ---------------------------------------------------------------------------
# Format dispatcher helper
# ---------------------------------------------------------------------------

def _dispatch_text_line(line: str, line_number: int, log_format: LogFormat) -> Optional[LogEntry]:
    """Dispatch a text line to the correct per-format parser."""
    if log_format == LogFormat.SYSLOG:
        return _parse_syslog_line(line, line_number)
    if log_format == LogFormat.SYSLOG2:
        return _parse_syslog2_line(line, line_number)
    if log_format == LogFormat.RDS:
        return _parse_rds_line(line, line_number)
    if log_format == LogFormat.LOGPLEX:
        return _parse_logplex_line(line, line_number)
    if log_format == LogFormat.REDSHIFT:
        return _parse_redshift_line(line, line_number)
    if log_format == LogFormat.PGBOUNCER:
        return _parse_pgbouncer_line(line, line_number)
    return _parse_stderr_line(line, line_number)


# ---------------------------------------------------------------------------
# Utility functions used by other modules
# ---------------------------------------------------------------------------

def is_slow_query(entry: LogEntry, threshold_ms: float) -> bool:
    """Return True if the entry is a slow query log line."""
    return entry.duration_ms is not None and entry.duration_ms >= threshold_ms


def is_lock_wait(entry: LogEntry) -> bool:
    return bool(_LOCK_WAIT_RE.search(entry.message))


def is_deadlock(entry: LogEntry) -> bool:
    return bool(_DEADLOCK_RE.search(entry.message))


def is_checkpoint(entry: LogEntry) -> bool:
    return bool(_CHECKPOINT_START_RE.search(entry.message) or _CHECKPOINT_RE.search(entry.message))


def is_autovacuum(entry: LogEntry) -> bool:
    return bool(re.search(r"automatic (?:vacuum|analyze)", entry.message, re.IGNORECASE))


def is_tempfile(entry: LogEntry) -> bool:
    return bool(_TEMPFILE_RE.search(entry.message))


def is_connection_event(entry: LogEntry) -> bool:
    return bool(re.search(r"connection (?:received|authorized|rejected)", entry.message, re.IGNORECASE))


def is_disconnection(entry: LogEntry) -> bool:
    return bool(_CONN_CLOSE_RE.search(entry.message))


def is_auth_failure(entry: LogEntry) -> bool:
    return bool(_AUTH_FAIL_RE.search(entry.message))


def is_replication_event(entry: LogEntry) -> bool:
    return bool(_REPL_LAG_RE.search(entry.message) or _WAL_RECEIVER_RE.search(entry.message))


def is_oom(entry: LogEntry) -> bool:
    return bool(_OOM_RE.search(entry.message))


def is_disk_full(entry: LogEntry) -> bool:
    return bool(_DISK_FULL_RE.search(entry.message))


def extract_lock_event(entry: LogEntry):
    """Extract lock wait information from a log entry message."""
    from .models import LockEvent

    is_dl = is_deadlock(entry)
    m = _LOCK_WAIT_RE.search(entry.message)
    if m:
        waiting_pid = int(m.group(1))
        lock_type = m.group(2)
        blocking_raw = m.group(4)
        blocking_pids = [int(p.strip()) for p in blocking_raw.split(",") if p.strip().isdigit()]
        return LockEvent(
            waiting_pid=waiting_pid,
            blocking_pid=blocking_pids[0] if blocking_pids else None,
            timestamp=entry.timestamp,
            lock_type=lock_type,
            is_deadlock=is_dl,
        )
    if is_dl:
        return LockEvent(
            waiting_pid=entry.pid,
            timestamp=entry.timestamp,
            is_deadlock=True,
        )
    return None


def extract_checkpoint(entry: LogEntry):
    """Extract checkpoint statistics from a log entry."""
    from .models import CheckpointStats

    m = _CHECKPOINT_RE.search(entry.message)
    if not m:
        return None
    buffers = int(m.group(1))
    wal_added = int(m.group(3))
    wal_removed = int(m.group(4))
    wal_recycled = int(m.group(5))
    write_s = float(m.group(6))
    sync_s = float(m.group(7))
    total_s = float(m.group(8))
    total_ms = total_s * 1000.0

    # Checkpoint cause
    cause = "scheduled"
    cm = _CHECKPOINT_CAUSE_RE.search(entry.message)
    if cm:
        cause_word = cm.group(1).lower()
        if cause_word in ("immediate", "requested", "xlog", "timed", "shutdown", "recovery"):
            cause = cause_word

    # Distance / estimate
    distance = None
    estimate = None
    dm = _CHECKPOINT_DISTANCE_RE.search(entry.message)
    if dm:
        distance = int(dm.group(1))
        estimate = int(dm.group(2))

    return {
        "duration_ms": total_ms,
        "write_s": write_s,
        "sync_s": sync_s,
        "buffers": buffers,
        "type": cause,
        "wal_added": wal_added,
        "wal_removed": wal_removed,
        "wal_recycled": wal_recycled,
        "distance": distance,
        "estimate": estimate,
    }


def extract_autovacuum(entry: LogEntry):
    """Extract autovacuum statistics from a log entry, including PG11.4+ extended metrics."""
    msg = entry.message
    # Match full autovacuum line
    m = re.search(
        r"automatic\s+(vacuum|analyze)\s+of\s+table\s+"
        r'"?([^":\s]+(?:\.\"[^\"]*\"|\.\\S+)?)\"?'
        r"(?::(.+))?",
        msg,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None

    vac_type = m.group(1).lower()
    table_raw = m.group(2)
    rest = m.group(3) or ""

    # Extract duration — handles both "elapsed time: 45.3 s" and "duration: 45.3 s"
    dur_m = re.search(r"(?:elapsed\s+time|elapsed|duration):\s*([\d.]+)\s*s", rest, re.IGNORECASE)
    duration_ms = float(dur_m.group(1)) * 1000.0 if dur_m else 0.0

    # Extract pages
    pages_m = re.search(r"pages:\s*(\d+)\s+removed,\s*(\d+)\s+remain", rest, re.IGNORECASE)
    pages_removed = int(pages_m.group(1)) if pages_m else 0

    # Extract tuples
    tuples_m = re.search(r"tuples:\s*([\d.]+)\s+removed,\s*([\d.]+)\s+remain", rest, re.IGNORECASE)
    tuples_removed = int(float(tuples_m.group(1))) if tuples_m else 0

    # Dead tuples before
    dead_m = re.search(r"dead\s+tuples?\s+before[:\s]+([\d.]+)", rest, re.IGNORECASE)
    dead_before = int(float(dead_m.group(1))) if dead_m else 0

    # Index scans
    idx_m = re.search(r"index scans:\s*(\d+)", rest, re.IGNORECASE)
    index_scans = int(idx_m.group(1)) if idx_m else 0

    # Parse schema.table
    parts = table_raw.replace('"', "").split(".")
    table = parts[-1] if parts else table_raw
    table_schema = parts[-2] if len(parts) >= 2 else "public"

    # Extended buffer metrics (PG11.4+)
    buf_hits = buf_misses = buf_dirtied = 0
    bm = _AUTOVAC_BUFFERS_RE.search(rest)
    if bm:
        buf_hits = int(bm.group(1))
        buf_misses = int(bm.group(2))
        buf_dirtied = int(bm.group(3))

    # WAL metrics
    wal_records = wal_fpi = wal_bytes = 0
    wm = _AUTOVAC_WAL_RE.search(rest)
    if wm:
        wal_records = int(wm.group(1))
        wal_fpi = int(wm.group(2))
        wal_bytes = int(wm.group(3))

    # CPU metrics
    cpu_user = cpu_sys = 0.0
    cm = _AUTOVAC_CPU_RE.search(rest)
    if cm:
        cpu_user = float(cm.group(1))
        cpu_sys = float(cm.group(2))

    # Skipped pins / frozen
    skipped_pins = skipped_frozen = 0
    fm = _AUTOVAC_FROZEN_RE.search(rest)
    if fm:
        skipped_pins = int(fm.group(1))
        skipped_frozen = int(fm.group(2))

    from .models import AutovacuumStats
    return AutovacuumStats(
        table=table,
        table_schema=table_schema,
        duration_ms=duration_ms,
        pages_removed=pages_removed,
        tuples_removed=tuples_removed,
        dead_tuples_before=dead_before,
        index_scans=index_scans,
        timestamp=entry.timestamp,
        is_analyze=(vac_type == "analyze"),
        operation=vac_type,
        buffer_hits=buf_hits,
        buffer_misses=buf_misses,
        buffers_dirtied=buf_dirtied,
        wal_records=wal_records,
        wal_fpi=wal_fpi,
        wal_bytes=wal_bytes,
        cpu_user_s=cpu_user,
        cpu_sys_s=cpu_sys,
        skipped_pins=skipped_pins,
        skipped_frozen=skipped_frozen,
    )


def extract_tempfile(entry: LogEntry):
    """Extract temp file statistics from a log entry."""
    m = _TEMPFILE_RE.search(entry.message)
    if not m:
        return None
    size_bytes = int(m.group(2))
    from .models import TempFileStats
    return TempFileStats(
        size_bytes=size_bytes,
        size_mb=round(size_bytes / (1024 * 1024), 2),
        session_id=entry.session_id,
        pid=entry.pid,
        timestamp=entry.timestamp,
        database=entry.database,
        user=entry.user,
    )
