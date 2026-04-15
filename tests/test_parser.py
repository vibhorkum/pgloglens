"""Tests for the pgloglens log parser."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import pytest

# Paths
SAMPLE_LOG = Path(__file__).parent / "sample_pg.log"
TESTS_DIR = Path(__file__).parent


def test_sample_log_exists():
    assert SAMPLE_LOG.exists(), f"Sample log file not found: {SAMPLE_LOG}"


def test_detect_format_stderr():
    from pgloglens.parser import detect_format, LogFormat
    sample_lines = [
        "2024-01-15 08:00:01.234 UTC [12345] LOG:  database system was shut down\n",
        "2024-01-15 08:00:03.451 UTC [12346] app@myapp LOG:  connection authorized\n",
    ]
    fmt = detect_format(sample_lines)
    assert fmt == LogFormat.STDERR


def test_detect_format_json():
    from pgloglens.parser import detect_format, LogFormat
    sample_lines = [
        '{"timestamp": "2024-01-15 08:00:01.234 UTC", "error_severity": "LOG", "message": "test"}\n',
    ]
    fmt = detect_format(sample_lines)
    assert fmt == LogFormat.JSONLOG


def test_parse_stderr_line_basic():
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 08:00:01.234 UTC [12345] LOG:  database system was shut down"
    entry = _parse_stderr_line(line, 1)
    assert entry is not None
    assert entry.pid == 12345
    assert entry.log_level.value == "LOG"
    assert "database system" in entry.message


def test_parse_stderr_line_with_user_db():
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 08:00:03.451 UTC [12346] app@myapp LOG:  connection authorized: user=app database=myapp"
    entry = _parse_stderr_line(line, 2)
    assert entry is not None
    assert entry.user == "app"
    assert entry.database == "myapp"
    assert entry.pid == 12346


def test_parse_stderr_line_with_duration():
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 08:00:12.500 UTC [12347] app@myapp LOG:  duration: 1234.567 ms  statement: SELECT * FROM users"
    entry = _parse_stderr_line(line, 3)
    assert entry is not None
    assert entry.duration_ms == pytest.approx(1234.567)
    assert "SELECT" in entry.query


def test_parse_stderr_line_error_with_sqlstate():
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 08:00:18.000 UTC [12346] app@myapp ERROR:  duplicate key value violates unique constraint \"users_email_key\" (23505)"
    entry = _parse_stderr_line(line, 4)
    assert entry is not None
    assert entry.log_level.value == "ERROR"
    assert entry.error_code == "23505"


def test_parse_stderr_line_fatal():
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 08:00:19.000 UTC [12350] baduser@myapp FATAL:  password authentication failed for user \"baduser\""
    entry = _parse_stderr_line(line, 5)
    assert entry is not None
    assert entry.log_level.value == "FATAL"
    assert "authentication failed" in entry.message


def test_parse_json_line():
    from pgloglens.parser import _parse_json_line
    import json
    obj = {
        "timestamp": "2024-01-15 08:00:01.234 UTC",
        "error_severity": "LOG",
        "process_id": 12345,
        "message": "test message",
        "user": "app",
        "dbname": "myapp",
    }
    line = json.dumps(obj)
    entry = _parse_json_line(line, 1)
    assert entry is not None
    assert entry.pid == 12345
    assert entry.message == "test message"
    assert entry.user == "app"
    assert entry.database == "myapp"


def test_parser_parse_sample_file():
    """Parse the sample log file and verify we get reasonable entries."""
    from pgloglens.parser import LogParser
    parser = LogParser(slow_query_threshold_ms=1000.0)
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    assert len(entries) > 50, f"Expected >50 entries, got {len(entries)}"


def test_parser_finds_slow_queries():
    from pgloglens.parser import LogParser, is_slow_query
    parser = LogParser(slow_query_threshold_ms=1000.0)
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    slow = [e for e in entries if is_slow_query(e, 1000.0)]
    assert len(slow) >= 5, f"Expected >=5 slow queries, got {len(slow)}"


def test_parser_finds_auth_failures():
    from pgloglens.parser import LogParser, is_auth_failure
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    failures = [e for e in entries if is_auth_failure(e)]
    assert len(failures) >= 5, f"Expected >=5 auth failures, got {len(failures)}"


def test_parser_finds_lock_waits():
    from pgloglens.parser import LogParser, is_lock_wait
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    locks = [e for e in entries if is_lock_wait(e)]
    assert len(locks) >= 1, f"Expected >=1 lock wait, got {len(locks)}"


def test_parser_finds_deadlock():
    from pgloglens.parser import LogParser, is_deadlock
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    deadlocks = [e for e in entries if is_deadlock(e)]
    assert len(deadlocks) >= 1, f"Expected >=1 deadlock, got {len(deadlocks)}"


def test_parser_finds_checkpoints():
    from pgloglens.parser import LogParser, is_checkpoint, extract_checkpoint
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    checkpoints = [e for e in entries if is_checkpoint(e)]
    assert len(checkpoints) >= 2, f"Expected >=2 checkpoint entries, got {len(checkpoints)}"
    # At least one should be extractable
    extracted = [extract_checkpoint(e) for e in checkpoints if extract_checkpoint(e)]
    assert len(extracted) >= 1


def test_parser_finds_autovacuum():
    from pgloglens.parser import LogParser, is_autovacuum, extract_autovacuum
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    avs = [e for e in entries if is_autovacuum(e)]
    assert len(avs) >= 3, f"Expected >=3 autovacuum entries, got {len(avs)}"


def test_parser_finds_temp_files():
    from pgloglens.parser import LogParser, is_tempfile, extract_tempfile
    parser = LogParser()
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    tmps = [e for e in entries if is_tempfile(e)]
    assert len(tmps) >= 3, f"Expected >=3 temp file entries, got {len(tmps)}"
    # Verify sizes
    for e in tmps:
        tf = extract_tempfile(e)
        assert tf is not None
        assert tf.size_bytes > 0


def test_parser_date_filter():
    from pgloglens.parser import LogParser
    from datetime import timezone
    # Filter to only one minute
    from_dt = datetime(2024, 1, 15, 8, 0, 0)
    to_dt = datetime(2024, 1, 15, 8, 0, 59)
    parser = LogParser(from_time=from_dt, to_time=to_dt)
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    for e in entries:
        if e.timestamp:
            assert e.timestamp >= from_dt
            assert e.timestamp <= to_dt


def test_parser_database_filter():
    from pgloglens.parser import LogParser
    parser = LogParser(filter_database="reporting")
    entries = list(parser.parse_file(SAMPLE_LOG, show_progress=False))
    for e in entries:
        if e.database:
            assert e.database == "reporting"


def test_is_connection_event():
    from pgloglens.parser import _parse_stderr_line, is_connection_event
    line = "2024-01-15 08:00:03.451 UTC [12346] app@myapp LOG:  connection authorized: user=app database=myapp"
    entry = _parse_stderr_line(line, 1)
    assert entry is not None
    assert is_connection_event(entry)


def test_extract_lock_event():
    from pgloglens.parser import _parse_stderr_line, extract_lock_event
    line = (
        "2024-01-15 08:00:25.000 UTC [12347] app@myapp LOG:  "
        "process 12355 still waiting for ShareLock on transaction 7891234; blocking processes: 12346"
    )
    entry = _parse_stderr_line(line, 1)
    assert entry is not None
    ev = extract_lock_event(entry)
    assert ev is not None
    assert ev.waiting_pid == 12355
    assert ev.lock_type == "ShareLock"


def test_extract_autovacuum():
    from pgloglens.parser import _parse_stderr_line, extract_autovacuum
    line = (
        '2024-01-15 08:00:40.000 UTC [12358] autovacuum LOG:  automatic vacuum of table "myapp.public.orders": '
        'index scans: 1, pages: 250 removed, 8750 remain, 0 skipped due to pins, 0 skipped frozen; '
        'tuples: 15234.00 removed, 1234567.00 remain, 0 are dead but not yet removable, oldest xmin: 7890123; '
        'I/O timings: read: 0.000 ms, write: 0.000 ms; elapsed time: 45.320 s'
    )
    entry = _parse_stderr_line(line, 1)
    assert entry is not None
    av = extract_autovacuum(entry)
    assert av is not None
    assert av.table == "orders"
    assert av.duration_ms == pytest.approx(45320.0)
    assert av.tuples_removed == 15234


def test_gzip_file_not_crash(tmp_path):
    """Test that gzip files are handled (just check they don't crash)."""
    import gzip
    gz_path = tmp_path / "test.log.gz"
    content = b"2024-01-15 08:00:01.234 UTC [12345] LOG:  test message\n"
    with gzip.open(gz_path, "wb") as fh:
        fh.write(content)
    from pgloglens.parser import LogParser
    parser = LogParser()
    entries = list(parser.parse_file(gz_path, show_progress=False))
    assert len(entries) >= 1


# ---------------------------------------------------------------------------
# Regression tests: SQL capture bugs
# ---------------------------------------------------------------------------

def test_statement_only_line_sets_query():
    """
    Regression: log_statement='all' + log_duration=on emits SQL and duration
    as SEPARATE log entries.  The statement-only line must set entry.query even
    though there is no duration on that line.
    """
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 09:00:00.000 UTC [9999] postgres@mydb LOG:  statement: SELECT * FROM orders WHERE id = 42"
    entry = _parse_stderr_line(line, 1)
    assert entry is not None
    assert entry.query is not None, "SQL must be extracted from statement-only line"
    assert "SELECT" in entry.query
    assert entry.duration_ms is None  # no duration on this line


def test_duration_only_line_no_sql_in_query():
    """
    A bare duration line (log_duration=on, no statement logging) must NOT
    set entry.query to the raw 'duration: X ms' message text — that would
    pollute the slow-query table with fake 'queries'.
    """
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 09:00:01.000 UTC [9999] postgres@mydb LOG:  duration: 1234.567 ms"
    entry = _parse_stderr_line(line, 2)
    assert entry is not None
    assert entry.duration_ms == pytest.approx(1234.567)
    # entry.query must remain None — the raw duration message is NOT a SQL query
    assert entry.query is None


def test_execute_phase_line_without_duration_sets_query():
    """
    An 'execute <name>: SELECT ...' line (extended query protocol, no duration)
    must set entry.query so the SQL is available for correlation.
    """
    from pgloglens.parser import _parse_stderr_line
    line = "2024-01-15 09:00:02.000 UTC [9999] postgres@mydb LOG:  execute <unnamed>: SELECT $1 FROM users"
    entry = _parse_stderr_line(line, 3)
    assert entry is not None
    assert entry.query is not None
    assert "SELECT" in entry.query
    assert entry.phase == "execute"


def test_pid_correlation_attaches_sql_to_duration_entry():
    """
    Regression: when log_statement='all' + log_duration=on are used together,
    the Analyzer must correlate the statement line with the subsequent duration
    line from the same PID so that the slow-query table shows actual SQL.
    """
    from pgloglens.parser import _parse_stderr_line
    from pgloglens.analyzer import Analyzer

    stmt_line = "2024-01-15 09:00:00.000 UTC [7777] postgres@mydb LOG:  statement: SELECT * FROM big_table WHERE status = 'open'"
    dur_line  = "2024-01-15 09:00:02.500 UTC [7777] postgres@mydb LOG:  duration: 2500.000 ms"

    entries = [
        _parse_stderr_line(stmt_line, 1),
        _parse_stderr_line(dur_line, 2),
    ]
    entries = [e for e in entries if e is not None]
    assert len(entries) == 2

    analyzer = Analyzer(log_file_paths=["test"], slow_query_threshold_ms=1000.0)
    result = analyzer.process_entries(iter(entries))

    # The slow query must carry the real SQL, not "duration: 2500.000 ms"
    assert len(result.slow_queries) >= 1
    sq = result.slow_queries[0]
    assert "SELECT" in sq.query, (
        f"Expected SQL in slow query, got: {sq.query!r}. "
        "PID-based correlation may be broken."
    )
    assert "duration:" not in sq.query.lower()


def test_branding_in_html_report():
    """
    Regression: the HTML report header must say 'pgLoglens', not 'pganalyzer'.
    The HTML template splits the name across a <span> tag so we search for the
    component parts rather than the concatenated string.
    """
    import pathlib
    reporter_path = pathlib.Path(__file__).parent.parent / "pgloglens" / "reporter.py"
    text = reporter_path.read_text()
    # The old wrong brand must be absent
    assert "pganalyzer" not in text, (
        "HTML report still contains 'pganalyzer' — should say 'pgLoglens'"
    )
    # The correct brand: header-logo contains 'Loglens' inside a <span>
    assert "Loglens</span>" in text, (
        "HTML report header-logo should contain 'Loglens</span>'"
    )
