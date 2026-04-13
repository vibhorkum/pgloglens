"""Tests for the pgloglens statistical analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

SAMPLE_LOG = Path(__file__).parent / "sample_pg.log"


def _run_full_analysis(slow_threshold: float = 1000.0):
    """Helper: parse sample log and run full analysis."""
    from pgloglens.parser import LogParser
    from pgloglens.analyzer import Analyzer

    parser = LogParser(slow_query_threshold_ms=slow_threshold)
    analyzer = Analyzer(
        log_file_paths=[str(SAMPLE_LOG)],
        slow_query_threshold_ms=slow_threshold,
        top_queries=25,
        top_errors=20,
    )
    entries = parser.parse_file(SAMPLE_LOG, show_progress=False)
    result = analyzer.process_entries(entries)
    return result


def test_full_analysis_returns_result():
    result = _run_full_analysis()
    assert result is not None
    assert result.total_entries > 0


def test_analysis_finds_slow_queries():
    result = _run_full_analysis()
    assert len(result.slow_queries) > 0


def test_slow_query_has_valid_stats():
    result = _run_full_analysis()
    for sq in result.slow_queries:
        assert sq.count >= 1
        assert sq.avg_duration_ms > 0
        assert sq.max_duration_ms >= sq.avg_duration_ms
        assert sq.min_duration_ms <= sq.avg_duration_ms
        assert sq.p95_duration_ms >= sq.p50_duration_ms
        assert sq.p99_duration_ms >= sq.p95_duration_ms


def test_analysis_finds_error_patterns():
    result = _run_full_analysis()
    assert len(result.error_patterns) > 0


def test_error_patterns_have_counts():
    result = _run_full_analysis()
    for ep in result.error_patterns:
        assert ep.count >= 1
        # Should have at least one sample message
        assert len(ep.sample_messages) >= 1


def test_analysis_finds_lock_events():
    result = _run_full_analysis()
    assert len(result.lock_events) > 0


def test_analysis_detects_deadlock():
    result = _run_full_analysis()
    assert result.deadlock_count >= 1


def test_analysis_finds_checkpoints():
    result = _run_full_analysis()
    # The sample log has checkpoint complete lines
    assert result.checkpoint_stats.count >= 1 or result.checkpoint_stats.warning_count >= 1


def test_analysis_finds_autovacuum():
    result = _run_full_analysis()
    assert len(result.autovacuum_stats) >= 3


def test_analysis_finds_temp_files():
    result = _run_full_analysis()
    assert len(result.temp_files) >= 3


def test_analysis_finds_auth_failures():
    result = _run_full_analysis()
    assert result.connection_stats.auth_failures >= 5


def test_analysis_finds_connections():
    result = _run_full_analysis()
    assert result.connection_stats.total_connections >= 3


def test_analysis_finds_panic_fatal():
    result = _run_full_analysis()
    assert len(result.panic_fatal_events) >= 5


def test_time_range_populated():
    result = _run_full_analysis()
    assert result.time_range_start is not None
    assert result.time_range_end is not None
    assert result.time_range_end >= result.time_range_start


def test_normalize_query_strips_literals():
    from pgloglens.analyzer import normalize_query
    q = "SELECT * FROM users WHERE email = 'test@example.com' AND age = 25"
    norm = normalize_query(q)
    assert "test@example.com" not in norm
    assert "25" not in norm
    assert "$" in norm


def test_normalize_query_strips_numbers():
    from pgloglens.analyzer import normalize_query
    q = "SELECT id FROM orders WHERE status = 'pending' AND id = 12345"
    norm = normalize_query(q)
    assert "12345" not in norm


def test_normalize_query_consistent():
    from pgloglens.analyzer import normalize_query
    q1 = "SELECT * FROM users WHERE id = 100"
    q2 = "SELECT * FROM users WHERE id = 200"
    assert normalize_query(q1) == normalize_query(q2)


def test_error_categorizer():
    from pgloglens.analyzer import categorize_error
    assert categorize_error("connection timeout") == "connection"
    assert categorize_error("deadlock detected") == "lock"
    assert categorize_error("no space left on device") == "disk"
    assert categorize_error("replication slot lag") == "replication"
    assert categorize_error("syntax error near SELECT") == "query"


def test_slow_queries_sorted_by_total_duration():
    result = _run_full_analysis()
    if len(result.slow_queries) >= 2:
        for i in range(len(result.slow_queries) - 1):
            assert result.slow_queries[i].total_duration_ms >= result.slow_queries[i + 1].total_duration_ms


def test_rca_runs_without_error():
    from pgloglens.rca import run_rca
    result = _run_full_analysis()
    findings = run_rca(result)
    assert isinstance(findings, list)
    # With our sample log having auth failures, we expect at least one finding
    assert len(findings) >= 1


def test_rca_finds_auth_failures():
    from pgloglens.rca import run_rca
    result = _run_full_analysis()
    run_rca(result)
    rule_ids = [f.rule_id for f in result.rca_findings]
    assert "AUTH_FAILURES_SPIKE" in rule_ids


def test_rca_findings_have_recommendations():
    from pgloglens.rca import run_rca
    result = _run_full_analysis()
    findings = run_rca(result)
    for finding in findings:
        assert len(finding.recommendations) >= 1
        assert finding.severity is not None
        assert finding.title
        assert finding.description


def test_rca_sorted_by_severity():
    from pgloglens.rca import run_rca
    from pgloglens.models import Severity
    result = _run_full_analysis()
    findings = run_rca(result)
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4
    }
    for i in range(len(findings) - 1):
        assert severity_order[findings[i].severity] <= severity_order[findings[i + 1].severity]


def test_autovacuum_frequency_analysis():
    from pgloglens.analyzer import analyze_autovacuum_frequency
    result = _run_full_analysis()
    freq = analyze_autovacuum_frequency(result.autovacuum_stats)
    assert len(freq) >= 1
    # Should be sorted by count descending
    for i in range(len(freq) - 1):
        assert freq[i][1] >= freq[i + 1][1]


def test_json_report_generates():
    from pgloglens.rca import run_rca
    from pgloglens.reporter import render_json
    result = _run_full_analysis()
    run_rca(result)
    import json
    output = render_json(result)
    data = json.loads(output)
    assert "slow_queries" in data
    assert "error_patterns" in data
    assert "rca_findings" in data


def test_markdown_report_generates():
    from pgloglens.rca import run_rca
    from pgloglens.reporter import render_markdown
    result = _run_full_analysis()
    run_rca(result)
    md = render_markdown(result)
    assert "# pgloglens" in md
    assert "## Top Slow Queries" in md or "## Error Patterns" in md


def test_html_report_generates():
    from pgloglens.rca import run_rca
    from pgloglens.reporter import render_html
    result = _run_full_analysis()
    run_rca(result)
    html = render_html(result)
    assert "<!DOCTYPE html>" in html
    assert "pgloglens" in html
    assert "Chart.js" in html
    assert "<table" in html


def test_html_report_is_self_contained():
    from pgloglens.reporter import render_html
    result = _run_full_analysis()
    html = render_html(result)
    # Should not reference external files except CDN links
    assert "localhost" not in html or "11434" in html  # ollama is ok
    # Should have inline CSS
    assert "<style>" in html
    assert "</style>" in html


def test_query_regression_detection():
    from pgloglens.analyzer import detect_query_regression
    from pgloglens.models import SlowQuery
    sq = SlowQuery(
        query="SELECT * FROM test",
        normalized_query="SELECT * FROM test",
        count=0,
    )
    # Add samples with clear upward trend
    for i, dur in enumerate([100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]):
        sq.add_sample(dur, None, None, None)
    # detect_query_regression expects a list and modifies in place
    result = detect_query_regression([sq])
    assert len(result) == 1
    assert result[0].is_regression is True
    assert result[0].regression_slope is not None
    assert result[0].regression_slope > 0


def test_connection_pool_efficiency():
    from pgloglens.analyzer import connection_pool_efficiency
    from pgloglens.models import ConnectionStats
    cs = ConnectionStats(total_connections=100, peak_concurrent=50)
    efficiency = connection_pool_efficiency(cs)
    assert 0 <= efficiency <= 100


def test_temp_files_sorted_by_size():
    result = _run_full_analysis()
    if len(result.temp_files) >= 2:
        for i in range(len(result.temp_files) - 1):
            assert result.temp_files[i].size_bytes >= result.temp_files[i + 1].size_bytes
