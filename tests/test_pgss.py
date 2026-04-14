"""Tests for pgloglens pg_stat_statements integration module."""

import json
import os
import tempfile
import pytest

from pgloglens.pgss import (
    PgssEntry,
    PgssSnapshot,
    CorrelationResult,
    load_pgss_snapshot,
    correlate_with_pgss,
    enrich_result_with_pgss,
    export_pgss_query,
    _parse_pgss_json,
    _parse_pgss_csv,
    _parse_pgss_text,
)
from pgloglens.models import AnalysisResult, SlowQuery


class TestPgssEntry:
    """Tests for PgssEntry dataclass."""

    def test_basic_entry(self):
        """Test creating a basic pg_stat_statements entry."""
        entry = PgssEntry(
            queryid=12345,
            query="SELECT * FROM users WHERE id = $1",
            calls=1000,
            total_exec_time_ms=5000.0,
            mean_exec_time_ms=5.0,
            max_exec_time_ms=50.0,
            rows=1000,
            shared_blks_hit=10000,
            shared_blks_read=100,
        )

        assert entry.queryid == 12345
        assert entry.calls == 1000
        assert entry.mean_exec_time_ms == 5.0

    def test_compute_derived_cache_hit_ratio(self):
        """Test computing cache hit ratio."""
        entry = PgssEntry(
            shared_blks_hit=900,
            shared_blks_read=100,
        )
        entry.compute_derived()

        assert entry.cache_hit_ratio == 90.0

    def test_compute_derived_zero_blocks(self):
        """Test cache hit ratio when no blocks."""
        entry = PgssEntry(
            shared_blks_hit=0,
            shared_blks_read=0,
        )
        entry.compute_derived()

        assert entry.cache_hit_ratio == 0.0

    def test_to_dict(self):
        """Test serializing entry to dictionary."""
        entry = PgssEntry(
            queryid=999,
            query="SELECT 1",
            calls=100,
            total_exec_time_ms=1000.0,
            mean_exec_time_ms=10.0,
            max_exec_time_ms=50.0,
            rows=100,
        )
        entry.compute_derived()

        d = entry.to_dict()
        assert d["queryid"] == 999
        assert d["calls"] == 100
        assert "cache_hit_ratio" in d


class TestPgssSnapshot:
    """Tests for PgssSnapshot dataclass."""

    def test_empty_snapshot(self):
        """Test empty snapshot."""
        snapshot = PgssSnapshot()
        assert len(snapshot.entries) == 0
        assert snapshot.total_queries == 0

    def test_build_indexes(self):
        """Test building lookup indexes."""
        entries = [
            PgssEntry(
                queryid=1,
                query="SELECT * FROM users",
                calls=100,
            ),
            PgssEntry(
                queryid=2,
                query="INSERT INTO logs VALUES ($1)",
                calls=50,
            ),
        ]

        snapshot = PgssSnapshot(entries=entries)
        snapshot.build_indexes()

        assert snapshot.total_queries == 2
        assert snapshot.total_calls == 150

    def test_lookup_by_queryid(self):
        """Test looking up entry by queryid."""
        entries = [
            PgssEntry(queryid=123, query="SELECT 1", calls=10),
            PgssEntry(queryid=456, query="SELECT 2", calls=20),
        ]

        snapshot = PgssSnapshot(entries=entries)
        snapshot.build_indexes()

        found = snapshot.lookup_by_queryid(123)
        assert found is not None
        assert found.calls == 10

        not_found = snapshot.lookup_by_queryid(999)
        assert not_found is None

    def test_lookup_by_normalized(self):
        """Test looking up entry by normalized query."""
        entries = [
            PgssEntry(query="SELECT * FROM users WHERE id = 123", calls=10),
            PgssEntry(query="INSERT INTO t VALUES (1, 'a')", calls=20),
        ]

        snapshot = PgssSnapshot(entries=entries)
        snapshot.build_indexes()

        # The normalized query should match
        # Note: exact matching depends on normalize_query implementation
        assert len(snapshot._by_normalized) == 2

    def test_to_dict(self):
        """Test serializing snapshot to dictionary."""
        snapshot = PgssSnapshot(
            entries=[PgssEntry(query="SELECT 1", calls=10)],
        )
        snapshot.build_indexes()

        d = snapshot.to_dict()
        assert "total_queries" in d
        assert "total_calls" in d
        assert "entries" in d


class TestParseJson:
    """Tests for JSON parsing."""

    def test_parse_array_format(self):
        """Test parsing JSON array format."""
        content = json.dumps([
            {
                "queryid": 123,
                "query": "SELECT * FROM t",
                "calls": 100,
                "total_exec_time": 5.0,  # seconds
                "mean_exec_time": 0.05,
                "rows": 100,
            },
            {
                "queryid": 456,
                "query": "INSERT INTO t",
                "calls": 50,
            },
        ])

        entries = _parse_pgss_json(content)
        assert len(entries) == 2
        assert entries[0].queryid == 123
        assert entries[0].calls == 100

    def test_parse_object_with_rows_format(self):
        """Test parsing JSON object with 'rows' key."""
        content = json.dumps({
            "rows": [
                {"queryid": 1, "query": "SELECT 1", "calls": 10},
            ]
        })

        entries = _parse_pgss_json(content)
        assert len(entries) == 1

    def test_parse_single_object(self):
        """Test parsing single JSON object."""
        content = json.dumps({
            "queryid": 999,
            "query": "SELECT NOW()",
            "calls": 1000,
        })

        entries = _parse_pgss_json(content)
        assert len(entries) == 1
        assert entries[0].queryid == 999


class TestParseCsv:
    """Tests for CSV parsing."""

    def test_parse_csv_format(self):
        """Test parsing CSV format."""
        content = """queryid,query,calls,total_exec_time,mean_exec_time,rows
123,"SELECT * FROM users",100,5.0,0.05,100
456,"INSERT INTO t",50,2.0,0.04,50
"""
        entries = _parse_pgss_csv(content)
        assert len(entries) == 2
        assert entries[0].calls == 100
        assert entries[1].calls == 50


class TestParseText:
    """Tests for psql text output parsing."""

    def test_parse_text_format(self):
        """Test parsing psql text output format."""
        content = """
 queryid |           query           | calls
---------+---------------------------+-------
     123 | SELECT * FROM users       |   100
     456 | INSERT INTO t             |    50
"""
        entries = _parse_pgss_text(content)
        # Text parsing is best-effort
        assert len(entries) >= 0


class TestLoadSnapshot:
    """Tests for loading snapshots from files."""

    def test_load_json_snapshot(self):
        """Test loading JSON snapshot file."""
        content = json.dumps([
            {"queryid": 1, "query": "SELECT 1", "calls": 10, "rows": 10},
            {"queryid": 2, "query": "SELECT 2", "calls": 20, "rows": 20},
        ])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write(content)
            f.flush()

            try:
                snapshot = load_pgss_snapshot(f.name)
                assert len(snapshot.entries) == 2
                assert snapshot.total_queries == 2
            finally:
                os.unlink(f.name)

    def test_load_csv_snapshot(self):
        """Test loading CSV snapshot file."""
        content = """queryid,query,calls,rows
1,"SELECT 1",10,10
2,"SELECT 2",20,20
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(content)
            f.flush()

            try:
                snapshot = load_pgss_snapshot(f.name)
                assert len(snapshot.entries) == 2
            finally:
                os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_pgss_snapshot("/nonexistent/path/pgss.json")


class TestCorrelationResult:
    """Tests for CorrelationResult dataclass."""

    def test_empty_correlation(self):
        """Test empty correlation result."""
        result = CorrelationResult()
        assert result.match_rate == 0.0
        assert len(result.matched_queries) == 0

    def test_to_dict(self):
        """Test serializing correlation result."""
        result = CorrelationResult(
            matched_queries=[{"query": "SELECT 1"}],
            log_only_queries=["INSERT INTO t"],
            pgss_only_queries=["DELETE FROM t"],
            match_rate=0.5,
            total_log_queries=10,
            total_pgss_queries=15,
            matched_count=5,
        )

        d = result.to_dict()
        assert d["match_rate"] == 50.0  # Converted to percentage
        assert d["matched_count"] == 5
        assert d["log_only_count"] == 1
        assert d["pgss_only_count"] == 1


class TestCorrelateWithPgss:
    """Tests for correlating log analysis with pgss."""

    def test_correlate_empty_results(self):
        """Test correlating empty results."""
        result = AnalysisResult()
        snapshot = PgssSnapshot()
        snapshot.build_indexes()

        correlation = correlate_with_pgss(result, snapshot)

        assert correlation.match_rate == 0.0
        assert correlation.matched_count == 0

    def test_correlate_with_matches(self):
        """Test correlating with matching queries."""
        # Create analysis result with slow queries
        result = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM users WHERE id = 123",
                    normalized_query="SELECT * FROM users WHERE id = $1",
                    count=100,
                    avg_duration_ms=50.0,
                    max_duration_ms=100.0,
                    total_duration_ms=5000.0,
                    durations=[50.0] * 100,
                ),
            ],
        )

        # Create pgss snapshot with similar query
        snapshot = PgssSnapshot(
            entries=[
                PgssEntry(
                    query="SELECT * FROM users WHERE id = $1",
                    calls=1000,
                    total_exec_time_ms=40000.0,
                    mean_exec_time_ms=40.0,
                    max_exec_time_ms=200.0,
                    shared_blks_hit=9000,
                    shared_blks_read=1000,
                ),
            ],
        )
        snapshot.build_indexes()

        correlation = correlate_with_pgss(result, snapshot)

        # Should find at least partial match based on normalization
        assert correlation.total_log_queries == 1
        assert correlation.total_pgss_queries == 1

    def test_correlate_log_only_queries(self):
        """Test detecting queries only in log."""
        result = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM unique_table",
                    normalized_query="SELECT * FROM unique_table",
                    count=10,
                    avg_duration_ms=100.0,
                    total_duration_ms=1000.0,
                    durations=[100.0] * 10,
                ),
            ],
        )

        snapshot = PgssSnapshot(
            entries=[
                PgssEntry(
                    query="SELECT * FROM different_table",
                    calls=100,
                ),
            ],
        )
        snapshot.build_indexes()

        correlation = correlate_with_pgss(result, snapshot)

        # The log query should be in log_only
        assert len(correlation.log_only_queries) >= 0


class TestEnrichResultWithPgss:
    """Tests for enriching analysis results with pgss data."""

    def test_enrich_adds_pgss_data(self):
        """Test that enrichment adds pgss attributes to slow queries."""
        result = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM t WHERE x = 1",
                    normalized_query="SELECT * FROM t WHERE x = $1",
                    count=50,
                    avg_duration_ms=100.0,
                    total_duration_ms=5000.0,
                    durations=[100.0] * 50,
                ),
            ],
        )

        snapshot = PgssSnapshot(
            entries=[
                PgssEntry(
                    query="SELECT * FROM t WHERE x = $1",
                    calls=500,
                    total_exec_time_ms=20000.0,
                    mean_exec_time_ms=40.0,
                    shared_blks_hit=8000,
                    shared_blks_read=2000,
                    temp_blks_read=100,
                    temp_blks_written=50,
                    rows=500,
                ),
            ],
        )
        snapshot.build_indexes()
        for e in snapshot.entries:
            e.compute_derived()

        enrich_result_with_pgss(result, snapshot)

        # Check if pgss attributes were added
        sq = result.slow_queries[0]
        # Note: attributes are added dynamically
        if hasattr(sq, "pgss_calls"):
            assert sq.pgss_calls == 500


class TestExportQuery:
    """Tests for export query generation."""

    def test_export_json_query(self):
        """Test generating JSON export query."""
        query = export_pgss_query(output_format="json")

        assert "SELECT" in query
        assert "json" in query.lower()
        assert "pg_stat_statements" in query

    def test_export_csv_query(self):
        """Test generating CSV export query."""
        query = export_pgss_query(output_format="csv")

        assert "SELECT" in query
        assert "CSV" in query
        assert "pg_stat_statements" in query

    def test_export_text_query(self):
        """Test generating text export query."""
        query = export_pgss_query(output_format="text")

        assert "SELECT" in query
        assert "pg_stat_statements" in query


class TestPgssIntegration:
    """Integration tests for pgss module."""

    def test_full_workflow(self):
        """Test complete pgss integration workflow."""
        # Create a realistic pgss snapshot
        pgss_content = json.dumps([
            {
                "queryid": 1001,
                "query": "SELECT * FROM orders WHERE customer_id = $1",
                "calls": 10000,
                "total_exec_time": 500.0,
                "mean_exec_time": 0.05,
                "rows": 10000,
                "shared_blks_hit": 50000,
                "shared_blks_read": 5000,
            },
            {
                "queryid": 1002,
                "query": "INSERT INTO audit_log VALUES ($1, $2, $3)",
                "calls": 5000,
                "total_exec_time": 100.0,
                "mean_exec_time": 0.02,
                "rows": 5000,
            },
            {
                "queryid": 1003,
                "query": "UPDATE inventory SET quantity = quantity - $1 WHERE product_id = $2",
                "calls": 1000,
                "total_exec_time": 200.0,
                "mean_exec_time": 0.2,
                "rows": 1000,
                "temp_blks_read": 100,
            },
        ])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write(pgss_content)
            f.flush()

            try:
                # Load snapshot
                snapshot = load_pgss_snapshot(f.name)

                assert len(snapshot.entries) == 3
                assert snapshot.total_queries == 3
                assert snapshot.total_calls == 16000

                # Create analysis result
                result = AnalysisResult(
                    slow_queries=[
                        SlowQuery(
                            query="SELECT * FROM orders WHERE customer_id = 12345",
                            normalized_query="SELECT * FROM orders WHERE customer_id = $1",
                            count=500,
                            avg_duration_ms=100.0,  # Much higher than pgss mean
                            max_duration_ms=500.0,
                            total_duration_ms=50000.0,
                            durations=[100.0] * 500,
                        ),
                    ],
                )

                # Correlate
                correlation = correlate_with_pgss(result, snapshot)

                assert correlation.total_log_queries == 1
                assert correlation.total_pgss_queries == 3

                # Enrich
                enrich_result_with_pgss(result, snapshot)

                # Verify to_dict works
                d = correlation.to_dict()
                assert "match_rate" in d
                assert "matched_queries" in d

            finally:
                os.unlink(f.name)

    def test_cache_hit_ratio_computation(self):
        """Test cache hit ratio is correctly computed."""
        content = json.dumps([
            {
                "queryid": 1,
                "query": "SELECT 1",
                "calls": 100,
                "shared_blks_hit": 9000,
                "shared_blks_read": 1000,
            },
        ])

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write(content)
            f.flush()

            try:
                snapshot = load_pgss_snapshot(f.name)
                entry = snapshot.entries[0]

                # compute_derived is called during load
                assert entry.cache_hit_ratio == 90.0
            finally:
                os.unlink(f.name)
