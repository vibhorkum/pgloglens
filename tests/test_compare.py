"""Tests for pgloglens compare (diff) module."""

import json
import os
import tempfile
import pytest
from datetime import datetime, timedelta

from pgloglens.compare import (
    QueryDiff,
    ErrorDiff,
    ComparisonResult,
    compare_results,
    save_analysis_artifact,
    load_analysis_artifact,
    render_comparison_text,
    render_comparison_markdown,
)
from pgloglens.models import (
    AnalysisResult,
    SlowQuery,
    ErrorPattern,
    RCAFinding,
    Severity,
)


class TestQueryDiff:
    """Tests for QueryDiff dataclass."""

    def test_basic_query_diff(self):
        """Test creating a basic query diff."""
        diff = QueryDiff(
            normalized_query="SELECT * FROM users WHERE id = $1",
            before_count=100,
            after_count=150,
            before_avg_ms=50.0,
            after_avg_ms=75.0,
        )
        diff.compute_deltas()

        assert diff.before_count == 100
        assert diff.after_count == 150
        assert diff.count_delta == 50

    def test_new_query_diff(self):
        """Test query diff for a new query."""
        diff = QueryDiff(
            normalized_query="INSERT INTO logs VALUES ($1)",
            before_count=None,
            after_count=500,
            after_avg_ms=10.0,
        )
        diff.compute_deltas()

        assert diff.status == "new"
        assert diff.before_count is None

    def test_disappeared_query_diff(self):
        """Test query diff for a disappeared query."""
        diff = QueryDiff(
            normalized_query="DELETE FROM old_table",
            before_count=200,
            before_avg_ms=30.0,
            after_count=None,
        )
        diff.compute_deltas()

        assert diff.status == "disappeared"
        assert diff.after_count is None

    def test_to_dict(self):
        """Test serializing query diff to dictionary."""
        diff = QueryDiff(
            normalized_query="SELECT 1",
            before_count=10,
            after_count=20,
            before_avg_ms=5.0,
            after_avg_ms=10.0,
        )
        diff.compute_deltas()
        d = diff.to_dict()

        assert d["normalized_query"] == "SELECT 1"
        assert "before" in d
        assert "after" in d
        assert "deltas" in d


class TestErrorDiff:
    """Tests for ErrorDiff dataclass."""

    def test_basic_error_diff(self):
        """Test creating a basic error diff."""
        diff = ErrorDiff(
            message_pattern="connection refused",
            category="connection",
            before_count=50,
            after_count=10,
        )
        diff.compute_deltas()

        assert diff.before_count == 50
        assert diff.count_delta == -40  # Decreased

    def test_new_error_diff(self):
        """Test error diff for a new error pattern."""
        diff = ErrorDiff(
            message_pattern="deadlock detected",
            category="lock",
            before_count=None,
            after_count=5,
        )
        diff.compute_deltas()

        assert diff.status == "new"

    def test_disappeared_error_diff(self):
        """Test error diff for a disappeared error."""
        diff = ErrorDiff(
            message_pattern="disk full",
            category="disk",
            before_count=100,
            after_count=None,
        )
        diff.compute_deltas()

        assert diff.status == "disappeared"


class TestComparisonResult:
    """Tests for ComparisonResult dataclass."""

    def test_empty_comparison(self):
        """Test empty comparison result."""
        result = ComparisonResult(
            before_label="baseline",
            after_label="current",
        )

        summary = result.summary()
        assert "queries" in summary
        assert "errors" in summary

    def test_to_dict(self):
        """Test serializing comparison result."""
        result = ComparisonResult(
            before_label="before",
            after_label="after",
        )

        d = result.to_dict()
        # Labels are nested under metadata
        assert d["metadata"]["before_label"] == "before"
        assert d["metadata"]["after_label"] == "after"
        # Query and error diffs are categorized
        assert "queries" in d
        assert "errors" in d
        assert "summary" in d


class TestCompareResults:
    """Tests for the compare_results function."""

    def test_compare_empty_results(self):
        """Test comparing two empty analysis results."""
        before = AnalysisResult()
        after = AnalysisResult()

        comparison = compare_results(before, after)

        assert isinstance(comparison, ComparisonResult)
        assert len(comparison.query_diffs) == 0
        assert len(comparison.error_diffs) == 0

    def test_compare_with_labels(self):
        """Test comparison with custom labels."""
        before = AnalysisResult()
        after = AnalysisResult()

        comparison = compare_results(
            before, after,
            before_label="production-baseline",
            after_label="staging-test",
        )

        assert comparison.before_label == "production-baseline"
        assert comparison.after_label == "staging-test"

    def test_compare_with_slow_queries(self):
        """Test comparing results with slow queries."""
        before = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM users WHERE email = 'test@test.com'",
                    normalized_query="SELECT * FROM users WHERE email = $1",
                    count=100,
                    total_duration_ms=5000.0,
                    avg_duration_ms=50.0,
                    max_duration_ms=100.0,
                    durations=[50.0] * 100,
                ),
            ],
        )

        after = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM users WHERE email = 'new@test.com'",
                    normalized_query="SELECT * FROM users WHERE email = $1",
                    count=200,
                    total_duration_ms=20000.0,
                    avg_duration_ms=100.0,
                    max_duration_ms=200.0,
                    durations=[100.0] * 200,
                ),
                SlowQuery(
                    query="INSERT INTO logs VALUES (1, 'test')",
                    normalized_query="INSERT INTO logs VALUES ($1, $2)",
                    count=50,
                    total_duration_ms=500.0,
                    avg_duration_ms=10.0,
                    max_duration_ms=20.0,
                    durations=[10.0] * 50,
                ),
            ],
        )

        comparison = compare_results(before, after)
        assert len(comparison.query_diffs) >= 1

    def test_compare_with_errors(self):
        """Test comparing results with error patterns."""
        before = AnalysisResult(
            error_patterns=[
                ErrorPattern(
                    error_code="23505",
                    message_pattern="duplicate key",
                    category="constraint",
                    count=50,
                ),
            ],
        )

        after = AnalysisResult(
            error_patterns=[
                ErrorPattern(
                    error_code="23505",
                    message_pattern="duplicate key",
                    category="constraint",
                    count=10,
                ),
                ErrorPattern(
                    error_code="57014",
                    message_pattern="canceling statement due to timeout",
                    category="query",
                    count=25,
                ),
            ],
        )

        comparison = compare_results(before, after)
        assert len(comparison.error_diffs) >= 1


class TestArtifactSaveLoad:
    """Tests for saving and loading analysis artifacts."""

    def test_save_and_load_artifact(self):
        """Test saving and loading an analysis artifact."""
        result = AnalysisResult(
            log_file_paths=["test.log"],
            total_entries=1000,
            slow_queries=[
                SlowQuery(
                    query="SELECT 1",
                    normalized_query="SELECT $1",
                    count=10,
                    total_duration_ms=100.0,
                    avg_duration_ms=10.0,
                    max_duration_ms=20.0,
                    durations=[10.0] * 10,
                ),
            ],
            error_patterns=[
                ErrorPattern(message_pattern="test error", count=5),
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "artifact.json")

            # Save
            save_analysis_artifact(result, path, label="test-artifact")

            # Verify file exists
            assert os.path.exists(path)

            # Load
            loaded_result, metadata = load_analysis_artifact(path)

            # Verify
            assert metadata["label"] == "test-artifact"
            assert loaded_result.total_entries == 1000

    def test_artifact_has_version_and_label(self):
        """Test that artifact contains version and label."""
        result = AnalysisResult()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "artifact.json")
            save_analysis_artifact(result, path, label="my-label")

            # Read raw JSON
            with open(path) as f:
                data = json.load(f)

            assert data["label"] == "my-label"
            assert "version" in data
            assert "created_at" in data


class TestComparisonRendering:
    """Tests for comparison rendering functions."""

    def test_render_comparison_text_empty(self):
        """Test rendering empty comparison to text."""
        comparison = ComparisonResult(
            before_label="before",
            after_label="after",
        )

        text = render_comparison_text(comparison)
        assert isinstance(text, str)

    def test_render_comparison_markdown(self):
        """Test rendering comparison to markdown."""
        comparison = ComparisonResult(
            before_label="baseline",
            after_label="current",
        )

        md = render_comparison_markdown(comparison)
        assert "#" in md  # Has headers


class TestCompareIntegration:
    """Integration tests for compare functionality."""

    def test_full_workflow(self):
        """Test complete comparison workflow."""
        now = datetime.now()

        # Create "before" result
        before = AnalysisResult(
            log_file_paths=["before.log"],
            time_range_start=now - timedelta(days=2),
            time_range_end=now - timedelta(days=1),
            total_entries=5000,
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM orders WHERE status = 'pending'",
                    normalized_query="SELECT * FROM orders WHERE status = $1",
                    count=500,
                    total_duration_ms=25000.0,
                    avg_duration_ms=50.0,
                    max_duration_ms=100.0,
                    p95_duration_ms=80.0,
                    durations=[50.0] * 500,
                ),
            ],
            error_patterns=[
                ErrorPattern(
                    message_pattern="connection timeout",
                    category="connection",
                    count=20,
                ),
            ],
        )

        # Create "after" result with some changes
        after = AnalysisResult(
            log_file_paths=["after.log"],
            time_range_start=now - timedelta(days=1),
            time_range_end=now,
            total_entries=8000,
            slow_queries=[
                SlowQuery(
                    query="SELECT * FROM orders WHERE status = 'pending'",
                    normalized_query="SELECT * FROM orders WHERE status = $1",
                    count=800,
                    total_duration_ms=80000.0,
                    avg_duration_ms=100.0,
                    max_duration_ms=300.0,
                    p95_duration_ms=200.0,
                    durations=[100.0] * 800,
                ),
            ],
            error_patterns=[
                ErrorPattern(
                    message_pattern="connection timeout",
                    category="connection",
                    count=5,
                ),
            ],
        )

        # Compare
        comparison = compare_results(
            before, after,
            before_label="production-jan",
            after_label="production-feb",
        )

        # Verify comparison
        assert comparison.before_label == "production-jan"
        assert comparison.after_label == "production-feb"

        # Test rendering
        text = render_comparison_text(comparison)
        assert len(text) > 0

        md = render_comparison_markdown(comparison)
        assert "#" in md

        # Test serialization
        d = comparison.to_dict()
        assert "queries" in d  # Categorized by status: new, disappeared, slower, faster
        assert "errors" in d   # Categorized by status: new, disappeared, increased
        assert "metadata" in d
        assert d["metadata"]["before_label"] == "production-jan"
        assert d["metadata"]["after_label"] == "production-feb"
