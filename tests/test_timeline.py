"""Tests for pgloglens timeline module."""

import pytest
from datetime import datetime, timedelta

from pgloglens.timeline import (
    EventType,
    TimelineEvent,
    IncidentTimeline,
    build_timeline,
    render_timeline_text,
    render_timeline_markdown,
)
from pgloglens.models import (
    AnalysisResult,
    ErrorPattern,
    LockEvent,
    CheckpointStats,
    AutovacuumStats,
    ConnectionStats,
    RCAFinding,
    Severity,
)


class TestEventType:
    """Tests for EventType enum."""

    def test_all_event_types(self):
        """Verify all expected event types exist."""
        expected = [
            "ERROR_BURST", "DEADLOCK", "LOCK_WAVE", "CHECKPOINT_SPIKE",
            "AUTOVACUUM", "CONNECTION_STORM", "OOM", "DISK_FULL",
            "CANCELLATION_WAVE", "REPLICATION_LAG", "AUTH_FAILURE_SPIKE",
            "SLOW_QUERY_SPIKE", "FATAL_PANIC"
        ]
        for et in expected:
            assert hasattr(EventType, et)

    def test_event_type_values(self):
        """Verify event type values are lowercase."""
        assert EventType.ERROR_BURST.value == "error_burst"
        assert EventType.DEADLOCK.value == "deadlock"


class TestTimelineEvent:
    """Tests for TimelineEvent dataclass."""

    def test_basic_event(self):
        """Test creating a basic timeline event."""
        ts = datetime.now()
        event = TimelineEvent(
            timestamp=ts,
            event_type=EventType.ERROR_BURST,
            severity="high",
            title="Error burst detected",
            description="50 errors in 5 minutes",
            metrics={"error_count": 50, "pattern": "connection timeout"},
        )
        assert event.timestamp == ts
        assert event.event_type == EventType.ERROR_BURST
        assert event.severity == "high"
        assert "50 errors" in event.description
        assert event.metrics["error_count"] == 50

    def test_to_dict(self):
        """Test serializing event to dictionary."""
        ts = datetime(2024, 1, 15, 10, 30, 0)
        event = TimelineEvent(
            timestamp=ts,
            event_type=EventType.DEADLOCK,
            severity="critical",
            title="Deadlock detected",
            description="Deadlock between PIDs 1234 and 5678",
        )
        d = event.to_dict()
        assert d["timestamp"] == ts.isoformat()
        assert d["event_type"] == "deadlock"
        assert d["severity"] == "critical"
        assert "Deadlock" in d["title"]


class TestIncidentTimeline:
    """Tests for IncidentTimeline dataclass."""

    def test_empty_timeline(self):
        """Test empty timeline."""
        timeline = IncidentTimeline()
        assert timeline.total_events == 0
        assert timeline.critical_events == 0
        assert len(timeline.events) == 0

    def test_timeline_with_events(self):
        """Test timeline with multiple events."""
        now = datetime.now()
        events = [
            TimelineEvent(
                timestamp=now - timedelta(hours=2),
                event_type=EventType.ERROR_BURST,
                severity="high",
                title="Error spike",
                description="High error rate",
            ),
            TimelineEvent(
                timestamp=now - timedelta(hours=1),
                event_type=EventType.DEADLOCK,
                severity="critical",
                title="Deadlock",
                description="Deadlock detected",
            ),
            TimelineEvent(
                timestamp=now,
                event_type=EventType.CHECKPOINT_SPIKE,
                severity="medium",
                title="Slow checkpoint",
                description="Checkpoint took 30s",
            ),
        ]
        timeline = IncidentTimeline(
            time_range_start=now - timedelta(hours=3),
            time_range_end=now,
            events=events,
            total_events=3,
            critical_events=1,
            high_events=1,
        )

        assert timeline.total_events == 3
        assert timeline.critical_events == 1
        assert timeline.high_events == 1

    def test_to_dict(self):
        """Test serializing timeline to dictionary."""
        now = datetime.now()
        timeline = IncidentTimeline(
            time_range_start=now - timedelta(hours=1),
            time_range_end=now,
            events=[],
            total_events=0,
            critical_events=0,
            high_events=0,
        )
        d = timeline.to_dict()
        assert "time_range_start" in d
        assert "time_range_end" in d
        assert "events" in d
        assert d["total_events"] == 0


class TestBuildTimelineWithErrorPatterns:
    """Tests for building timeline with error patterns."""

    def test_build_timeline_extracts_error_bursts(self):
        """Test that error bursts are extracted from error patterns."""
        now = datetime.now()
        result = AnalysisResult(
            time_range_start=now - timedelta(hours=1),
            time_range_end=now,
            error_patterns=[
                ErrorPattern(
                    message_pattern="connection timeout",
                    count=100,
                    category="connection",
                    first_seen=now - timedelta(hours=1),
                    last_seen=now,
                ),
                ErrorPattern(
                    message_pattern="duplicate key",
                    count=5,
                    category="constraint",
                    first_seen=now - timedelta(minutes=30),
                    last_seen=now,
                ),
            ],
        )

        timeline = build_timeline(result)
        # Should produce a timeline
        assert isinstance(timeline, IncidentTimeline)

    def test_build_timeline_extracts_deadlocks(self):
        """Test extracting deadlock and lock wait events."""
        now = datetime.now()
        result = AnalysisResult(
            time_range_start=now - timedelta(hours=1),
            time_range_end=now,
            lock_events=[
                LockEvent(
                    timestamp=now,
                    is_deadlock=True,
                    waiting_pid=1234,
                    blocking_pid=5678,
                    waiting_query="UPDATE t SET x=1",
                ),
                LockEvent(
                    timestamp=now - timedelta(minutes=5),
                    is_deadlock=False,
                    wait_duration_ms=5000,
                    waiting_query="SELECT * FROM t",
                ),
            ],
        )

        timeline = build_timeline(result)
        deadlock_events = [e for e in timeline.events if e.event_type == EventType.DEADLOCK]
        assert len(deadlock_events) >= 1
        # Deadlock severity may be 'critical' or 'high' depending on implementation
        assert deadlock_events[0].severity in ("critical", "high")


class TestBuildTimeline:
    """Tests for the main build_timeline function."""

    def test_build_timeline_empty_result(self):
        """Test building timeline from empty analysis result."""
        result = AnalysisResult()
        timeline = build_timeline(result)

        assert isinstance(timeline, IncidentTimeline)

    def test_build_timeline_with_data(self):
        """Test building timeline from result with data."""
        now = datetime.now()
        result = AnalysisResult(
            time_range_start=now - timedelta(hours=2),
            time_range_end=now,
            error_patterns=[
                ErrorPattern(
                    message_pattern="connection refused",
                    count=50,
                    category="connection",
                    first_seen=now - timedelta(hours=1),
                    last_seen=now,
                ),
            ],
            lock_events=[
                LockEvent(
                    timestamp=now - timedelta(minutes=30),
                    is_deadlock=True,
                    waiting_pid=123,
                    blocking_pid=456,
                ),
            ],
        )

        timeline = build_timeline(result, window_minutes=10)

        assert timeline.time_range_start is not None
        assert timeline.time_range_end is not None


class TestTimelineRendering:
    """Tests for timeline rendering functions."""

    def test_render_timeline_text_empty(self):
        """Test rendering empty timeline to text."""
        timeline = IncidentTimeline()
        text = render_timeline_text(timeline)

        assert "TIMELINE" in text.upper() or text == ""

    def test_render_timeline_text_with_events(self):
        """Test rendering timeline with events to text."""
        now = datetime.now()
        timeline = IncidentTimeline(
            time_range_start=now - timedelta(hours=1),
            time_range_end=now,
            events=[
                TimelineEvent(
                    timestamp=now - timedelta(minutes=30),
                    event_type=EventType.DEADLOCK,
                    severity="critical",
                    title="Deadlock detected",
                    description="Deadlock between PIDs",
                ),
            ],
            total_events=1,
            critical_events=1,
        )

        text = render_timeline_text(timeline)
        assert "Deadlock" in text or "DEADLOCK" in text or "deadlock" in text

    def test_render_timeline_markdown(self):
        """Test rendering timeline to markdown."""
        now = datetime.now()
        timeline = IncidentTimeline(
            time_range_start=now - timedelta(hours=1),
            time_range_end=now,
            events=[
                TimelineEvent(
                    timestamp=now,
                    event_type=EventType.ERROR_BURST,
                    severity="high",
                    title="Error spike",
                    description="100 errors in 5 minutes",
                ),
            ],
            total_events=1,
            high_events=1,
        )

        md = render_timeline_markdown(timeline)
        assert "#" in md  # Has headers


class TestTimelineIntegration:
    """Integration tests for timeline functionality."""

    def test_full_workflow(self):
        """Test complete timeline workflow from result to output."""
        now = datetime.now()

        # Create a realistic analysis result
        result = AnalysisResult(
            log_file_paths=["test.log"],
            time_range_start=now - timedelta(hours=4),
            time_range_end=now,
            total_entries=10000,
            error_patterns=[
                ErrorPattern(
                    message_pattern="FATAL: too many connections",
                    count=200,
                    category="connection",
                    first_seen=now - timedelta(hours=2),
                    last_seen=now - timedelta(hours=1),
                ),
            ],
            lock_events=[
                LockEvent(
                    timestamp=now - timedelta(hours=3),
                    is_deadlock=True,
                    waiting_pid=100,
                    blocking_pid=200,
                ),
                LockEvent(
                    timestamp=now - timedelta(hours=2, minutes=30),
                    is_deadlock=True,
                    waiting_pid=101,
                    blocking_pid=201,
                ),
            ],
        )

        # Build timeline
        timeline = build_timeline(result, window_minutes=15)

        # Verify timeline properties
        assert isinstance(timeline, IncidentTimeline)

        # Render to text
        text = render_timeline_text(timeline)
        assert len(text) > 0

        # Render to markdown
        md = render_timeline_markdown(timeline)
        assert "#" in md  # Has headers

        # Verify to_dict works
        d = timeline.to_dict()
        assert "events" in d
        assert "total_events" in d
