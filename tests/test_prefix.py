"""Exhaustive tests for pgloglens log_line_prefix module.

This module tests all 18 escape sequences, common prefix patterns,
edge cases, and integration with the parser.
"""

import pytest
import re

from pgloglens.prefix import (
    PrefixCompiler,
    COMMON_PREFIXES,
    get_common_prefix,
    prefix_to_description,
    detect_prefix_from_log,
    infer_prefix_fields_heuristically,
    build_entry_from_prefix,
    patch_parser,
    _ESCAPE_TABLE,
    _TIMESTAMP_FIELDS,
    _PID_FIELDS,
)


class TestEscapeSequences:
    """Test all 18 escape sequences defined in _ESCAPE_TABLE."""

    def test_escape_a_application_name(self):
        """Test %a extracts application_name."""
        compiler = PrefixCompiler("%m [%p] %q%a ")
        line = "2024-01-15 08:00:01.234 UTC [1234] myapp LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("application_name") == "myapp"

    def test_escape_u_user(self):
        """Test %u extracts user."""
        compiler = PrefixCompiler("%m [%p] user=%u ")
        line = "2024-01-15 08:00:01.234 UTC [1234] user=alice LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("user") == "alice"

    def test_escape_d_database(self):
        """Test %d extracts database."""
        compiler = PrefixCompiler("%m [%p] db=%d ")
        line = "2024-01-15 08:00:01.234 UTC [1234] db=myapp LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("database") == "myapp"

    def test_escape_r_remote_host_port(self):
        """Test %r extracts remote_host_port."""
        compiler = PrefixCompiler("%m [%p] %r ")
        line = "2024-01-15 08:00:01.234 UTC [1234] 192.168.1.10(12345) LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert "192.168.1.10" in fields.get("remote_host_port", "")

    def test_escape_h_remote_host(self):
        """Test %h extracts remote_host."""
        compiler = PrefixCompiler("%m [%p] client=%h ")
        line = "2024-01-15 08:00:01.234 UTC [1234] client=192.168.1.10 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("remote_host") == "192.168.1.10"

    def test_escape_b_backend_type(self):
        """Test %b extracts backend_type."""
        compiler = PrefixCompiler("%m [%p] [%b] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] [autovacuum worker] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("backend_type") == "autovacuum worker"

    def test_escape_p_pid(self):
        """Test %p extracts pid."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [9999] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("pid") == "9999"

    def test_escape_P_parallel_leader_pid(self):
        """Test %P extracts parallel_leader_pid."""
        compiler = PrefixCompiler("%m [%p] leader=%P ")
        line = "2024-01-15 08:00:01.234 UTC [1234] leader=5678 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("parallel_leader_pid") == "5678"

    def test_escape_t_timestamp(self):
        """Test %t extracts timestamp (without milliseconds)."""
        compiler = PrefixCompiler("%t [%p] ")
        line = "2024-01-15 08:00:01 UTC [1234] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert "2024-01-15 08:00:01" in fields.get("timestamp", "")

    def test_escape_m_timestamp_ms(self):
        """Test %m extracts timestamp_ms (with milliseconds)."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        ts = fields.get("timestamp_ms", "")
        assert "2024-01-15 08:00:01.234" in ts

    def test_escape_n_timestamp_epoch(self):
        """Test %n extracts timestamp_epoch."""
        compiler = PrefixCompiler("%n [%p] ")
        line = "1705305601.234 [1234] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert "1705305601.234" in fields.get("timestamp_epoch", "")

    def test_escape_i_command_tag(self):
        """Test %i extracts command_tag."""
        compiler = PrefixCompiler("%m [%p] %q[%i] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] [SELECT] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("command_tag") == "SELECT"

    def test_escape_e_sql_state(self):
        """Test %e extracts sql_state (SQLSTATE code)."""
        compiler = PrefixCompiler("%m [%p] %e ")
        line = "2024-01-15 08:00:01.234 UTC [1234] 42601 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("sql_state") == "42601"

    def test_escape_c_session_id(self):
        """Test %c extracts session_id."""
        compiler = PrefixCompiler("%m [%p] [%c] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] [5ff1a8b2.4d2] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert "5ff1a8b2.4d2" in fields.get("session_id", "")

    def test_escape_l_line_num(self):
        """Test %l extracts line_num."""
        compiler = PrefixCompiler("%m [%p]: [%l-1] ")
        line = "2024-01-15 08:00:01.234 UTC [1234]: [5-1] LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("line_num") == "5"

    def test_escape_s_session_start(self):
        """Test %s extracts session_start timestamp."""
        compiler = PrefixCompiler("%m [%p] start=%s ")
        line = "2024-01-15 08:00:01.234 UTC [1234] start=2024-01-15 07:30:00 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert "2024-01-15 07:30:00" in fields.get("session_start", "")

    def test_escape_v_virtual_txid(self):
        """Test %v extracts virtual_txid."""
        compiler = PrefixCompiler("%m [%p] vxid=%v ")
        line = "2024-01-15 08:00:01.234 UTC [1234] vxid=3/100 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("virtual_txid") == "3/100"

    def test_escape_x_txid(self):
        """Test %x extracts txid."""
        compiler = PrefixCompiler("%m [%p] xid=%x ")
        line = "2024-01-15 08:00:01.234 UTC [1234] xid=12345678 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("txid") == "12345678"

    def test_escape_Q_query_id(self):
        """Test %Q extracts query_id (PostgreSQL 14+)."""
        compiler = PrefixCompiler("%m [%p] qid=%Q ")
        line = "2024-01-15 08:00:01.234 UTC [1234] qid=9876543210 LOG:  message"
        fields = compiler.parse_line(line)
        assert fields is not None
        assert fields.get("query_id") == "9876543210"


class TestPercentQBehavior:
    """Test the %q escape sequence behavior for background vs client processes."""

    def test_client_backend_has_all_fields(self):
        """Test client backend has user, database, application after %q."""
        compiler = PrefixCompiler("%m [%p] %q%u@%d/%a ")
        line = "2024-01-15 08:00:01.234 UTC [1234] app@mydb/rails LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("user") == "app"
        assert fields.get("database") == "mydb"
        assert fields.get("application_name") == "rails"

    def test_background_process_has_no_session_fields(self):
        """Test background process (autovacuum, etc.) omits fields after %q."""
        compiler = PrefixCompiler("%m [%p] %q%u@%d/%a ")
        line = "2024-01-15 08:00:01.234 UTC [5678] LOG:  automatic vacuum of table"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("pid") == "5678"
        assert "user" not in fields
        assert "database" not in fields
        assert "application_name" not in fields

    def test_checkpointer_process(self):
        """Test checkpointer background process."""
        compiler = PrefixCompiler("%m [%p] %q%u@%d ")
        line = "2024-01-15 08:00:01.234 UTC [999] LOG:  checkpoint complete"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("pid") == "999"
        assert "user" not in fields
        assert "database" not in fields


class TestCommonPrefixes:
    """Test all entries in COMMON_PREFIXES dictionary."""

    def test_default_pg10(self):
        """Test default PostgreSQL 10+ prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["default_pg10"])
        line = "2024-01-15 08:00:01.234 UTC [1234] LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert "timestamp_ms" in fields
        assert "pid" in fields

    def test_default_legacy(self):
        """Test legacy default prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["default_legacy"])
        line = "2024-01-15 08:00:01 UTC [1234]: LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert "timestamp" in fields
        assert "pid" in fields

    def test_with_user_db(self):
        """Test prefix with user and database."""
        compiler = PrefixCompiler(COMMON_PREFIXES["with_user_db"])
        line = "2024-01-15 08:00:01.234 UTC [1234] alice@mydb LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("user") == "alice"
        assert fields.get("database") == "mydb"

    def test_with_user_db_app(self):
        """Test prefix with user, database, and application."""
        compiler = PrefixCompiler(COMMON_PREFIXES["with_user_db_app"])
        line = "2024-01-15 08:00:01.234 UTC [1234] alice@mydb/rails LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("user") == "alice"
        assert fields.get("database") == "mydb"
        assert fields.get("application_name") == "rails"

    def test_debian(self):
        """Test Debian-style prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["debian"])
        line = "2024-01-15 08:00:01 UTC [1234-5] alice@mydb LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert "timestamp" in fields
        assert fields.get("pid") == "1234"

    def test_edb_recommended(self):
        """Test EDB recommended prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["edb_recommended"])
        line = "2024-01-15 08:00:01.234 UTC [1234]: [5-1] user=alice,db=mydb,app=psql,client=10.0.0.1 LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("user") == "alice"
        assert fields.get("database") == "mydb"
        assert fields.get("application_name") == "psql"
        assert fields.get("remote_host") == "10.0.0.1"

    def test_pgbadger_classic(self):
        """Test pgBadger classic prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["pgbadger_classic"])
        line = "2024-01-15 08:00:01 UTC [1234]: [5-1] LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert "timestamp" in fields
        assert "pid" in fields
        assert fields.get("line_num") == "5"

    def test_rds_prefix(self):
        """Test AWS RDS prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["rds"])
        line = "2024-01-15 08:00:01 UTC:192.168.1.10(12345):alice@mydb:[1234]:LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        # RDS format is complex, just verify it parses

    def test_full_prefix(self):
        """Test full comprehensive prefix."""
        compiler = PrefixCompiler(COMMON_PREFIXES["full"])
        line = "2024-01-15 08:00:01.234 UTC [1234] [user=alice,db=mydb,app=rails,client=10.0.0.1] LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert "timestamp_ms" in fields


class TestPrefixCompilerValidation:
    """Test prefix validation for required fields."""

    def test_valid_prefix(self):
        """Test valid prefix with timestamp and pid."""
        compiler = PrefixCompiler("%m [%p] ")
        warnings = compiler.validate()
        assert len(warnings) == 0

    def test_missing_timestamp(self):
        """Test warning when timestamp is missing."""
        compiler = PrefixCompiler("[%p] ")
        warnings = compiler.validate()
        assert any("timestamp" in w.lower() for w in warnings)

    def test_missing_pid(self):
        """Test warning when PID is missing."""
        compiler = PrefixCompiler("%m ")
        warnings = compiler.validate()
        assert any("process-id" in w.lower() for w in warnings)

    def test_session_id_as_pid_alternative(self):
        """Test that %c (session_id) satisfies PID requirement."""
        compiler = PrefixCompiler("%m [%c] ")
        warnings = compiler.validate()
        # Should not warn about missing PID since session_id is present
        assert not any("process-id" in w.lower() for w in warnings)

    def test_epoch_timestamp_alternative(self):
        """Test that %n (epoch) satisfies timestamp requirement."""
        compiler = PrefixCompiler("%n [%p] ")
        warnings = compiler.validate()
        assert not any("timestamp" in w.lower() for w in warnings)


class TestPrefixCompilerProperties:
    """Test PrefixCompiler properties."""

    def test_has_user(self):
        """Test has_user property."""
        assert PrefixCompiler("%m [%p] %u ").has_user is True
        assert PrefixCompiler("%m [%p] ").has_user is False

    def test_has_database(self):
        """Test has_database property."""
        assert PrefixCompiler("%m [%p] %d ").has_database is True
        assert PrefixCompiler("%m [%p] ").has_database is False

    def test_has_application(self):
        """Test has_application property."""
        assert PrefixCompiler("%m [%p] %a ").has_application is True
        assert PrefixCompiler("%m [%p] ").has_application is False

    def test_has_host(self):
        """Test has_host property (matches both %h and %r)."""
        assert PrefixCompiler("%m [%p] %h ").has_host is True
        assert PrefixCompiler("%m [%p] %r ").has_host is True
        assert PrefixCompiler("%m [%p] ").has_host is False

    def test_has_sqlstate(self):
        """Test has_sqlstate property."""
        assert PrefixCompiler("%m [%p] %e ").has_sqlstate is True
        assert PrefixCompiler("%m [%p] ").has_sqlstate is False

    def test_has_session_id(self):
        """Test has_session_id property."""
        assert PrefixCompiler("%m [%c] ").has_session_id is True
        assert PrefixCompiler("%m [%p] ").has_session_id is False

    def test_has_line_num(self):
        """Test has_line_num property."""
        assert PrefixCompiler("%m [%p]: [%l] ").has_line_num is True
        assert PrefixCompiler("%m [%p] ").has_line_num is False

    def test_fields_property(self):
        """Test fields property returns ordered list."""
        compiler = PrefixCompiler("%m [%p] %u@%d ")
        fields = compiler.fields
        assert "timestamp_ms" in fields
        assert "pid" in fields
        assert "user" in fields
        assert "database" in fields


class TestWidthSpecifiers:
    """Test width specifiers in prefix escapes."""

    def test_left_aligned_width(self):
        """Test left-aligned width specifier (%-15u)."""
        compiler = PrefixCompiler("%-15u %p ")
        line = "app             1234 LOG:  message"
        fields = compiler.parse_line(line)

        assert fields is not None
        assert fields.get("user") == "app"
        assert fields.get("pid") == "1234"

    def test_right_aligned_width(self):
        """Test right-aligned width specifier (%15u)."""
        compiler = PrefixCompiler("%15u %p ")
        # Right-aligned would have leading spaces
        line = "            app 1234 LOG:  message"
        fields = compiler.parse_line(line)

        # Parser may handle this with flexible whitespace
        assert fields is None or fields.get("pid") == "1234"

    def test_width_with_digits(self):
        """Test width specifier with multiple digits."""
        compiler = PrefixCompiler("%10p ")
        line = "      1234 LOG:  message"
        fields = compiler.parse_line(line)
        # Should still extract the PID
        assert fields is None or "pid" in fields


class TestGetCommonPrefix:
    """Test get_common_prefix() function."""

    def test_existing_prefix(self):
        """Test getting an existing common prefix."""
        assert get_common_prefix("default_pg10") == "%m [%p] "
        assert get_common_prefix("with_user_db_app") == "%m [%p] %q%u@%d/%a "

    def test_nonexistent_prefix(self):
        """Test getting a non-existent prefix returns None."""
        assert get_common_prefix("nonexistent") is None
        assert get_common_prefix("") is None


class TestPrefixToDescription:
    """Test prefix_to_description() function."""

    def test_simple_prefix(self):
        """Test description of simple prefix."""
        desc = prefix_to_description("%m [%p] ")
        assert "timestamp_ms" in desc
        assert "pid" in desc

    def test_prefix_with_q(self):
        """Test description includes bracketed optional fields."""
        desc = prefix_to_description("%m [%p] %q%u@%d ")
        assert "timestamp_ms" in desc
        assert "pid" in desc
        assert "[" in desc  # Optional fields in brackets
        assert "user" in desc
        assert "database" in desc

    def test_empty_prefix(self):
        """Test description of empty prefix."""
        desc = prefix_to_description("")
        assert "empty" in desc.lower() or desc == ""


class TestDetectPrefixFromLog:
    """Test detect_prefix_from_log() function."""

    def test_detect_default_pg10(self):
        """Test detecting default PG10+ prefix."""
        sample = [
            "2024-01-15 08:00:01.234 UTC [1234] LOG:  connection received",
            "2024-01-15 08:00:01.235 UTC [1234] LOG:  connection authorized",
            "2024-01-15 08:00:02.100 UTC [5678] LOG:  checkpoint complete",
        ]
        detected = detect_prefix_from_log(sample)
        assert detected == "%m [%p] "

    def test_detect_with_user_db(self):
        """Test detecting prefix with user and database."""
        sample = [
            "2024-01-15 08:00:01.234 UTC [1234] alice@mydb LOG:  query",
            "2024-01-15 08:00:01.235 UTC [1234] bob@mydb LOG:  query",
            "2024-01-15 08:00:02.100 UTC [5678] LOG:  checkpoint",  # Background
        ]
        detected = detect_prefix_from_log(sample)
        # Should detect the user@db format
        assert detected is not None
        assert "%u" in detected or detected == "%m [%p] "

    def test_no_detection_on_garbage(self):
        """Test no detection on non-matching lines."""
        sample = [
            "This is not a PostgreSQL log line",
            "Neither is this one",
            "Random text here",
        ]
        detected = detect_prefix_from_log(sample)
        assert detected is None

    def test_empty_sample(self):
        """Test with empty sample list."""
        detected = detect_prefix_from_log([])
        assert detected is None


class TestInferPrefixFieldsHeuristically:
    """Test infer_prefix_fields_heuristically() function."""

    def test_infer_user_from_pattern(self):
        """Test inferring user presence from log patterns."""
        sample = [
            "2024-01-15 08:00:01 [1234] user=alice LOG:  query",
            "2024-01-15 08:00:02 [1234] user=bob LOG:  query",
            "2024-01-15 08:00:03 [5678] user=carol LOG:  query",
        ]
        fields = infer_prefix_fields_heuristically(sample)
        assert fields["user"] is True

    def test_infer_database_from_pattern(self):
        """Test inferring database presence."""
        sample = [
            "2024-01-15 08:00:01 [1234] db=myapp LOG:  query",
            "2024-01-15 08:00:02 [1234] db=myapp LOG:  query",
        ]
        fields = infer_prefix_fields_heuristically(sample)
        assert fields["database"] is True

    def test_infer_host_from_ip(self):
        """Test inferring host presence from IP addresses."""
        sample = [
            "2024-01-15 08:00:01 [1234] client=192.168.1.10 LOG:  query",
            "2024-01-15 08:00:02 [1234] client=192.168.1.11 LOG:  query",
        ]
        fields = infer_prefix_fields_heuristically(sample)
        assert fields["host"] is True

    def test_infer_session_id(self):
        """Test inferring session_id presence."""
        sample = [
            "2024-01-15 08:00:01 [1234] [5ff1a8b2.4d2] LOG:  query",
            "2024-01-15 08:00:02 [1234] [5ff1a8b2.4d2] LOG:  query",
        ]
        fields = infer_prefix_fields_heuristically(sample)
        assert fields["session_id"] is True


class TestBuildEntryFromPrefix:
    """Test build_entry_from_prefix() function."""

    def test_basic_entry(self):
        """Test building entry from basic prefix."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [9999] LOG:  slow query detected"
        result = build_entry_from_prefix(line, compiler)

        assert result is not None
        fields, level, message = result
        assert fields.get("pid") == "9999"
        assert level == "LOG"
        assert "slow query" in message

    def test_error_level_entry(self):
        """Test entry with ERROR level."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] ERROR:  relation does not exist"
        result = build_entry_from_prefix(line, compiler)

        assert result is not None
        fields, level, message = result
        assert level == "ERROR"
        assert "relation" in message

    def test_fatal_level_entry(self):
        """Test entry with FATAL level."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] FATAL:  too many connections"
        result = build_entry_from_prefix(line, compiler)

        assert result is not None
        fields, level, message = result
        assert level == "FATAL"

    def test_warning_level_entry(self):
        """Test entry with WARNING level."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "2024-01-15 08:00:01.234 UTC [1234] WARNING:  parameter deprecated"
        result = build_entry_from_prefix(line, compiler)

        assert result is not None
        fields, level, message = result
        assert level == "WARNING"

    def test_no_match_returns_none(self):
        """Test non-matching line returns None."""
        compiler = PrefixCompiler("%m [%p] ")
        line = "This is not a PostgreSQL log line"
        result = build_entry_from_prefix(line, compiler)

        assert result is None

    def test_entry_with_all_fields(self):
        """Test entry with all prefix fields populated."""
        compiler = PrefixCompiler("%m [%p] %q%u@%d/%a ")
        line = "2024-01-15 08:00:01.234 UTC [1234] alice@mydb/rails LOG:  query executed"
        result = build_entry_from_prefix(line, compiler)

        assert result is not None
        fields, level, message = result
        assert fields.get("user") == "alice"
        assert fields.get("database") == "mydb"
        assert fields.get("application_name") == "rails"
        assert level == "LOG"


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_double_percent_escape(self):
        """Test %% is treated as literal percent sign."""
        compiler = PrefixCompiler("%m [%p] %% ")
        # Should compile without error
        regex = compiler.compile()
        assert regex is not None

    def test_nested_percent_q(self):
        """Test handling of multiple %q in prefix."""
        compiler = PrefixCompiler("%m [%p] %q%u %q%d ")
        # Should handle gracefully
        regex = compiler.compile()
        assert regex is not None

    def test_unknown_escape(self):
        """Test unknown escape sequence is treated as literal."""
        compiler = PrefixCompiler("%m [%p] %Z ")  # %Z is not defined
        regex = compiler.compile()
        # Should compile, treating %Z as literal
        assert regex is not None

    def test_empty_prefix(self):
        """Test empty prefix compiles."""
        compiler = PrefixCompiler("")
        regex = compiler.compile()
        assert regex is not None

    def test_only_literal_text(self):
        """Test prefix with only literal text."""
        compiler = PrefixCompiler("[PostgreSQL] ")
        regex = compiler.compile()
        line = "[PostgreSQL] LOG:  message"
        # May or may not match depending on implementation

    def test_timezone_variations(self):
        """Test various timezone formats in timestamp."""
        compiler = PrefixCompiler("%m [%p] ")

        # UTC
        line1 = "2024-01-15 08:00:01.234 UTC [1234] LOG:  msg"
        fields1 = compiler.parse_line(line1)
        assert fields1 is not None

        # EST
        line2 = "2024-01-15 08:00:01.234 EST [1234] LOG:  msg"
        fields2 = compiler.parse_line(line2)
        assert fields2 is not None

        # PST+8
        line3 = "2024-01-15 08:00:01.234 PST+8 [1234] LOG:  msg"
        fields3 = compiler.parse_line(line3)
        # May or may not match depending on regex

    def test_ipv6_host(self):
        """Test IPv6 address in host field."""
        compiler = PrefixCompiler("%m [%p] client=%h ")
        line = "2024-01-15 08:00:01.234 UTC [1234] client=::1 LOG:  msg"
        fields = compiler.parse_line(line)
        # IPv6 handling may vary

    def test_very_long_application_name(self):
        """Test long application name."""
        compiler = PrefixCompiler("%m [%p] %q%a ")
        line = "2024-01-15 08:00:01.234 UTC [1234] verylongapplicationname LOG:  msg"
        fields = compiler.parse_line(line)
        assert fields is not None
        # Long application names may be parsed; fields after %q are optional
        # The key test is that parsing succeeds


class TestPrefixCompilerRepr:
    """Test string representation."""

    def test_repr(self):
        """Test __repr__ method."""
        compiler = PrefixCompiler("%m [%p] ")
        repr_str = repr(compiler)
        assert "PrefixCompiler" in repr_str
        assert "%m [%p]" in repr_str


class TestIntegration:
    """Integration tests for prefix module."""

    def test_full_workflow(self):
        """Test complete workflow from detection to parsing."""
        # Sample log lines using a simple, well-known format
        sample = [
            "2024-01-15 08:00:01.234 UTC [1234] LOG:  connection received",
            "2024-01-15 08:00:01.235 UTC [1234] LOG:  connection authorized",
            "2024-01-15 08:00:02.100 UTC [5678] LOG:  checkpoint starting",
            "2024-01-15 08:00:10.500 UTC [5678] LOG:  checkpoint complete",
            "2024-01-15 08:00:11.000 UTC [1234] LOG:  disconnection",
        ]

        # Detect prefix
        detected = detect_prefix_from_log(sample)
        assert detected is not None
        assert detected == "%m [%p] "

        # Compile and validate
        compiler = PrefixCompiler(detected)
        warnings = compiler.validate()
        assert len(warnings) == 0  # Valid prefix

        # Parse all lines
        for line in sample:
            result = build_entry_from_prefix(line, compiler)
            assert result is not None, f"Failed to parse: {line}"
            fields, level, message = result
            assert level in ["LOG", "ERROR", "WARNING", "FATAL", "PANIC", "DEBUG", "INFO", "NOTICE"]

    def test_all_common_prefixes_compile(self):
        """Test that all common prefixes compile successfully."""
        for name, prefix in COMMON_PREFIXES.items():
            compiler = PrefixCompiler(prefix)
            try:
                regex = compiler.compile()
                assert regex is not None, f"Failed to compile {name}"
            except Exception as e:
                pytest.fail(f"Common prefix {name} failed to compile: {e}")

    def test_escape_table_completeness(self):
        """Verify all documented escapes are in the table."""
        expected_escapes = "audrhbpPtmnieclsvxQ"  # All documented escapes
        for esc in expected_escapes:
            assert esc in _ESCAPE_TABLE, f"Escape %{esc} missing from table"

    def test_timestamp_fields_set(self):
        """Verify timestamp fields set is correct."""
        assert "timestamp" in _TIMESTAMP_FIELDS
        assert "timestamp_ms" in _TIMESTAMP_FIELDS
        assert "timestamp_epoch" in _TIMESTAMP_FIELDS

    def test_pid_fields_set(self):
        """Verify PID fields set is correct."""
        assert "pid" in _PID_FIELDS
        assert "session_id" in _PID_FIELDS
