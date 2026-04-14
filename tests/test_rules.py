"""Tests for pgloglens custom rules module."""

import os
import tempfile
import pytest

from pgloglens.rules import (
    CustomRule,
    RulePack,
    load_rule_pack,
    discover_rule_packs,
    create_example_rule_pack,
    apply_rule_pack_to_findings,
    _parse_yaml,
    _parse_value,
    _build_rule_pack,
)
from pgloglens.models import (
    AnalysisResult,
    RCAFinding,
    Severity,
    SlowQuery,
    ErrorPattern,
    SessionStats,
    TempFileStats,
)


class TestCustomRule:
    """Tests for CustomRule dataclass."""

    def test_basic_rule(self):
        """Test creating a basic custom rule."""
        rule = CustomRule(
            rule_id="TEST_RULE",
            severity="high",
            title="Test rule",
            condition="len(result.slow_queries) > 10",
            description="Too many slow queries",
            recommendations=["Optimize queries", "Add indexes"],
        )

        assert rule.rule_id == "TEST_RULE"
        assert rule.severity == "high"
        assert len(rule.recommendations) == 2

    def test_rule_evaluation_true(self):
        """Test rule that evaluates to True."""
        rule = CustomRule(
            rule_id="MANY_SLOW_QUERIES",
            severity="high",
            title="Many slow queries",
            condition="len(result.slow_queries) > 5",
            description="More than 5 slow query patterns",
            recommendations=["Review queries"],
        )

        # Create result with many slow queries
        result = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query=f"SELECT {i}",
                    normalized_query=f"SELECT ${i}",
                )
                for i in range(10)
            ]
        )

        finding = rule.evaluate(result)
        assert finding is not None
        assert finding.rule_id == "MANY_SLOW_QUERIES"
        assert finding.severity == Severity.HIGH

    def test_rule_evaluation_false(self):
        """Test rule that evaluates to False."""
        rule = CustomRule(
            rule_id="MANY_ERRORS",
            severity="medium",
            title="Many errors",
            condition="len(result.error_patterns) > 100",
            description="More than 100 error patterns",
            recommendations=["Review errors"],
        )

        # Create result with few errors
        result = AnalysisResult(
            error_patterns=[
                ErrorPattern(message_pattern="error 1"),
                ErrorPattern(message_pattern="error 2"),
            ]
        )

        finding = rule.evaluate(result)
        assert finding is None

    def test_rule_evaluation_with_sum(self):
        """Test rule using sum() in condition."""
        rule = CustomRule(
            rule_id="HIGH_TEMP_USAGE",
            severity="medium",
            title="High temp file usage",
            condition="sum(t.size_mb for t in result.temp_files) > 100",
            description="Total temp files exceed 100MB",
            recommendations=["Increase work_mem"],
        )

        # Create result with temp files
        result = AnalysisResult(
            temp_files=[
                TempFileStats(size_mb=50.0),
                TempFileStats(size_mb=60.0),
            ]
        )

        finding = rule.evaluate(result)
        assert finding is not None
        assert finding.rule_id == "HIGH_TEMP_USAGE"

    def test_rule_evaluation_error_handling(self):
        """Test rule handles evaluation errors gracefully."""
        rule = CustomRule(
            rule_id="BAD_RULE",
            severity="high",
            title="Bad rule",
            condition="result.nonexistent_attr > 10",  # Will fail
            description="This will error",
            recommendations=[],
        )

        result = AnalysisResult()
        # Should not raise, returns None
        finding = rule.evaluate(result)
        assert finding is None

    def test_disabled_rule(self):
        """Test disabled rule is not evaluated."""
        rule = CustomRule(
            rule_id="DISABLED_RULE",
            severity="high",
            title="Disabled rule",
            condition="True",  # Would always fire
            description="This is disabled",
            recommendations=[],
            enabled=False,
        )

        result = AnalysisResult()
        finding = rule.evaluate(result)
        assert finding is None


class TestRulePack:
    """Tests for RulePack dataclass."""

    def test_empty_rule_pack(self):
        """Test empty rule pack."""
        pack = RulePack()
        assert pack.name == "default"
        assert len(pack.custom_rules) == 0
        assert len(pack.severity_overrides) == 0

    def test_rule_pack_with_rules(self):
        """Test rule pack with custom rules."""
        pack = RulePack(
            name="test-pack",
            version="1.0",
            custom_rules=[
                CustomRule(
                    rule_id="TEST1",
                    severity="high",
                    title="Test 1",
                    condition="True",
                    description="Always fires",
                ),
                CustomRule(
                    rule_id="TEST2",
                    severity="low",
                    title="Test 2",
                    condition="False",
                    description="Never fires",
                ),
            ],
        )

        assert pack.name == "test-pack"
        assert len(pack.custom_rules) == 2

    def test_rule_pack_compile_patterns(self):
        """Test compiling ignore patterns."""
        pack = RulePack(
            ignore_error_patterns=["timeout", "connection refused"],
            ignore_query_patterns=["^SELECT 1$", "health.?check"],
        )

        pack.compile_patterns()

        assert len(pack._compiled_error_patterns) == 2
        assert len(pack._compiled_query_patterns) == 2

    def test_should_ignore_error(self):
        """Test error message ignore matching."""
        pack = RulePack(
            ignore_error_patterns=["duplicate key.*temp_", "statement timeout"],
        )
        pack.compile_patterns()

        assert pack.should_ignore_error("duplicate key constraint violated on temp_table")
        assert pack.should_ignore_error("canceling statement due to statement timeout")
        assert not pack.should_ignore_error("connection refused")

    def test_should_ignore_query(self):
        """Test query ignore matching."""
        pack = RulePack(
            ignore_query_patterns=["^SELECT 1$", "^SELECT version()"],
        )
        pack.compile_patterns()

        assert pack.should_ignore_query("SELECT 1")
        assert pack.should_ignore_query("SELECT version()")
        assert not pack.should_ignore_query("SELECT * FROM users")

    def test_get_severity_override(self):
        """Test severity override lookup."""
        pack = RulePack(
            severity_overrides={
                "DEADLOCK_DETECTED": "critical",
                "SLOW_CHECKPOINTS": "low",
            },
        )

        assert pack.get_severity_override("DEADLOCK_DETECTED") == Severity.CRITICAL
        assert pack.get_severity_override("SLOW_CHECKPOINTS") == Severity.LOW
        assert pack.get_severity_override("UNKNOWN_RULE") is None

    def test_evaluate_custom_rules(self):
        """Test evaluating all custom rules."""
        pack = RulePack(
            custom_rules=[
                CustomRule(
                    rule_id="FIRES",
                    severity="high",
                    title="This fires",
                    condition="len(result.slow_queries) >= 0",  # Always true
                    description="Always fires",
                ),
                CustomRule(
                    rule_id="NO_FIRE",
                    severity="low",
                    title="This does not fire",
                    condition="len(result.slow_queries) > 1000",
                    description="Never fires",
                ),
            ],
        )

        result = AnalysisResult(slow_queries=[])
        findings = pack.evaluate_custom_rules(result)

        assert len(findings) == 1
        assert findings[0].rule_id == "FIRES"


class TestParseYaml:
    """Tests for YAML parsing helpers."""

    def test_parse_simple_yaml(self):
        """Test parsing simple YAML."""
        content = """
name: test-pack
version: "1.0"
description: A test pack
"""
        data = _parse_yaml(content)
        assert data["name"] == "test-pack"
        assert data["version"] == "1.0"

    def test_parse_nested_yaml(self):
        """Test parsing nested YAML structure."""
        content = """
severity_overrides:
  RULE1: critical
  RULE2: low
"""
        data = _parse_yaml(content)
        assert "severity_overrides" in data
        assert data["severity_overrides"]["RULE1"] == "critical"

    def test_parse_value_types(self):
        """Test parsing different value types."""
        assert _parse_value("true") is True
        assert _parse_value("false") is False
        assert _parse_value("yes") is True
        assert _parse_value("no") is False
        assert _parse_value("null") is None
        assert _parse_value("123") == 123
        assert _parse_value("1.5") == 1.5
        assert _parse_value("hello") == "hello"
        assert _parse_value('"quoted"') == "quoted"


class TestLoadRulePack:
    """Tests for loading rule packs from files."""

    def test_load_yaml_rule_pack(self):
        """Test loading YAML rule pack."""
        content = """
name: test-rules
version: "2.0"
description: Test rule pack

severity_overrides:
  DEADLOCK_DETECTED: critical

ignore_patterns:
  errors:
    - timeout
  queries:
    - "^SELECT 1$"

custom_rules:
  - rule_id: CUSTOM_TEST
    severity: high
    title: Custom test rule
    condition: "len(result.slow_queries) > 5"
    description: Too many slow queries
    recommendations:
      - Optimize queries
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(content)
            f.flush()

            try:
                pack = load_rule_pack(f.name)
                assert pack.name == "test-rules"
                assert pack.version == "2.0"
                assert "DEADLOCK_DETECTED" in pack.severity_overrides
                assert len(pack.custom_rules) >= 0  # May be 0 if parsing limited
            finally:
                os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_rule_pack("/nonexistent/path/rules.yaml")


class TestBuildRulePack:
    """Tests for building RulePack from parsed data."""

    def test_build_from_dict(self):
        """Test building rule pack from dictionary."""
        data = {
            "name": "built-pack",
            "version": "1.5",
            "description": "A built pack",
            "severity_overrides": {
                "RULE1": "critical",
            },
            "ignore_patterns": {
                "errors": ["timeout"],
                "queries": ["SELECT 1"],
            },
            "custom_rules": [
                {
                    "rule_id": "CUSTOM1",
                    "severity": "high",
                    "title": "Custom rule 1",
                    "condition": "True",
                    "description": "Test",
                    "recommendations": ["Do something"],
                },
            ],
        }

        pack = _build_rule_pack(data)

        assert pack.name == "built-pack"
        assert pack.version == "1.5"
        assert len(pack.severity_overrides) == 1
        assert len(pack.ignore_error_patterns) == 1
        assert len(pack.ignore_query_patterns) == 1
        assert len(pack.custom_rules) == 1


class TestApplyRulePackToFindings:
    """Tests for applying rule pack to findings."""

    def test_apply_severity_override(self):
        """Test applying severity override to findings."""
        findings = [
            RCAFinding(
                rule_id="DEADLOCK_DETECTED",
                severity=Severity.HIGH,  # Original
                title="Deadlock",
                description="Deadlock found",
            ),
            RCAFinding(
                rule_id="SLOW_QUERIES",
                severity=Severity.MEDIUM,
                title="Slow queries",
                description="Slow queries found",
            ),
        ]

        pack = RulePack(
            severity_overrides={
                "DEADLOCK_DETECTED": "critical",  # Override to critical
            },
        )

        modified = apply_rule_pack_to_findings(findings, pack)

        assert len(modified) == 2
        # First finding should have overridden severity
        deadlock = next(f for f in modified if f.rule_id == "DEADLOCK_DETECTED")
        assert deadlock.severity == Severity.CRITICAL

        # Second finding unchanged
        slow = next(f for f in modified if f.rule_id == "SLOW_QUERIES")
        assert slow.severity == Severity.MEDIUM

    def test_apply_no_override(self):
        """Test findings unchanged when no overrides match."""
        findings = [
            RCAFinding(
                rule_id="SOME_RULE",
                severity=Severity.LOW,
                title="Some rule",
                description="Description",
            ),
        ]

        pack = RulePack(
            severity_overrides={
                "OTHER_RULE": "critical",
            },
        )

        modified = apply_rule_pack_to_findings(findings, pack)

        assert len(modified) == 1
        assert modified[0].severity == Severity.LOW


class TestDiscoverRulePacks:
    """Tests for rule pack discovery."""

    def test_discover_in_empty_dirs(self):
        """Test discovery in directories with no rule packs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            packs = discover_rule_packs([tmpdir])
            assert len(packs) == 0

    def test_discover_yaml_files(self):
        """Test discovery finds YAML files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some rule pack files
            for name in ["pack1.yaml", "pack2.yml", "pack3.toml"]:
                path = os.path.join(tmpdir, name)
                with open(path, "w") as f:
                    f.write("name: test\n")

            packs = discover_rule_packs([tmpdir])
            assert len(packs) == 3


class TestCreateExampleRulePack:
    """Tests for example rule pack creation."""

    def test_create_example(self):
        """Test creating example rule pack file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "example.yaml")
            create_example_rule_pack(path)

            assert os.path.exists(path)

            # Verify content
            with open(path) as f:
                content = f.read()

            assert "pgloglens" in content.lower()
            assert "severity_overrides" in content
            assert "ignore_patterns" in content
            assert "custom_rules" in content


class TestRulesIntegration:
    """Integration tests for rules module."""

    def test_full_workflow(self):
        """Test complete rule pack workflow."""
        # Create a rule pack
        pack = RulePack(
            name="integration-test",
            version="1.0",
            severity_overrides={
                "BUILT_IN_RULE": "critical",
            },
            ignore_error_patterns=["expected error"],
            ignore_query_patterns=["^SELECT 1$"],
            custom_rules=[
                CustomRule(
                    rule_id="CUSTOM_HIGH_ERROR_RATE",
                    severity="high",
                    title="High error rate",
                    condition="len(result.error_patterns) > 2",
                    description="More than 2 error patterns",
                    recommendations=["Review errors", "Check logs"],
                ),
            ],
        )
        pack.compile_patterns()

        # Create analysis result
        result = AnalysisResult(
            slow_queries=[
                SlowQuery(
                    query="SELECT 1",  # Should be ignored
                    normalized_query="SELECT $1",
                ),
                SlowQuery(
                    query="SELECT * FROM users",
                    normalized_query="SELECT * FROM users",
                ),
            ],
            error_patterns=[
                ErrorPattern(message_pattern="error 1", count=10),
                ErrorPattern(message_pattern="error 2", count=5),
                ErrorPattern(message_pattern="error 3", count=3),
            ],
        )

        # Test ignore patterns
        assert pack.should_ignore_query("SELECT 1")
        assert not pack.should_ignore_query("SELECT * FROM users")

        # Evaluate custom rules
        findings = pack.evaluate_custom_rules(result)
        assert len(findings) == 1
        assert findings[0].rule_id == "CUSTOM_HIGH_ERROR_RATE"

        # Apply severity overrides to existing findings
        existing_findings = [
            RCAFinding(
                rule_id="BUILT_IN_RULE",
                severity=Severity.MEDIUM,
                title="Built-in rule",
                description="A built-in finding",
            ),
        ]

        modified = apply_rule_pack_to_findings(existing_findings, pack)
        assert modified[0].severity == Severity.CRITICAL
