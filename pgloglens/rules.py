"""Custom rule pack support for pgloglens.

Allows users to define custom RCA rules via YAML or TOML files:
- Custom ignore patterns for specific errors/queries
- Severity overrides for built-in rules
- Environment-specific heuristics

Example rule pack (YAML):
```yaml
name: production-rules
version: "1.0"

# Override severity of built-in rules
severity_overrides:
  AUTH_FAILURES_SPIKE: critical  # Make auth failures always critical
  SLOW_CHECKPOINTS: low         # Downgrade checkpoint warnings

# Ignore specific patterns
ignore_patterns:
  errors:
    - "duplicate key.*temp_"    # Ignore temp table conflicts
    - "canceling statement due to statement timeout"
  queries:
    - "^SELECT 1$"              # Ignore health checks

# Custom rules
custom_rules:
  - rule_id: CUSTOM_LONG_TX
    severity: high
    title: "Long-running transactions detected"
    condition: "result.session_stats.avg_session_duration_ms > 300000"
    description: "Average session duration exceeds 5 minutes"
    recommendations:
      - "Review application connection handling"
      - "Check for uncommitted transactions"

  - rule_id: CUSTOM_HIGH_TEMP
    severity: medium
    title: "High temp file usage"
    condition: "sum(t.size_mb for t in result.temp_files) > 1000"
    description: "Total temp file usage exceeds 1GB"
    recommendations:
      - "Increase work_mem"
      - "Add indexes to avoid sort operations"
```
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .models import AnalysisResult, RCAFinding, Severity


@dataclass
class CustomRule:
    """A custom RCA rule defined in a rule pack."""

    rule_id: str
    severity: str
    title: str
    condition: str
    description: str
    recommendations: List[str] = field(default_factory=list)
    enabled: bool = True

    def evaluate(self, result: AnalysisResult) -> Optional[RCAFinding]:
        """Evaluate this rule against an AnalysisResult.

        The condition is a Python expression that has access to `result`.
        Returns an RCAFinding if the condition is True, None otherwise.
        """
        if not self.enabled:
            return None

        try:
            # Create a safe evaluation context
            context = {
                "result": result,
                "sum": sum,
                "len": len,
                "any": any,
                "all": all,
                "max": max,
                "min": min,
            }

            # Evaluate the condition
            if eval(self.condition, {"__builtins__": {}}, context):
                return RCAFinding(
                    rule_id=self.rule_id,
                    severity=Severity(self.severity.upper()),
                    title=self.title,
                    description=self.description,
                    recommendations=self.recommendations,
                )
        except Exception as e:
            # Log but don't fail on rule evaluation errors
            import sys
            print(f"[pgloglens] Rule {self.rule_id} evaluation error: {e}", file=sys.stderr)

        return None


@dataclass
class RulePack:
    """A collection of custom rules and configuration."""

    name: str = "default"
    version: str = "1.0"
    description: str = ""

    # Severity overrides for built-in rules
    severity_overrides: Dict[str, str] = field(default_factory=dict)

    # Patterns to ignore
    ignore_error_patterns: List[str] = field(default_factory=list)
    ignore_query_patterns: List[str] = field(default_factory=list)

    # Custom rules
    custom_rules: List[CustomRule] = field(default_factory=list)

    # Compiled regex patterns (populated on load)
    _compiled_error_patterns: List[re.Pattern] = field(default_factory=list)
    _compiled_query_patterns: List[re.Pattern] = field(default_factory=list)

    def compile_patterns(self) -> None:
        """Compile regex patterns for efficient matching."""
        self._compiled_error_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.ignore_error_patterns
        ]
        self._compiled_query_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.ignore_query_patterns
        ]

    def should_ignore_error(self, message: str) -> bool:
        """Check if an error message should be ignored."""
        return any(p.search(message) for p in self._compiled_error_patterns)

    def should_ignore_query(self, query: str) -> bool:
        """Check if a query should be ignored."""
        return any(p.search(query) for p in self._compiled_query_patterns)

    def get_severity_override(self, rule_id: str) -> Optional[Severity]:
        """Get severity override for a rule, if any."""
        override = self.severity_overrides.get(rule_id)
        if override:
            try:
                return Severity(override.upper())
            except ValueError:
                pass
        return None

    def evaluate_custom_rules(self, result: AnalysisResult) -> List[RCAFinding]:
        """Evaluate all custom rules and return findings."""
        findings = []
        for rule in self.custom_rules:
            finding = rule.evaluate(result)
            if finding:
                findings.append(finding)
        return findings


def load_rule_pack(path: str) -> RulePack:
    """Load a rule pack from a YAML or TOML file.

    Args:
        path: Path to the rule pack file

    Returns:
        RulePack object
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Rule pack not found: {path}")

    content = path_obj.read_text(encoding="utf-8")
    suffix = path_obj.suffix.lower()

    if suffix in (".yaml", ".yml"):
        data = _parse_yaml(content)
    elif suffix == ".toml":
        data = _parse_toml(content)
    else:
        # Try YAML first, then TOML
        try:
            data = _parse_yaml(content)
        except Exception:
            data = _parse_toml(content)

    return _build_rule_pack(data)


def _parse_yaml(content: str) -> Dict[str, Any]:
    """Parse YAML content."""
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        # Minimal YAML parser for simple configs
        return _minimal_yaml_parse(content)


def _minimal_yaml_parse(content: str) -> Dict[str, Any]:
    """Minimal YAML parser for simple configurations."""
    result: Dict[str, Any] = {}
    current: Dict[str, Any] = result
    stack: List[tuple] = []

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Handle list items
        if stripped.startswith("- "):
            item = stripped[2:].strip()
            # Find the parent list
            if stack:
                parent_key = stack[-1][1]
                if isinstance(current.get(parent_key), list):
                    if item.startswith("{") or ":" in item:
                        # Dict item
                        item_dict = {}
                        if ":" in item:
                            for part in item.split(","):
                                if ":" in part:
                                    k, v = part.split(":", 1)
                                    item_dict[k.strip()] = _parse_value(v.strip())
                        current[parent_key].append(item_dict)
                    else:
                        current[parent_key].append(_parse_value(item))
            continue

        if ":" not in stripped:
            continue

        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()

        # Adjust stack based on indentation
        while stack and indent <= stack[-1][0]:
            stack.pop()
            current = stack[-1][2] if stack else result

        if not val:
            # Start of a new section or list
            new_dict: Dict[str, Any] = {}
            current[key] = new_dict
            stack.append((indent, key, current))
            current = new_dict
        elif val == "[]":
            current[key] = []
            stack.append((indent, key, current))
        else:
            current[key] = _parse_value(val)

    return result


def _parse_value(val: str) -> Any:
    """Parse a YAML value."""
    val = val.strip().strip('"\'')
    if val.lower() in ("true", "yes"):
        return True
    if val.lower() in ("false", "no"):
        return False
    if val.lower() in ("null", "~", ""):
        return None
    try:
        return int(val)
    except ValueError:
        try:
            return float(val)
        except ValueError:
            return val


def _parse_toml(content: str) -> Dict[str, Any]:
    """Parse TOML content."""
    try:
        import tomllib
        return tomllib.loads(content)
    except ImportError:
        try:
            import toml
            return toml.loads(content)
        except ImportError:
            raise ImportError("TOML parsing requires tomllib (Python 3.11+) or toml package")


def _build_rule_pack(data: Dict[str, Any]) -> RulePack:
    """Build a RulePack from parsed data."""
    pack = RulePack(
        name=data.get("name", "custom"),
        version=str(data.get("version", "1.0")),
        description=data.get("description", ""),
    )

    # Severity overrides
    pack.severity_overrides = data.get("severity_overrides", {})

    # Ignore patterns
    ignore = data.get("ignore_patterns", {})
    pack.ignore_error_patterns = ignore.get("errors", [])
    pack.ignore_query_patterns = ignore.get("queries", [])

    # Custom rules
    for rule_data in data.get("custom_rules", []):
        rule = CustomRule(
            rule_id=rule_data.get("rule_id", "CUSTOM"),
            severity=rule_data.get("severity", "medium"),
            title=rule_data.get("title", "Custom rule"),
            condition=rule_data.get("condition", "False"),
            description=rule_data.get("description", ""),
            recommendations=rule_data.get("recommendations", []),
            enabled=rule_data.get("enabled", True),
        )
        pack.custom_rules.append(rule)

    # Compile patterns
    pack.compile_patterns()

    return pack


def discover_rule_packs(search_paths: Optional[List[str]] = None) -> List[str]:
    """Discover available rule pack files.

    Args:
        search_paths: List of directories to search (defaults to ~/.pgloglens/rules/)

    Returns:
        List of rule pack file paths
    """
    if search_paths is None:
        search_paths = [
            str(Path.home() / ".pgloglens" / "rules"),
            str(Path.cwd() / ".pgloglens" / "rules"),
            "/etc/pgloglens/rules",
        ]

    found = []
    for search_path in search_paths:
        path = Path(search_path)
        if path.exists() and path.is_dir():
            for f in path.iterdir():
                if f.suffix in (".yaml", ".yml", ".toml"):
                    found.append(str(f))

    return sorted(found)


def apply_rule_pack_to_findings(
    findings: List[RCAFinding],
    pack: RulePack,
) -> List[RCAFinding]:
    """Apply a rule pack to modify findings.

    This applies severity overrides from the rule pack.
    """
    modified = []
    for finding in findings:
        override = pack.get_severity_override(finding.rule_id)
        if override:
            finding = RCAFinding(
                rule_id=finding.rule_id,
                severity=override,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                recommendations=finding.recommendations,
                affected_queries=finding.affected_queries,
                metric_value=finding.metric_value,
                metric_label=finding.metric_label,
            )
        modified.append(finding)
    return modified


def create_example_rule_pack(path: str) -> None:
    """Create an example rule pack file.

    Args:
        path: Path to write the example file
    """
    example = '''# pgloglens Custom Rule Pack
# Place this file in ~/.pgloglens/rules/ or specify with --rule-pack

name: example-rules
version: "1.0"
description: "Example custom rules for pgloglens"

# Override severity of built-in rules
# Available severities: critical, high, medium, low, info
severity_overrides:
  # Make auth failures always critical in production
  AUTH_FAILURES_SPIKE: critical
  # Downgrade checkpoint warnings on systems with fast SSDs
  SLOW_CHECKPOINTS: low

# Ignore specific patterns (regex)
ignore_patterns:
  errors:
    # Ignore expected duplicate key errors on temp tables
    - "duplicate key.*temp_"
    # Ignore timeout cancellations from background jobs
    - "canceling statement due to statement timeout"
  queries:
    # Ignore health check queries
    - "^SELECT 1$"
    - "^SELECT version\\(\\)$"

# Custom rules
# Each rule has:
#   - rule_id: Unique identifier
#   - severity: critical/high/medium/low/info
#   - title: Short description
#   - condition: Python expression (has access to `result`)
#   - description: Detailed description
#   - recommendations: List of suggestions
custom_rules:
  - rule_id: CUSTOM_LONG_SESSION
    severity: high
    title: "Long-running sessions detected"
    condition: "result.session_stats.avg_session_duration_ms > 300000"
    description: "Average session duration exceeds 5 minutes, indicating potential connection leaks"
    recommendations:
      - "Review application connection pool settings"
      - "Check for uncommitted transactions"
      - "Consider using statement_timeout"

  - rule_id: CUSTOM_HIGH_TEMP_TOTAL
    severity: medium
    title: "High total temp file usage"
    condition: "sum(t.size_mb for t in result.temp_files) > 1000"
    description: "Total temp file usage exceeds 1GB across all queries"
    recommendations:
      - "Increase work_mem for heavy queries"
      - "Add indexes to avoid large sort operations"
      - "Consider partitioning large tables"

  - rule_id: CUSTOM_QUERY_COUNT
    severity: info
    title: "High query volume"
    condition: "len(result.slow_queries) > 100"
    description: "More than 100 unique slow query patterns detected"
    recommendations:
      - "Review query normalization settings"
      - "Consider query caching or prepared statements"
'''

    with open(path, "w", encoding="utf-8") as f:
        f.write(example)
