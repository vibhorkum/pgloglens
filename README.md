# pgloglens

**PostgreSQL log analyzer with LLM-powered root cause analysis.**

`pgloglens` parses PostgreSQL log files and produces actionable insights that go beyond what pgBadger provides — including rule-based root cause analysis and optional AI-powered diagnosis via OpenAI, Anthropic, Google Gemini, or local Ollama models.

## Features

### Core Analysis
- **Multi-format log parsing**: stderr, syslog, csvlog, jsonlog (PostgreSQL 15+), pgbouncer, RDS, Heroku, Redshift, CloudSQL
- **Slow query analysis**: normalized query patterns, P50/P95/P99 percentiles, regression detection
- **Error pattern clustering**: SQLSTATE grouping, error storms, trend detection
- **Lock & deadlock analysis**: lock chain reconstruction, most-blocking queries
- **Connection statistics**: peak concurrent, by-hour charts, auth failure tracking
- **Checkpoint analysis**: frequency warnings, duration trending, WAL write amplification
- **Autovacuum insights**: table frequency analysis, bloat indicators
- **Temp file analysis**: work_mem candidates with size-based recommendations
- **Replication lag events**: standby health monitoring
- **Rule-based RCA**: 22+ deterministic rules covering the most common PostgreSQL failure modes
- **LLM-powered analysis**: send summarized findings to GPT-4o, Claude, Gemini, or local Ollama
- **Four output formats**: terminal (rich), HTML (interactive), JSON, Markdown

### New in v2.0
- **Diff/Comparison Mode**: Compare two analyses side-by-side to detect regressions
- **Incident Timeline**: Reconstruct chronological flow of events during incidents
- **Save & Compare**: Save analysis artifacts for later comparison
- **Custom Rule Packs**: Define custom RCA rules via YAML/TOML files
- **pg_stat_statements Correlation**: Import and correlate with pgss snapshots
- **Summary Mode**: Quick 5-line health check with exit codes for CI/CD
- **Glob/Rotation Support**: Analyze rotated logs with glob patterns
- **log_line_prefix Support**: Full support for 18 PostgreSQL escape sequences

## Installation

```bash
pip install pgloglens
```

Or install from source:

```bash
git clone https://github.com/example/pgloglens
cd pgloglens
pip install -e .
```

**Requirements**: Python 3.10+

## Quick Start

```bash
# Basic terminal analysis
pgloglens analyze /var/log/postgresql/postgresql.log

# HTML report
pgloglens analyze postgresql.log --format html -o report.html

# With LLM analysis (requires OPENAI_API_KEY)
pgloglens analyze postgresql.log --llm-provider openai --format html -o report.html

# Filter to last 24 hours, specific database
pgloglens analyze postgresql.log --from-time -24h --database myapp

# Multiple files (e.g., rotated logs)
pgloglens analyze postgresql.log postgresql.log.1 --format html -o report.html

# JSON output for pipeline integration
pgloglens analyze postgresql.log --format json | jq '.slow_queries[0]'

# Watch mode (real-time tail)
pgloglens watch /var/log/postgresql/postgresql.log --alert-threshold-ms 3000
```

## CLI Reference

### `pgloglens analyze`

```
pgloglens analyze [OPTIONS] LOG_FILE [LOG_FILE...]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `html`, `json`, `markdown` |
| `--output`, `-o` | stdout | Output file path |
| `--slow-query-threshold` | `1000` | Min duration (ms) for slow query classification |
| `--from-time` | — | Start filter: ISO datetime or relative (`-1h`, `-24h`, `-7d`) |
| `--to-time` | — | End filter |
| `--database`, `-d` | — | Filter by database name |
| `--user`, `-u` | — | Filter by PostgreSQL username |
| `--llm-provider` | `none` | LLM provider: `openai`, `anthropic`, `ollama`, `google`, `none` |
| `--llm-model` | provider default | Model name |
| `--llm-api-key` | env var | API key (overrides environment variable) |
| `--top-queries` | `25` | Number of slow query patterns in report |
| `--top-errors` | `20` | Number of error patterns in report |
| `--no-rca` | off | Skip rule-based RCA |
| `--config` | `~/.pgloglens.yaml` | Config file path |
| `--verbose`, `-v` | off | Show progress and timing |
| `--workers` | CPU count | Parallel workers for multiple files |

### `pgloglens watch`

```
pgloglens watch [OPTIONS] LOG_FILE
```

| Option | Default | Description |
|--------|---------|-------------|
| `--alert-threshold-ms` | `5000` | Alert on queries slower than this |
| `--webhook-url` | — | POST JSON alerts to webhook |
| `--interval` | `5` | Polling interval in seconds |

### `pgloglens config`

```bash
pgloglens config init        # Create ~/.pgloglens.yaml
pgloglens config show        # Show resolved configuration
```

### `pgloglens version`

Shows version and installed LLM provider packages.

### `pgloglens diff`

Compare two log analyses to detect regressions:

```bash
# Compare two log files/directories
pgloglens diff logs/yesterday/ logs/today/

# Compare saved artifacts
pgloglens diff baseline.json after-deploy.json --format markdown -o diff.md

# Compare with custom labels
pgloglens diff prod-v1.2.log prod-v1.3.log --before-label "v1.2" --after-label "v1.3"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `json`, `markdown`, `html` |
| `--output`, `-o` | stdout | Output file path |
| `--before-label` | `before` | Label for the before analysis |
| `--after-label` | `after` | Label for the after analysis |

### `pgloglens timeline`

Generate an incident timeline from log events:

```bash
# Generate timeline from logs
pgloglens timeline postgresql.log

# Markdown output for incident reports
pgloglens timeline logs/*.log --format markdown -o incident.md

# Adjust time window for event grouping
pgloglens timeline postgresql.log --window-minutes 10
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output`, `-o` | stdout | Output file path |
| `--window-minutes` | `5` | Time window for grouping related events |

### `pgloglens save`

Save analysis results as an artifact for later comparison:

```bash
# Save baseline analysis
pgloglens save postgresql.log -o baseline.json --label production-baseline

# Save pre-deploy state
pgloglens save logs/*.log -o before-deploy.json
```

### `pgloglens summary`

Quick health check with 5-line output (ideal for CI/CD):

```bash
# Quick summary
pgloglens summary postgresql.log

# With exit codes for CI/CD
pgloglens summary logs/*.log --exit-code
# Exit codes: 0=healthy, 1=critical issues, 2=high severity issues
```

### `pgloglens rules`

Manage custom rule packs:

```bash
# Create example rule pack
pgloglens rules init --path ~/.pgloglens/rules/custom.yaml

# List available rule packs
pgloglens rules list
```

### `pgloglens dump`

Export normalized queries with statistics:

```bash
pgloglens dump postgresql.log --format csv -o queries.csv
pgloglens dump postgresql.log --format json --min-count 5 --min-duration-ms 100
```

### `pgloglens index-advisor`

AI-powered index recommendations:

```bash
pgloglens index-advisor postgresql.log --llm-provider openai
pgloglens index-advisor pg.log --llm-provider anthropic --top-queries 15 -o indexes.json
```

## LLM Provider Setup

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
pgloglens analyze postgresql.log --llm-provider openai --llm-model gpt-4o
```

Available models: `gpt-4o` (default), `gpt-4-turbo`, `gpt-3.5-turbo`

### Anthropic

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
pgloglens analyze postgresql.log --llm-provider anthropic --llm-model claude-opus-4-5
```

Available models: `claude-opus-4-5` (default), `claude-sonnet-4-5`

### Google Gemini

```bash
export GOOGLE_API_KEY="AIza..."
pgloglens analyze postgresql.log --llm-provider google --llm-model gemini-1.5-pro
```

Available models: `gemini-1.5-pro` (default), `gemini-pro`

### Ollama (local, no API key needed)

```bash
# Make sure Ollama is running: ollama serve
pgloglens analyze postgresql.log --llm-provider ollama --llm-model llama3
```

## Configuration File

Create `~/.pgloglens.yaml` (or run `pgloglens config init`):

```yaml
slow_query_threshold_ms: 1000

llm:
  provider: openai           # openai | anthropic | ollama | google | none
  model: gpt-4o
  api_key: ${OPENAI_API_KEY} # supports env var substitution

report:
  format: html               # terminal | html | json | markdown
  top_queries: 25
  top_errors: 20

filters:
  databases: []              # empty = analyze all databases
  users: []

watch:
  alert_threshold_ms: 5000
  interval_seconds: 5
```

## Custom Rule Packs

Create custom RCA rules, override severity of built-in rules, and define ignore patterns:

```yaml
# ~/.pgloglens/rules/production.yaml
name: production-rules
version: "1.0"

# Override severity of built-in rules
severity_overrides:
  AUTH_FAILURES_SPIKE: critical  # Make auth failures always critical
  SLOW_CHECKPOINTS: low          # Downgrade on fast SSD systems

# Ignore specific patterns
ignore_patterns:
  errors:
    - "duplicate key.*temp_"     # Ignore temp table conflicts
    - "canceling statement due to statement timeout"
  queries:
    - "^SELECT 1$"               # Ignore health checks

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
```

Use custom rules:

```bash
pgloglens analyze postgresql.log --rule-pack ~/.pgloglens/rules/production.yaml
```

## pg_stat_statements Correlation

Correlate log analysis with `pg_stat_statements` data for deeper insights:

```bash
# Export pg_stat_statements to JSON
psql -c "COPY (SELECT json_agg(row_to_json(t)) FROM (
    SELECT queryid, query, calls, total_exec_time, mean_exec_time, rows,
           shared_blks_hit, shared_blks_read, temp_blks_read, temp_blks_written
    FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 1000
) t) TO STDOUT;" > pgss_snapshot.json

# Analyze with correlation
pgloglens analyze postgresql.log --pgss-snapshot pgss_snapshot.json
```

This provides:
- Match rate between log queries and pgss entries
- Comparison of log durations vs cumulative pgss stats
- Cache hit ratios and temp file usage from pgss
- Queries that appear in logs but not pgss (dynamic SQL)

## Supported Log Formats

pgloglens auto-detects the log format from file content:

| Format | `log_destination` | Description |
|--------|--------------------|-------------|
| `stderr` | `stderr` (default) | `YYYY-MM-DD HH:MM:SS.mmm UTC [PID] user@db LEVEL: message` |
| `syslog` | `syslog` | Month Day Time host postgres[PID]: message |
| `csvlog` | `csvlog` | RFC 4180 CSV with all 23+ PostgreSQL columns |
| `jsonlog` | `jsonlog` (PG 15+) | One JSON object per line |

Gzip-compressed files (`.gz`) are handled transparently.

PostgreSQL log format is configured in `postgresql.conf`:
```
log_destination = 'stderr'  # or csvlog, jsonlog, syslog
logging_collector = on
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_duration = off          # use log_min_duration_statement instead
log_min_duration_statement = 1000  # log queries > 1s
log_line_prefix = '%t [%p] %u@%d '  # recommended for pgloglens
log_lock_waits = on
log_temp_files = 0           # log all temp files
log_autovacuum_min_duration = 0
log_checkpoints = on
```

## Rule-Based RCA Rules

pgloglens evaluates 14 deterministic rules before any LLM call:

| Rule ID | Severity | Trigger | Recommendation |
|---------|----------|---------|----------------|
| `HIGH_CHECKPOINT_FREQUENCY` | HIGH | ≥3 checkpoint warnings | Increase `max_wal_size` |
| `SLOW_CHECKPOINTS` | MEDIUM | Avg checkpoint >60s | Move WAL to faster disk |
| `CONNECTION_EXHAUSTION` | CRITICAL/HIGH | Peak connections ≥150/80 | Deploy PgBouncer |
| `LOCK_STORMS` | CRITICAL/HIGH | ≥10 lock wait events | Review transaction ordering |
| `DEADLOCK_PATTERN` | HIGH | ≥2 deadlocks | Canonical lock ordering |
| `TEMP_FILE_ABUSE` | HIGH/MEDIUM | Temp files ≥100MB | Increase `work_mem` |
| `AUTOVACUUM_LAGGING` | HIGH/MEDIUM | Table vacuumed ≥10x | Adjust `fillfactor` |
| `AUTH_FAILURES_SPIKE` | CRITICAL/HIGH | ≥100/20 auth failures | Check pg_hba.conf |
| `REPLICATION_LAG` | CRITICAL/HIGH | Lag ≥100/any MB | Check standby I/O |
| `OOM_KILLER` | CRITICAL | OOM events | Reduce `shared_buffers` |
| `SLOW_QUERY_REGRESSION` | HIGH | Slope >1% per execution | `ANALYZE`, `REINDEX` |
| `ERROR_STORM` | CRITICAL | >50 errors/5min window | Circuit breaker |
| `SSL_FATAL_ERRORS` | HIGH | SSL FATAL events | Check certificates |
| `DISK_FULL` | CRITICAL | Write failure events | Free disk space |
| `LONG_RUNNING_TRANSACTIONS` | CRITICAL/HIGH | Queries >5min | Set `statement_timeout` |

## Architecture

```
pgloglens/
├── cli.py       Click commands — argument parsing, orchestration
├── parser.py    Streaming log parser — 4 format handlers, auto-detect
├── analyzer.py  Aggregation engine — slow queries, errors, connections, etc.
├── rca.py       14 deterministic RCA rules → RCAFinding objects
├── llm.py       Unified LLM interface (OpenAI / Anthropic / Ollama / Google)
├── reporter.py  4 output renderers — terminal/HTML/JSON/Markdown
└── models.py    Pydantic v2 data models
```

**Data flow:**
```
LogFile(s) → parser.py → LogEntry stream → analyzer.py → AnalysisResult
                                                              ↓
                                                         rca.py → RCAFinding list
                                                              ↓
                                                         llm.py → AI analysis text
                                                              ↓
                                                         reporter.py → Report
```

## pgloglens vs pgBadger

| Feature | pgloglens | pgBadger |
|---------|-----------|---------|
| Slow query P50/P95/P99 | ✅ | ✅ |
| Query normalization | ✅ | ✅ |
| HTML report | ✅ | ✅ |
| JSON/Markdown output | ✅ | ❌ |
| **LLM-powered RCA** | ✅ | ❌ |
| **Rule-based RCA (14 rules)** | ✅ | ❌ |
| **Query regression detection** | ✅ | ❌ |
| **Real-time watch mode** | ✅ | ❌ |
| **Webhook alerting** | ✅ | ❌ |
| **Config file support** | ✅ | Partial |
| **gzip transparent** | ✅ | ✅ |
| **jsonlog (PG 15+)** | ✅ | ✅ |
| Multiple LLM providers | ✅ | ❌ |
| Streaming parser (low memory) | ✅ | ❌ |
| Error storm detection | ✅ | ❌ |
| Python (3.10+) | ✅ | Perl |
| Parallel file processing | ✅ | ✅ |

## Development

```bash
pip install -e ".[dev]"

# Run unit tests
pytest tests/test_parser.py tests/test_analyzer.py -v

# Run a single test
pytest tests/test_parser.py::test_parse_stderr_line_basic -v

# Format
black pgloglens/ tests/

# Type check
mypy pgloglens/
```

### Running against the sample log

```bash
cd /path/to/pgloglens
python -m pgloglens.cli analyze tests/sample_pg.log --verbose
python -m pgloglens.cli analyze tests/sample_pg.log --format html -o /tmp/report.html
```

### Docker Integration Tests

For comprehensive testing against real PostgreSQL logs:

```bash
# Quick: automated test script
./scripts/run_docker_tests.sh

# Manual steps:
docker-compose up -d                          # Start PostgreSQL container
pip install psycopg2-binary                   # Install PostgreSQL driver
python tests/docker/generate_logs.py          # Generate test scenarios
docker cp pgloglens-test-pg:/var/log/postgresql/postgresql.log tests/docker/
pytest tests/test_integration.py -v --docker  # Run integration tests
docker-compose down -v                        # Cleanup
```

The Docker tests generate realistic logs covering:
- Slow queries with varying durations
- Error patterns (constraint violations, syntax errors, etc.)
- Lock contention and deadlock scenarios
- Connection and authentication events
- Checkpoint activity
- Autovacuum events
- Temp file creation

## Author

Vibhor Kumar

## License

MIT
