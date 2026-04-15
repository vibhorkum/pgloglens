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
- **Configurable RCA thresholds**: override default rule thresholds per environment via config file
- **Parse error visibility**: automatic warning when >5% of log entries fail to parse
- **LLM-powered analysis**: send summarized findings to GPT-4o, Claude, Gemini, or local Ollama
- **Five output formats**: terminal (rich), HTML (interactive), JSON, Markdown, JSON Lines (JSONL)

### New in v2.0
- **Diff/Comparison Mode**: Compare two analyses side-by-side to detect regressions
- **Incident Timeline**: Reconstruct chronological flow of events during incidents
- **Save & Compare**: Save analysis artifacts for later comparison
- **Custom Rule Packs**: Define custom RCA rules via YAML/TOML files
- **pg_stat_statements Correlation**: Import and correlate with pgss snapshots
- **Summary Mode**: Quick 5-line health check with CI/CD exit codes (on by default)
- **JSONL Streaming**: Stream raw log entries as JSON Lines for pipeline integration
- **Relative time filters**: `--from-time 2h` (no minus sign needed)
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

# Filter to last 2 hours, specific database
pgloglens analyze postgresql.log --from-time 2h --database myapp

# Multiple files (e.g., rotated logs)
pgloglens analyze postgresql.log postgresql.log.1 --format html -o report.html

# JSON output for pipeline integration
pgloglens analyze postgresql.log --format json | jq '.slow_queries[0]'

# Stream raw log entries as JSON Lines — pipe into jq or downstream tools
pgloglens analyze postgresql.log --format jsonl | jq 'select(.duration_ms > 5000)'
pgloglens analyze postgresql.log --format jsonl -o entries.jsonl

# CI/CD health gate — exits 0 (healthy), 1 (critical), 2 (high severity)
if pgloglens summary postgresql.log; then
    echo "Log is healthy — deploying"
fi

# Watch mode (real-time tail)
pgloglens watch /var/log/postgresql/postgresql.log --alert-slow-ms 3000
```

## CLI Reference

### `pgloglens analyze`

```
pgloglens analyze [OPTIONS] LOG_FILE [LOG_FILE...]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f` | `terminal` | Output format: `terminal`, `html`, `json`, `markdown`, `jsonl` |
| `--output`, `-o` | stdout | Output file path |
| `--slow-query-threshold` | `1000` | Min duration (ms) for slow query classification |
| `--from-time` | — | Start filter: ISO datetime or relative (`2h`, `30m`, `7d`, `-24h`) |
| `--to-time` | — | End filter (same formats as `--from-time`) |
| `--database`, `-d` | — | Filter by database name |
| `--user`, `-u` | — | Filter by PostgreSQL username |
| `--application` | — | Filter by application name |
| `--host` | — | Filter by client host/IP |
| `--llm-provider` | `none` | LLM provider: `openai`, `anthropic`, `ollama`, `google`, `none` |
| `--llm-model` | provider default | Model name |
| `--llm-api-key` | env var | API key (overrides environment variable) |
| `--top-queries` | `25` | Number of slow query patterns in report |
| `--top-errors` | `20` | Number of error patterns in report |
| `--no-rca` | off | Skip rule-based RCA |
| `--rule-pack` | — | Path to custom rule pack (YAML/TOML) |
| `--config` | `~/.pgloglens.yaml` | Config file path |
| `--verbose`, `-v` | off | Show progress and timing |
| `--workers` | CPU count | Parallel workers for multiple files |

**Relative time examples:**
```bash
pgloglens analyze pg.log --from-time 2h        # last 2 hours
pgloglens analyze pg.log --from-time 30m       # last 30 minutes
pgloglens analyze pg.log --from-time 7d        # last 7 days
pgloglens analyze pg.log --from-time -24h      # same as 24h (legacy form also works)
pgloglens analyze pg.log --from-time 2026-04-14T00:00:00  # absolute ISO timestamp
```

**JSONL format** streams one JSON object per parsed log entry and bypasses the analysis pipeline entirely — useful for feeding into `jq`, custom scripts, or downstream tools:
```bash
# All slow queries over 5 seconds
pgloglens analyze pg.log --format jsonl | jq 'select(.duration_ms > 5000)'

# Only ERROR-level entries for a specific database
pgloglens analyze pg.log --format jsonl | jq 'select(.log_level == "ERROR" and .database == "myapp")'

# Save raw entries for external processing
pgloglens analyze pg.log --format jsonl -o entries.jsonl
```

### `pgloglens watch`

```
pgloglens watch [OPTIONS] LOG_FILE
```

| Option | Default | Description |
|--------|---------|-------------|
| `--alert-slow-ms` | `5000` | Alert on queries slower than this |
| `--alert-errors` | `10` | Alert after N errors per minute |
| `--webhook-url` | — | POST JSON alerts to webhook |
| `--interval` | `5` | Polling interval in seconds |
| `--watch-llm-provider` | `none` | Real-time LLM analysis of alerting queries |

### `pgloglens summary`

Quick health check ideal for CI/CD pipelines. **Exit codes are on by default** — no extra flag needed:

```bash
# Returns exit code 0 (healthy), 1 (critical), or 2 (high severity)
pgloglens summary postgresql.log

# Use directly in deployment scripts
if pgloglens summary postgresql.log; then
    kubectl rollout restart deployment/api
fi

# Analyze multiple files
pgloglens summary /var/log/postgresql/*.log

# Suppress exit codes (always exits 0)
pgloglens summary postgresql.log --no-exit-code
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No critical or high severity findings |
| `1` | One or more CRITICAL findings |
| `2` | One or more HIGH findings (no critical) |

### `pgloglens config`

```bash
pgloglens config init        # Create ~/.pgloglens.yaml with all options documented
pgloglens config show        # Show resolved configuration
```

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
pgloglens timeline postgresql.log
pgloglens timeline logs/*.log --format markdown -o incident.md
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
pgloglens save postgresql.log -o baseline.json --label production-baseline
pgloglens save logs/*.log -o before-deploy.json
```

### `pgloglens dump`

Export normalized queries with statistics:

```bash
pgloglens dump postgresql.log --format csv -o queries.csv
pgloglens dump postgresql.log --format json --min-count 5 --min-duration-ms 500
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f` | `text` | Output format: `text`, `csv`, `json` |
| `--output`, `-o` | stdout | Output file path |
| `--min-count` | `1` | Minimum occurrence count to include |
| `--min-duration-ms` | `100` | Minimum avg duration to include (ms) |

### `pgloglens index-advisor`

AI-powered index recommendations:

```bash
pgloglens index-advisor postgresql.log --llm-provider openai
pgloglens index-advisor pg.log --llm-provider anthropic --top-queries 15 -o indexes.json
```

### `pgloglens rules`

Manage custom rule packs:

```bash
pgloglens rules init --path ~/.pgloglens/rules/custom.yaml
pgloglens rules list
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
  alert_slow_ms: 5000
  interval_seconds: 5

# RCA rule threshold overrides — tune for your environment.
# Omit any key to keep the built-in default.
rca_thresholds:
  connection_warn: 80          # warn at N peak connections (default: 80)
  connection_critical: 150     # critical at N peak connections (default: 150)
  checkpoint_freq_warn: 3      # warn after N checkpoint-too-frequent messages
  checkpoint_slow_ms: 60000    # warn when avg checkpoint > N ms (60s)
  lock_warn: 10                # warn at N lock wait events
  lock_critical: 50
  deadlock_warn: 2
  temp_file_mb: 100            # flag temp files >= N MB
  temp_file_high_mb: 1024      # HIGH severity temp files >= N MB
  auth_fail_warn: 5
  auth_fail_critical: 50
  long_tx_warn_ms: 300000      # warn on transactions longer than 5 min
  long_tx_critical_ms: 3600000 # critical on transactions longer than 1 hr
  error_storm_threshold: 50    # warn when > N errors per 5-minute window
```

**Why override thresholds?** Default values suit a typical 100-connection PostgreSQL instance. On a 500-connection server the `connection_warn: 80` threshold will fire constantly. Override `connection_warn: 200` and `connection_critical: 450` in your config to get actionable alerts instead of noise.

## Parse Error Visibility

pgloglens automatically validates parse health after processing each log file. If more than 5% of log entries fail to parse, a warning is printed to stderr:

```
[WARNING] Parse error rate: 12.3% (1,234 of 10,000 entries failed to parse).
Check --log-line-prefix or --platform if the format differs from default stderr.
```

Common causes:
- Log format changed after a PostgreSQL version upgrade
- `log_line_prefix` in `postgresql.conf` differs from the auto-detected pattern — pass `--log-line-prefix '%t [%p] %u@%d '` explicitly
- Using RDS/CloudSQL logs without `--platform rds` / `--platform cloudsql`

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
| `syslog2` | syslog (EDB) | EDB/EnterpriseDB syslog variant |
| `csvlog` | `csvlog` | RFC 4180 CSV with all 23+ PostgreSQL columns |
| `jsonlog` | `jsonlog` (PG 15+) | One JSON object per line |
| `rds` | — | AWS RDS/Aurora stderr variant |
| `cloudsql` | — | GCP Cloud SQL JSON-encapsulated format |
| `logplex` | — | Heroku logplex format |
| `redshift` | — | Amazon Redshift log format |
| `pgbouncer` | — | PgBouncer connection pooler logs |

Compressed files (`.gz`, `.bz2`, `.lz4`, `.zst`, `.xz`, `.zip`) are handled transparently.

PostgreSQL log format is configured in `postgresql.conf`:
```
log_destination = 'stderr'  # or csvlog, jsonlog, syslog
logging_collector = on
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000  # log queries > 1s
log_line_prefix = '%t [%p] %u@%d '  # recommended for pgloglens
log_lock_waits = on
log_temp_files = 0           # log all temp files
log_autovacuum_min_duration = 0
log_checkpoints = on
```

## Rule-Based RCA Rules

pgloglens evaluates 22+ deterministic rules. All thresholds are configurable via `rca_thresholds` in the config file.

| Rule ID | Severity | Default Trigger | Recommendation |
|---------|----------|----------------|----------------|
| `HIGH_CHECKPOINT_FREQUENCY` | HIGH | ≥3 checkpoint warnings | Increase `max_wal_size` |
| `SLOW_CHECKPOINTS` | MEDIUM | Avg checkpoint >60s | Move WAL to faster disk |
| `CONNECTION_EXHAUSTION` | CRITICAL/HIGH | Peak connections ≥150/80 | Deploy PgBouncer |
| `LOCK_STORMS` | CRITICAL/HIGH | ≥50/10 lock wait events | Review transaction ordering |
| `DEADLOCK_PATTERN` | HIGH | ≥2 deadlocks | Canonical lock ordering |
| `TEMP_FILE_ABUSE` | HIGH/MEDIUM | Temp files ≥100MB | Increase `work_mem` |
| `AUTOVACUUM_LAGGING` | HIGH/MEDIUM | Table vacuumed ≥10x | Adjust `fillfactor` |
| `AUTH_FAILURES_SPIKE` | CRITICAL/HIGH | ≥50/5 auth failures | Check pg_hba.conf |
| `REPLICATION_LAG` | CRITICAL/HIGH | Lag ≥100/any MB | Check standby I/O |
| `OOM_KILLER` | CRITICAL | OOM events | Reduce `shared_buffers` |
| `SLOW_QUERY_REGRESSION` | HIGH | Upward duration slope | `ANALYZE`, `REINDEX` |
| `ERROR_STORM` | CRITICAL | >50 errors/5min | Circuit breaker |
| `SSL_FATAL_ERRORS` | HIGH | SSL FATAL events | Check certificates |
| `DISK_FULL` | CRITICAL | Write failure events | Free disk space |
| `LONG_RUNNING_TRANSACTIONS` | CRITICAL/HIGH | Queries >5min/1hr | Set `statement_timeout` |
| `HIGH_SESSION_IDLE_TIME` | MEDIUM | Idle >70% of session | Deploy PgBouncer |
| `QUERY_TYPE_IMBALANCE` | HIGH | DELETE/UPDATE >40% + locks | Batch DML off-peak |
| `PREPARE_PHASE_BOTTLENECK` | MEDIUM | Parse >20% of execute | Use prepared statements |
| `AUTOVACUUM_WAL_AMPLIFICATION` | HIGH | Autovacuum >100MB WAL | `pg_repack` |
| `CONNECTION_STORM_BY_HOST` | HIGH | Single host >60% conns | Check pooling on host |
| `MANAGED_PLATFORM_DETECTED` | INFO | RDS/Redshift detected | Use platform tools |
| `PGBOUNCER_POOL_EXHAUSTION` | CRITICAL | >10 pool errors | Increase pool size |
| `CANCELLED_QUERY_STORM` | HIGH | >20 cancellations | Review `statement_timeout` |

## Architecture

```
pgloglens/
├── cli.py       Click commands — argument parsing, orchestration
├── parser.py    Streaming log parser — 10 format handlers, auto-detect, parse error tracking
├── analyzer.py  Aggregation engine — slow queries, errors, connections, etc.
├── rca.py       22+ deterministic RCA rules → RCAFinding objects; RCAConfig for thresholds
├── llm.py       Unified LLM interface (OpenAI / Anthropic / Ollama / Google)
├── reporter.py  5 output renderers — terminal/HTML/JSON/Markdown/JSONL
├── models.py    Pydantic v2 data models
├── prefix.py    log_line_prefix pattern compiler (18 escape sequences)
├── compare.py   Diff/comparison functionality for before/after analysis
├── timeline.py  Incident timeline reconstruction from log events
├── rules.py     Custom rule pack support (YAML/TOML)
├── pgss.py      Optional pg_stat_statements snapshot correlation
└── utils.py     Utility functions (percentile calculations, etc.)
```

**Data flow:**
```
LogFile(s) → parser.py → LogEntry stream → analyzer.py → AnalysisResult
                 ↓                                              ↓
           parse_errors                                   rca.py (RCAConfig)
           warning if                                          ↓
           rate > 5%                                     rules.py → Custom rules
                                                               ↓
                                                         llm.py → AI analysis text
                                                               ↓
                                                         reporter.py → Report
                                                               ↓
                                          compare.py / timeline.py → Specialized outputs
```

## pgloglens vs pgBadger

| Feature | pgloglens | pgBadger |
|---------|-----------|---------|
| Slow query P50/P95/P99 | ✅ | ✅ |
| Query normalization | ✅ | ✅ |
| HTML report | ✅ | ✅ |
| JSON/Markdown output | ✅ | ❌ |
| **JSON Lines (JSONL) streaming** | ✅ | ❌ |
| **LLM-powered RCA** | ✅ | ❌ |
| **22+ Rule-based RCA** | ✅ | ❌ |
| **Configurable RCA thresholds** | ✅ | ❌ |
| **Parse error visibility** | ✅ | ❌ |
| **Query regression detection** | ✅ | ❌ |
| **Real-time watch mode** | ✅ | ❌ |
| **Webhook alerting** | ✅ | ❌ |
| **CI/CD exit codes (default)** | ✅ | ❌ |
| **Config file support** | ✅ | Partial |
| **gzip/bz2/lz4/zst transparent** | ✅ | ✅ |
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

# Run all unit tests
pytest tests/ -v

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
python -m pgloglens.cli analyze tests/sample_pg.log --format jsonl | jq 'select(.duration_ms != null)'
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
