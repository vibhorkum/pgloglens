# pgloglens

**PostgreSQL log analyzer with LLM-powered root cause analysis.**

`pgloglens` parses PostgreSQL log files and produces actionable insights that go beyond what pgBadger provides — including rule-based root cause analysis and optional AI-powered diagnosis via OpenAI, Anthropic, Google Gemini, or local Ollama models.

## Features

- **Multi-format log parsing**: stderr, syslog, csvlog, jsonlog (PostgreSQL 15+), gzip-compressed
- **Slow query analysis**: normalized query patterns, P50/P95/P99 percentiles, regression detection
- **Error pattern clustering**: SQLSTATE grouping, error storms, trend detection
- **Lock & deadlock analysis**: lock chain reconstruction, most-blocking queries
- **Connection statistics**: peak concurrent, by-hour charts, auth failure tracking
- **Checkpoint analysis**: frequency warnings, duration trending, WAL write amplification
- **Autovacuum insights**: table frequency analysis, bloat indicators
- **Temp file analysis**: work_mem candidates with size-based recommendations
- **Replication lag events**: standby health monitoring
- **Rule-based RCA**: 14 deterministic rules covering the most common PostgreSQL failure modes
- **LLM-powered analysis**: send summarized findings to GPT-4o, Claude, Gemini, or local Ollama
- **Four output formats**: terminal (rich), HTML (interactive), JSON, Markdown

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
