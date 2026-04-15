# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pgloglens is a PostgreSQL log analyzer with LLM-powered root cause analysis. It parses PostgreSQL log files (stderr, syslog, csvlog, jsonlog, gzip-compressed) and produces actionable insights including rule-based RCA and optional AI-powered diagnosis via OpenAI, Anthropic, Google Gemini, or Ollama. Outputs: terminal, HTML, JSON, Markdown, JSONL (streaming).

Author: Vibhor Kumar

## Build and Development Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run a single test
pytest tests/test_parser.py::test_parse_stderr_line_basic -v

# Format code
black pgloglens/ tests/

# Type check
mypy pgloglens/

# Run analyzer against sample log
python -m pgloglens.cli analyze tests/sample_pg.log --verbose
python -m pgloglens.cli analyze tests/sample_pg.log --format html -o /tmp/report.html

# Stream raw entries as JSONL (bypasses analysis pipeline)
python -m pgloglens.cli analyze tests/sample_pg.log --format jsonl | jq .

# Summarize with CI-friendly exit codes (default on; use --no-exit-code to suppress)
python -m pgloglens.cli summary tests/sample_pg.log
```

## Architecture

```
pgloglens/
├── cli.py       # Click commands - argument parsing, orchestration
├── parser.py    # Streaming log parser - 10 format handlers, auto-detect
├── analyzer.py  # Aggregation engine - slow queries, errors, connections, etc.
├── rca.py       # 22+ deterministic RCA rules -> RCAFinding objects
├── llm.py       # Unified LLM interface (OpenAI / Anthropic / Ollama / Google)
├── reporter.py  # 5 output renderers - terminal/HTML/JSON/Markdown/JSONL
├── models.py    # Pydantic v2 data models
├── prefix.py    # log_line_prefix pattern compiler (18 escape sequences)
├── compare.py   # Diff/comparison functionality for before/after analysis
├── timeline.py  # Incident timeline reconstruction from log events
├── rules.py     # Custom rule pack support (YAML/TOML)
├── pgss.py      # Optional pg_stat_statements snapshot correlation
└── utils.py     # Utility functions (percentile calculations, etc.)
```

**Data flow:**
```
LogFile(s) -> parser.py -> LogEntry stream -> analyzer.py -> AnalysisResult
                 |                                                |
          parse_errors /                                    rca.py (RCAConfig) -> RCAFinding list
          entries_attempted                                       |
          (warn if ≥5% fail)                                rules.py -> Custom rules
                                                                  |
                                                             llm.py -> AI analysis text
                                                                  |
                                                             reporter.py -> Report
                                                                  |
                                          compare.py / timeline.py -> Specialized outputs

JSONL path (--format jsonl): LogFile(s) -> parser.py -> LogEntry stream -> stdout/file (bypasses analyzer)
```

## Key CLI Commands

- `pgloglens analyze` - Main analysis command with many filtering options
- `pgloglens watch` - Real-time log monitoring with alerts
- `pgloglens dump` - Export normalized queries with stats
- `pgloglens index-advisor` - AI-powered index recommendations
- `pgloglens config init|show` - Configuration management
- `pgloglens diff` - Compare two analyses to detect regressions
- `pgloglens timeline` - Generate incident timeline from logs
- `pgloglens save` - Save analysis artifact for later comparison
- `pgloglens summary` - Quick 5-line health check; exits non-zero on issues by default (`--no-exit-code` to suppress)
- `pgloglens rules init|list` - Custom rule pack management

## Notable Implementation Details

### Configurable RCA Thresholds
`rca.py` exposes an `RCAConfig` dataclass (22 fields) with defaults matching the original hardcoded values. A module-level `_rca_config` global is set by `run_rca()` before executing rules; individual rules call `get_rca_config()` to read it. Config file key: `rca_thresholds` (map of field names to numeric overrides). Example:

```toml
[rca_thresholds]
connection_warn = 150
temp_file_mb = 256
deadlock_count = 3
```

### Parse Error Visibility
`LogParser` accumulates `parse_errors` and `entries_attempted` counters during parsing. After `process_entries()`, `cli.py` copies these to `AnalysisResult` and emits a stderr warning when the error rate is ≥5%. This surfaces log format mismatches early without failing the run.

### JSONL Output Format (`--format jsonl`)
JSONL exits the analysis pipeline early in `cmd_analyze` — it calls `_stream_jsonl()` which writes one JSON object per line (each a serialized `LogEntry`) to stdout or `-o FILE`. No `AnalysisResult` is produced. Useful for piping into `jq` or custom tooling.

### Relative Time Flags
`--from-time` / `--until-time` accept `2h`, `30m`, `7d` (no leading minus). The `_parse_relative_time()` helper strips any accidental minus prefix, then tries `h`/`m`/`d` suffixes before falling back to dateutil/fromisoformat for absolute timestamps.

### `pgloglens dump` Default Duration
`--min-duration-ms` defaults to **100 ms** (was 0). Prevents noise from trivial queries in dump output.

### `pgloglens summary` Exit Codes
Exit codes are **on by default**. Use `--no-exit-code` to suppress (e.g., in non-CI contexts). Exit 0 = healthy, 1 = warnings, 2 = critical issues.

### Reporter and `--top-queries`
The analyzer already truncates `result.slow_queries` to `[:self.top_queries]` before storing. The reporter renders all entries in the list without an additional cap, so `--top-queries N` is fully respected.

## Supported Log Formats

The parser auto-detects: stderr (default), syslog, syslog2 (EDB), csvlog, jsonlog (PG 15+), pgbouncer, rds, logplex (Heroku), redshift, cloudsql. Compressed files (.gz, .bz2, .lz4, .zst, .xz, .zip) are handled transparently.

## LLM Provider Setup

Requires environment variables: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` (Ollama needs no key). LLM features are optional - the tool works without them for rule-based analysis.

## Testing

### Quick Test Run (Unit Tests)

```bash
# Run all unit tests
pytest tests/test_parser.py tests/test_analyzer.py -v

# Run a specific test
pytest tests/test_parser.py::test_parse_stderr_line_basic -v

# Run with coverage
pytest tests/ -v --cov=pgloglens --cov-report=term-missing
```

### Docker Integration Tests

For comprehensive validation against real PostgreSQL logs:

```bash
# Full automated test run
./scripts/run_docker_tests.sh

# Or manually:
docker-compose up -d                          # Start PostgreSQL
python tests/docker/generate_logs.py          # Generate test logs
docker cp pgloglens-test-pg:/var/log/postgresql/postgresql.log tests/docker/
pytest tests/test_integration.py -v --docker  # Run integration tests
docker-compose down -v                        # Cleanup
```

### Test Coverage

Tests are organized by capability:

| Test File | Coverage |
|-----------|----------|
| `test_parser.py` | Format detection, line parsing, extraction functions |
| `test_analyzer.py` | Statistics, aggregation, RCA rules, output formats |
| `test_prefix.py` | log_line_prefix compiler, all 18 escape sequences |
| `test_compare.py` | Diff/comparison functionality, artifact save/load |
| `test_timeline.py` | Incident timeline reconstruction |
| `test_rules.py` | Custom rule packs, YAML parsing, severity overrides |
| `test_pgss.py` | pg_stat_statements snapshot loading and correlation |
| `test_integration.py` | End-to-end validation with Docker-generated logs |

### Adding New Tests

When adding features, add tests that cover:
1. **Parser level** (`test_parser.py`): New regex patterns, extraction functions
2. **Analyzer level** (`test_analyzer.py`): New statistics, aggregation logic
3. **Integration level** (`test_integration.py`): End-to-end behavior validation

Use the existing fixtures:
- `tests/sample_pg.log` - Synthetic stderr log with all event types
- `tests/edb_syslog.log` - EDB/syslog2 format sample
- `tests/docker/postgresql.log` - Real logs from Docker (after running `generate_logs.py`)

### Test Markers

```bash
pytest tests/ -v                     # Unit tests only
pytest tests/ -v --docker            # Include Docker integration tests
pytest tests/ -v --slow              # Include slow tests
pytest tests/ -v --docker --slow     # All tests
```

## Dependencies

Core (pure Python): click, rich, tqdm, pydantic v2, python-dateutil, jinja2

Optional LLM: openai, anthropic, google-genai

Optional: pyyaml (for config files)

Dev: pytest, pytest-asyncio, black, mypy, ruff
