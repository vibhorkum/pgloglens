# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pgloglens is a PostgreSQL log analyzer with LLM-powered root cause analysis. It parses PostgreSQL log files (stderr, syslog, csvlog, jsonlog, gzip-compressed) and produces actionable insights including rule-based RCA and optional AI-powered diagnosis via OpenAI, Anthropic, Google Gemini, or Ollama.

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
```

## Architecture

```
pgloglens/
├── cli.py       # Click commands - argument parsing, orchestration
├── parser.py    # Streaming log parser - 10 format handlers, auto-detect
├── analyzer.py  # Aggregation engine - slow queries, errors, connections, etc.
├── rca.py       # 14+ deterministic RCA rules -> RCAFinding objects
├── llm.py       # Unified LLM interface (OpenAI / Anthropic / Ollama / Google)
├── reporter.py  # 4 output renderers - terminal/HTML/JSON/Markdown
├── models.py    # Pydantic v2 data models
├── prefix.py    # log_line_prefix pattern compiler
└── utils.py     # Utility functions (percentile calculations, etc.)
```

**Data flow:**
```
LogFile(s) -> parser.py -> LogEntry stream -> analyzer.py -> AnalysisResult
                                                                  |
                                                             rca.py -> RCAFinding list
                                                                  |
                                                             llm.py -> AI analysis text
                                                                  |
                                                             reporter.py -> Report
```

## Key CLI Commands

- `pgloglens analyze` - Main analysis command with many filtering options
- `pgloglens watch` - Real-time log monitoring with alerts
- `pgloglens dump` - Export normalized queries with stats
- `pgloglens index-advisor` - AI-powered index recommendations
- `pgloglens config init|show` - Configuration management

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
