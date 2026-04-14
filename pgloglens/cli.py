"""Click-based CLI entrypoint for pgloglens v2.0."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

import click

from . import __version__
from .analyzer import Analyzer
from .models import AnalysisResult
from .parser import LogParser
from .rca import run_rca
from .reporter import generate_report


# ---------------------------------------------------------------------------
# Pure-Python YAML helpers (pyyaml optional)
# ---------------------------------------------------------------------------

def _yaml_load(text: str) -> dict:
    """Parse simple YAML config. Uses pyyaml if available, else a minimal parser."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    result: dict = {}
    current: dict = result
    stack: list = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
            current = stack[-1][1] if stack else result
        if not val:
            new_dict: dict = {}
            current[key] = new_dict
            stack.append((indent, current))
            current = new_dict
        else:
            if val.lower() in ("true", "yes"):
                current[key] = True
            elif val.lower() in ("false", "no"):
                current[key] = False
            elif val.lower() in ("null", "~", ""):
                current[key] = None
            else:
                try:
                    current[key] = int(val)
                except ValueError:
                    try:
                        current[key] = float(val)
                    except ValueError:
                        current[key] = val.strip('"\'')
    return result


def _yaml_dump(data: dict, indent: int = 0) -> str:
    """Serialize dict to YAML-like text. Uses pyyaml if available."""
    try:
        import yaml  # type: ignore
        return yaml.dump(data, default_flow_style=False)
    except ImportError:
        pass
    lines = []
    prefix = "  " * indent
    for k, v in data.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.append(_yaml_dump(v, indent + 1))
        elif isinstance(v, list):
            lines.append(f"{prefix}{k}:")
            for item in v:
                lines.append(f"{prefix}  - {item}")
        elif v is None:
            lines.append(f"{prefix}{k}: null")
        elif isinstance(v, bool):
            lines.append(f"{prefix}{k}: {'true' if v else 'false'}")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config(config_path: Optional[str]) -> dict:
    """Load YAML config file, returning an empty dict if not found."""
    paths = []
    if config_path:
        paths.append(Path(config_path))
    paths.append(Path.home() / ".pgloglens.yaml")
    paths.append(Path.home() / ".pgloglens.yml")

    for p in paths:
        if p.exists():
            try:
                with open(p) as fh:
                    return _yaml_load(fh.read()) or {}
            except Exception:
                pass
    return {}


def _parse_relative_time(s: str) -> Optional[datetime]:
    """Parse relative time strings like -1h, -24h, -30m, -7d."""
    s = s.strip()
    if s.startswith("-"):
        try:
            if s.endswith("h"):
                hours = float(s[1:-1])
                return datetime.now() - timedelta(hours=hours)
            if s.endswith("m"):
                mins = float(s[1:-1])
                return datetime.now() - timedelta(minutes=mins)
            if s.endswith("d"):
                days = float(s[1:-1])
                return datetime.now() - timedelta(days=days)
        except ValueError:
            pass
    # Try ISO format
    try:
        from dateutil import parser as dtparser
        return dtparser.parse(s)
    except Exception:
        pass
    # Fallback: try datetime.fromisoformat
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _resolve_env_var(val: str) -> Optional[str]:
    """Resolve ${ENV_VAR} placeholders in config values."""
    if not val:
        return None
    m = re.match(r"\$\{([^}]+)\}", val)
    if m:
        return os.environ.get(m.group(1), val)
    return val


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

def _common_analyze_options(fn):
    """Decorator that adds common analysis options to a Click command."""
    decorators = [
        click.option("--format", "-f", "output_format",
                     type=click.Choice(["terminal", "html", "json", "markdown"], case_sensitive=False),
                     default="terminal", show_default=True, help="Output format"),
        click.option("--output", "-o", "output_file",
                     type=click.Path(), default=None, help="Output file path"),
        click.option("--slow-query-threshold", "slow_query_threshold", type=float,
                     default=1000.0, show_default=True, help="Min duration (ms) for slow query"),
        click.option("--database", "-d", type=str, default=None,
                     help="Filter by database name"),
        click.option("--user", "-u", type=str, default=None,
                     help="Filter by PostgreSQL username"),
        click.option("--llm-provider",
                     type=click.Choice(["openai", "anthropic", "ollama", "google", "none"],
                                       case_sensitive=False),
                     default="none", show_default=True, help="LLM provider for AI analysis"),
        click.option("--llm-model", type=str, default=None,
                     help="LLM model name (overrides default for provider)"),
        click.option("--llm-api-key", type=str, default=None,
                     help="LLM API key (overrides env var)"),
        click.option("--top-queries", type=int, default=25, show_default=True,
                     help="Number of top slow queries to include"),
        click.option("--top-errors", type=int, default=20, show_default=True,
                     help="Number of top error patterns to include"),
        click.option("--no-rca", is_flag=True, default=False,
                     help="Skip rule-based root cause analysis"),
        click.option("--config", "config_file", type=click.Path(), default=None,
                     help="Config file path"),
        click.option("--verbose", "-v", is_flag=True, default=False),
        click.option("--workers", type=int, default=None,
                     help="Parallel workers for multiple files (default: CPU count)"),
    ]
    for dec in reversed(decorators):
        fn = dec(fn)
    return fn


# ---------------------------------------------------------------------------
# Main group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="pgloglens")
def main():
    """pgloglens v2.0 — PostgreSQL log analyzer with LLM-powered root cause analysis.

    Analyzes PostgreSQL log files and produces detailed reports covering slow
    queries, errors, lock contention, checkpoints, autovacuum, sessions, query
    types, and more.

    \b
    Quick start:
      pgloglens analyze postgresql.log
      pgloglens analyze postgresql.log --format html -o report.html
      pgloglens analyze postgresql.log --llm-provider openai --format html -o report.html
      pgloglens dump postgresql.log --format csv -o queries.csv
      pgloglens index-advisor postgresql.log --llm-provider openai
    """


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@main.command("analyze")
@click.argument("log_files", nargs=-1, required=False, type=click.Path(exists=True))
@_common_analyze_options
@click.option("--from-time", "from_time", type=str, default=None,
              help="Start time (ISO or relative: -1h, -24h, -7d)")
@click.option("--to-time", "to_time", type=str, default=None,
              help="End time filter (ISO or relative: -1h)")
@click.option("--application", type=str, default=None,
              help="Filter by application name")
@click.option("--host", type=str, default=None,
              help="Filter by client host/IP")
@click.option("--pid", "pids", type=int, multiple=True,
              help="Filter by session PID (repeatable)")
@click.option("--session-id", "session_ids", type=str, multiple=True,
              help="Filter by session ID (repeatable)")
@click.option("--exclude-query", "exclude_queries", type=str, multiple=True,
              help="Exclude queries matching regex (repeatable)")
@click.option("--include-query", "include_queries", type=str, multiple=True,
              help="Only include queries matching regex (repeatable)")
@click.option("--exclude-db", "exclude_dbs", type=str, multiple=True,
              help="Exclude database (repeatable)")
@click.option("--exclude-user", "exclude_users", type=str, multiple=True,
              help="Exclude user (repeatable)")
@click.option("--select-only", is_flag=True, default=False,
              help="Only analyze SELECT queries")
@click.option("--anonymize", is_flag=True, default=False,
              help="Replace literal values with placeholders")
@click.option("--dump-queries", "dump_queries_file", type=click.Path(), default=None,
              help="Dump all normalized queries with counts to file")
@click.option("--show-plans", is_flag=True, default=False,
              help="Show auto_explain plans in output")
@click.option("--ai-slow-queries", "ai_slow_queries", type=int, default=0,
              show_default=True, help="AI-analyze top N slow queries individually (0=disabled)")
@click.option("--ai-explain-plans", is_flag=True, default=False,
              help="AI-analyze captured auto_explain plans")
@click.option("--ai-generate-config", is_flag=True, default=False,
              help="Ask LLM to generate optimized postgresql.conf section")
@click.option("--ai-index-recommendations", "ai_index_recs", is_flag=True, default=False,
              help="Ask LLM to generate CREATE INDEX recommendations")
@click.option("--stream-llm", is_flag=True, default=False,
              help="Stream LLM output token by token to terminal")
@click.option("--log-line-prefix", "log_line_prefix", default=None,
              help="PostgreSQL log_line_prefix value (e.g. '%%m [%%p] %%q%%u@%%d/%%a '). "
                   "Auto-detected if not specified. Use 'auto' to force auto-detection.")
@click.option("--list-prefixes", is_flag=True, default=False,
              help="List all well-known log_line_prefix patterns and exit")
@click.option("--platform",
              type=click.Choice(["auto", "postgresql", "rds", "redshift", "cloudsql", "heroku", "pgbouncer"],
                                case_sensitive=False),
              default="auto", show_default=True, help="Source platform hint")
@click.option("--incremental", "incremental_file", type=click.Path(), default=None,
              help="Incremental mode: state file path")
@click.option("--explode-by-database", "explode_dir", type=click.Path(), default=None,
              help="Generate one report per database in this directory")
@click.option("--summary-only", is_flag=True, default=False,
              help="Output only a 5-line summary (same as 'pgloglens summary')")
@click.option("--exit-code", "use_exit_code", is_flag=True, default=False,
              help="Exit with non-zero code if critical/high issues found")
@click.option("--rule-pack", "rule_pack_path", type=click.Path(), default=None,
              help="Path to custom rule pack (YAML/TOML)")
@click.option("--pgss-snapshot", "pgss_snapshot_path", type=click.Path(), default=None,
              help="Path to pg_stat_statements snapshot for correlation")
def cmd_analyze(
    log_files: Tuple[str, ...],
    output_format: str,
    output_file: Optional[str],
    slow_query_threshold: float,
    from_time: Optional[str],
    to_time: Optional[str],
    database: Optional[str],
    user: Optional[str],
    llm_provider: str,
    llm_model: Optional[str],
    llm_api_key: Optional[str],
    top_queries: int,
    top_errors: int,
    no_rca: bool,
    config_file: Optional[str],
    verbose: bool,
    workers: Optional[int],
    application: Optional[str],
    host: Optional[str],
    pids: Tuple[int, ...],
    session_ids: Tuple[str, ...],
    exclude_queries: Tuple[str, ...],
    include_queries: Tuple[str, ...],
    exclude_dbs: Tuple[str, ...],
    exclude_users: Tuple[str, ...],
    select_only: bool,
    anonymize: bool,
    dump_queries_file: Optional[str],
    show_plans: bool,
    ai_slow_queries: int,
    ai_explain_plans: bool,
    ai_generate_config: bool,
    ai_index_recs: bool,
    stream_llm: bool,
    log_line_prefix: Optional[str],
    list_prefixes: bool,
    platform: str,
    incremental_file: Optional[str],
    explode_dir: Optional[str],
    summary_only: bool,
    use_exit_code: bool,
    rule_pack_path: Optional[str],
    pgss_snapshot_path: Optional[str],
):
    """Analyze one or more PostgreSQL log files.

    \b
    Examples:
      pgloglens analyze postgresql.log
      pgloglens analyze *.log --format html -o report.html
      pgloglens analyze pg.log --slow-query-threshold 500 --top-queries 50
      pgloglens analyze pg.log --llm-provider openai --llm-model gpt-4o
      pgloglens analyze pg.log --from-time -24h --database myapp
      pgloglens analyze pg.log --application myservice --ai-slow-queries 5
      pgloglens analyze pg.log --ai-generate-config --ai-index-recommendations
      pgloglens analyze pg.log --stream-llm --llm-provider anthropic
      pgloglens analyze pg.log --platform rds --anonymize
    """
    # --list-prefixes: print all known patterns and exit
    if list_prefixes:
        from .prefix import COMMON_PREFIXES, prefix_to_description
        click.echo("Known log_line_prefix patterns:\n")
        for name, prefix_str in COMMON_PREFIXES.items():
            desc = prefix_to_description(prefix_str)
            click.echo(f"  {name}")
            click.echo(f"    prefix : {prefix_str!r}")
            click.echo(f"    fields : {desc}")
            click.echo()
        raise SystemExit(0)

    # Require log files unless --list-prefixes was given
    if not log_files:
        raise click.UsageError("Missing argument 'LOG_FILES...'. Provide at least one log file, or use --list-prefixes.")

    # Load config and apply defaults
    cfg = _load_config(config_file)
    slow_query_threshold = cfg.get("slow_query_threshold_ms", slow_query_threshold)
    top_queries = cfg.get("report", {}).get("top_queries", top_queries)
    top_errors = cfg.get("report", {}).get("top_errors", top_errors)

    if llm_provider == "none":
        cfg_provider = cfg.get("llm", {}).get("provider", "none")
        if cfg_provider != "none":
            llm_provider = cfg_provider
            llm_model = llm_model or cfg.get("llm", {}).get("model")
            llm_api_key = llm_api_key or _resolve_env_var(cfg.get("llm", {}).get("api_key", ""))

    if output_format == "terminal" and not output_file:
        output_format = cfg.get("report", {}).get("format", "terminal")

    # Parse time filters
    from_dt = _parse_relative_time(from_time) if from_time else None
    to_dt = _parse_relative_time(to_time) if to_time else None

    # Compile query filters
    exclude_query_patterns = [re.compile(p, re.IGNORECASE) for p in exclude_queries]
    include_query_patterns = [re.compile(p, re.IGNORECASE) for p in include_queries]

    if verbose:
        click.echo(f"[pgloglens] v2.0 — Analyzing {len(log_files)} file(s)...")
        click.echo(f"  Slow query threshold: {slow_query_threshold}ms")
        click.echo(f"  Platform: {platform}")
        if from_dt:
            click.echo(f"  From: {from_dt}")
        if to_dt:
            click.echo(f"  To: {to_dt}")
        if application:
            click.echo(f"  Application filter: {application}")
        if host:
            click.echo(f"  Host filter: {host}")
        if exclude_dbs:
            click.echo(f"  Excluded DBs: {', '.join(exclude_dbs)}")
        if exclude_users:
            click.echo(f"  Excluded users: {', '.join(exclude_users)}")
        if select_only:
            click.echo("  Mode: SELECT-only")
        if anonymize:
            click.echo("  Anonymization: enabled")
        if log_line_prefix:
            click.echo(f"  log_line_prefix: {log_line_prefix!r}")
        else:
            click.echo("  log_line_prefix: (auto-detect)")

    # Handle incremental mode
    incremental_state = None
    if incremental_file:
        incremental_state = _load_incremental_state(incremental_file)
        if verbose and incremental_state:
            click.echo(f"  Incremental mode: resuming from {incremental_state.get('last_parsed_timestamp', 'start')}")

    # Parse and analyze
    t0 = time.time()
    result = _run_analysis(
        log_files=list(log_files),
        slow_query_threshold=slow_query_threshold,
        from_dt=from_dt,
        to_dt=to_dt,
        database=database,
        user=user,
        top_queries=top_queries,
        top_errors=top_errors,
        verbose=verbose,
        workers=workers,
        application=application,
        host=host,
        pids=list(pids),
        session_ids=list(session_ids),
        exclude_query_patterns=exclude_query_patterns,
        include_query_patterns=include_query_patterns,
        exclude_dbs=list(exclude_dbs),
        exclude_users=list(exclude_users),
        select_only=select_only,
        anonymize=anonymize,
        log_line_prefix=log_line_prefix,
    )

    # Set platform
    if platform != "auto":
        result.source_platform = platform

    # Load custom rule pack if provided
    rule_pack = None
    if rule_pack_path:
        try:
            from .rules import load_rule_pack
            rule_pack = load_rule_pack(rule_pack_path)
            if verbose:
                click.echo(f"[pgloglens] Loaded rule pack: {rule_pack.name} ({len(rule_pack.custom_rules)} custom rules)")
        except Exception as e:
            click.echo(f"[WARNING] Could not load rule pack: {e}", err=True)

    # RCA
    if not no_rca:
        if verbose:
            click.echo("[pgloglens] Running rule-based RCA...")
        run_rca(result)

        # Apply rule pack overrides and custom rules
        if rule_pack:
            from .rules import apply_rule_pack_to_findings
            result.rca_findings = apply_rule_pack_to_findings(result.rca_findings, rule_pack)
            # Evaluate custom rules
            custom_findings = rule_pack.evaluate_custom_rules(result)
            if custom_findings:
                result.rca_findings.extend(custom_findings)
                if verbose:
                    click.echo(f"  Added {len(custom_findings)} findings from custom rules")

    # pg_stat_statements correlation
    if pgss_snapshot_path:
        try:
            from .pgss import load_pgss_snapshot, correlate_with_pgss, enrich_result_with_pgss
            if verbose:
                click.echo(f"[pgloglens] Loading pg_stat_statements snapshot: {pgss_snapshot_path}")
            pgss_snapshot = load_pgss_snapshot(pgss_snapshot_path)
            enrich_result_with_pgss(result, pgss_snapshot)
            correlation = correlate_with_pgss(result, pgss_snapshot)
            result.pgss_correlation = correlation
            if verbose:
                click.echo(f"  Matched {correlation.matched_count}/{correlation.total_log_queries} queries ({correlation.match_rate*100:.1f}%)")
        except Exception as e:
            click.echo(f"[WARNING] Could not load pgss snapshot: {e}", err=True)

    # Main LLM analysis
    if llm_provider != "none":
        if verbose:
            click.echo(f"[pgloglens] Running LLM analysis with {llm_provider}...")
        try:
            from .llm import get_provider, build_analysis_context, stream_llm_analysis
            provider_obj = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)

            if stream_llm:
                async def _stream_main():
                    tokens = []
                    async for token in provider_obj.stream_analyze(
                        build_analysis_context(result)
                    ):
                        tokens.append(token)
                        click.echo(token, nl=False)
                    click.echo()
                    return "".join(tokens)
                llm_text = asyncio.run(_stream_main())
            else:
                from .llm import run_llm_analysis
                llm_text = asyncio.run(
                    run_llm_analysis(
                        result,
                        provider_name=llm_provider,
                        model=llm_model,
                        api_key=llm_api_key,
                    )
                )
            result.llm_analysis = llm_text
        except Exception as exc:
            click.echo(f"[WARNING] LLM analysis failed: {exc}", err=True)

        # AI slow query analysis
        if ai_slow_queries > 0 and result.slow_queries:
            if verbose:
                click.echo(f"[pgloglens] AI-analyzing top {ai_slow_queries} slow queries...")
            try:
                from .rca import ai_analyze_slow_queries
                provider_obj = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)
                sq_analyses = asyncio.run(
                    ai_analyze_slow_queries(result.slow_queries, provider_obj, top_n=ai_slow_queries)
                )
                # Attach to result for reporting
                result.ai_slow_query_analyses = sq_analyses
                if verbose:
                    click.echo(f"  Analyzed {len(sq_analyses)} slow queries")
            except Exception as exc:
                click.echo(f"[WARNING] AI slow query analysis failed: {exc}", err=True)

        # AI explain plan analysis
        if ai_explain_plans and result.auto_explain_plans:
            if verbose:
                click.echo(f"[pgloglens] AI-analyzing {len(result.auto_explain_plans)} explain plans...")
            try:
                from .rca import ai_analyze_explain_plan
                provider_obj = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)

                async def _analyze_plans():
                    for plan in result.auto_explain_plans[:10]:
                        plan.ai_analysis = await ai_analyze_explain_plan(plan, provider_obj)

                asyncio.run(_analyze_plans())
            except Exception as exc:
                click.echo(f"[WARNING] AI explain plan analysis failed: {exc}", err=True)

        # AI config generation
        if ai_generate_config:
            if verbose:
                click.echo("[pgloglens] Generating AI postgresql.conf recommendations...")
            try:
                from .rca import ai_generate_postgresql_config
                provider_obj = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)
                config_text = asyncio.run(ai_generate_postgresql_config(result, provider_obj))
                result.ai_generated_config = config_text
                if verbose:
                    click.echo("  Config generated successfully")
            except Exception as exc:
                click.echo(f"[WARNING] AI config generation failed: {exc}", err=True)

        # AI index recommendations
        if ai_index_recs and result.slow_queries:
            if verbose:
                click.echo("[pgloglens] Generating AI index recommendations...")
            try:
                from .rca import ai_generate_index_recommendations
                provider_obj = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)
                index_recs = asyncio.run(
                    ai_generate_index_recommendations(result.slow_queries, provider_obj)
                )
                result.ai_index_recommendations = index_recs
                if verbose:
                    click.echo(f"  Generated {len(index_recs)} index recommendations")
            except Exception as exc:
                click.echo(f"[WARNING] AI index recommendations failed: {exc}", err=True)

    # Dump queries to file if requested
    if dump_queries_file:
        _dump_queries_to_file(result, dump_queries_file, file_format="json")
        if verbose:
            click.echo(f"[pgloglens] Queries dumped to: {dump_queries_file}")

    # Explode by database
    if explode_dir:
        _explode_by_database(result, explode_dir, output_format, verbose)
        return

    # Generate report
    if verbose:
        elapsed = time.time() - t0
        click.echo(f"[pgloglens] Analysis complete in {elapsed:.1f}s")
        click.echo(f"  Slow queries: {len(result.slow_queries)}")
        click.echo(f"  Error patterns: {len(result.error_patterns)}")
        click.echo(f"  RCA findings: {len(result.rca_findings)}")

    # Summary-only mode: just print 5-line summary and optionally exit
    if summary_only:
        critical_count = sum(1 for f in result.rca_findings if f.severity.value == "CRITICAL")
        high_count = sum(1 for f in result.rca_findings if f.severity.value == "HIGH")

        click.echo(f"Entries: {result.total_entries:,}")
        click.echo(f"Slow queries: {len(result.slow_queries)} patterns")
        click.echo(f"Errors: {len(result.error_patterns)} patterns | Deadlocks: {result.deadlock_count}")
        click.echo(f"Findings: {critical_count} critical, {high_count} high, {len(result.rca_findings) - critical_count - high_count} other")

        if result.rca_findings:
            top = result.rca_findings[0]
            click.echo(f"Top issue: [{top.severity.value}] {top.title}")
        else:
            click.echo("Top issue: None")

        if use_exit_code:
            if critical_count > 0:
                sys.exit(1)
            elif high_count > 0:
                sys.exit(2)
        return

    _write_report(result, output_format, output_file)

    # Exit code based on severity (even without summary_only)
    if use_exit_code:
        critical_count = sum(1 for f in result.rca_findings if f.severity.value == "CRITICAL")
        high_count = sum(1 for f in result.rca_findings if f.severity.value == "HIGH")
        if critical_count > 0:
            sys.exit(1)
        elif high_count > 0:
            sys.exit(2)

    # Save incremental state
    if incremental_file:
        _save_incremental_state(incremental_file, result)


def _load_incremental_state(state_file: str) -> Optional[dict]:
    """Load incremental state from JSON file."""
    try:
        with open(state_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _save_incremental_state(state_file: str, result: AnalysisResult) -> None:
    """Save incremental state to JSON file."""
    state = {
        "last_parsed_timestamp": result.time_range_end.isoformat() if result.time_range_end else None,
        "log_file_paths": result.log_file_paths,
        "total_entries_processed": result.total_entries,
    }
    try:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as exc:
        click.echo(f"[WARNING] Could not save incremental state: {exc}", err=True)


def _explode_by_database(
    result: AnalysisResult,
    output_dir: str,
    output_format: str,
    verbose: bool,
) -> None:
    """Generate one report per database."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Collect all databases from slow queries and connections
    databases = set(result.connection_stats.connections_by_database.keys())
    for sq in result.slow_queries:
        databases.update(sq.databases)

    if not databases:
        click.echo("[WARNING] No database data found for explode-by-database.")
        return

    for db in sorted(databases):
        # Build a filtered result for this database
        from copy import deepcopy
        db_result = deepcopy(result)
        db_result.slow_queries = [
            sq for sq in result.slow_queries if db in sq.databases
        ]
        db_result.error_patterns = [
            ep for ep in result.error_patterns if db in ep.affected_databases
        ]

        ext = {"html": ".html", "json": ".json", "markdown": ".md"}.get(output_format, ".txt")
        out_file = out_path / f"report_{db}{ext}"
        generate_report(db_result, format=output_format, output_path=str(out_file))
        if verbose:
            click.echo(f"  Report for database '{db}' written to: {out_file}")

    click.echo(f"[pgloglens] Exploded reports written to: {output_dir}")


def _run_analysis(
    log_files: List[str],
    slow_query_threshold: float,
    from_dt: Optional[datetime],
    to_dt: Optional[datetime],
    database: Optional[str],
    user: Optional[str],
    top_queries: int,
    top_errors: int,
    verbose: bool,
    workers: Optional[int],
    application: Optional[str] = None,
    host: Optional[str] = None,
    pids: Optional[List[int]] = None,
    session_ids: Optional[List[str]] = None,
    exclude_query_patterns=None,
    include_query_patterns=None,
    exclude_dbs: Optional[List[str]] = None,
    exclude_users: Optional[List[str]] = None,
    select_only: bool = False,
    anonymize: bool = False,
    log_line_prefix: Optional[str] = None,
    auto_detect_prefix: bool = True,
) -> AnalysisResult:
    """Parse log files and run analysis."""
    # Auto-detect log_line_prefix if not provided and auto_detect is on
    resolved_prefix = log_line_prefix
    if not resolved_prefix and auto_detect_prefix and log_files:
        try:
            from .prefix import detect_prefix_from_log
            with open(log_files[0], 'r', encoding='utf-8', errors='replace') as _f:
                _sample = [next(_f) for _ in range(50) if True]
            resolved_prefix = detect_prefix_from_log(_sample)
            if verbose and resolved_prefix:
                click.echo(f"  Auto-detected log_line_prefix: {resolved_prefix!r}")
        except Exception:
            resolved_prefix = None

    parser = LogParser(
        slow_query_threshold_ms=slow_query_threshold,
        from_time=from_dt,
        to_time=to_dt,
        filter_database=database,
        filter_user=user,
        filter_application=application,
        filter_host=host,
        filter_pids=pids or [],
        filter_session_ids=session_ids or [],
        exclude_query_re=list(exclude_query_patterns or []),
        include_query_re=list(include_query_patterns or []),
        select_only=select_only,
        anonymize=anonymize,
        log_line_prefix=resolved_prefix,
    )
    analyzer = Analyzer(
        log_file_paths=list(log_files),
        slow_query_threshold_ms=slow_query_threshold,
        top_queries=top_queries,
        top_errors=top_errors,
    )

    # Compile exclude/include filters
    _exclude_patterns = exclude_query_patterns or []
    _include_patterns = include_query_patterns or []
    _exclude_dbs = set(exclude_dbs or [])
    _exclude_users = set(exclude_users or [])

    def _should_include(entry) -> bool:
        """Apply all v2 filters to a log entry."""
        if application and entry.application_name != application:
            return False
        if host and entry.remote_host != host:
            return False
        if pids and entry.pid not in pids:
            return False
        if session_ids and entry.session_id not in session_ids:
            return False
        if _exclude_dbs and entry.database in _exclude_dbs:
            return False
        if _exclude_users and entry.user in _exclude_users:
            return False
        if select_only:
            q = (entry.query or entry.message or "").strip().upper()
            if not q.startswith("SELECT"):
                return False
        query_text = entry.query or entry.message or ""
        for pat in _exclude_patterns:
            if pat.search(query_text):
                return False
        if _include_patterns:
            if not any(pat.search(query_text) for pat in _include_patterns):
                return False
        return True

    def _stream_all_files():
        for path in log_files:
            for entry in parser.parse_file(path, show_progress=verbose or len(log_files) == 1):
                if _should_include(entry):
                    yield entry

    result = analyzer.process_entries(_stream_all_files())
    result.anonymized = anonymize
    return result


def _write_report(result: AnalysisResult, output_format: str, output_file: Optional[str]) -> None:
    """Write the report to the specified output."""
    if output_format == "terminal" and not output_file:
        generate_report(result, format="terminal")
        return

    content = generate_report(result, format=output_format, output_path=output_file)

    if output_file:
        click.echo(f"Report written to: {output_file}")
    elif content:
        click.echo(content)


def _dump_queries_to_file(
    result: AnalysisResult,
    file_path: str,
    file_format: str = "json",
    min_count: int = 1,
    min_duration_ms: float = 0.0,
) -> None:
    """Dump normalized queries with stats to a file."""
    queries = [
        sq for sq in result.slow_queries
        if sq.count >= min_count and sq.avg_duration_ms >= min_duration_ms
    ]
    queries.sort(key=lambda q: q.total_duration_ms, reverse=True)

    if file_format == "json":
        data = [
            {
                "normalized_query": sq.normalized_query,
                "count": sq.count,
                "avg_duration_ms": round(sq.avg_duration_ms, 2),
                "max_duration_ms": round(sq.max_duration_ms, 2),
                "p95_duration_ms": round(sq.p95_duration_ms, 2),
                "total_duration_ms": round(sq.total_duration_ms, 2),
                "query_type": getattr(sq, "query_type", "unknown"),
                "databases": sorted(sq.databases),
                "users": sorted(sq.users),
            }
            for sq in queries
        ]
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    elif file_format == "csv":
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "normalized_query", "count", "avg_duration_ms", "max_duration_ms",
                "p95_duration_ms", "total_duration_ms", "query_type", "databases", "users",
            ])
            writer.writeheader()
            for sq in queries:
                writer.writerow({
                    "normalized_query": sq.normalized_query,
                    "count": sq.count,
                    "avg_duration_ms": round(sq.avg_duration_ms, 2),
                    "max_duration_ms": round(sq.max_duration_ms, 2),
                    "p95_duration_ms": round(sq.p95_duration_ms, 2),
                    "total_duration_ms": round(sq.total_duration_ms, 2),
                    "query_type": getattr(sq, "query_type", "unknown"),
                    "databases": "|".join(sorted(sq.databases)),
                    "users": "|".join(sorted(sq.users)),
                })

    else:  # text
        lines = []
        for sq in queries:
            lines.append(
                f"count={sq.count} avg={sq.avg_duration_ms:.0f}ms "
                f"max={sq.max_duration_ms:.0f}ms total={sq.total_duration_ms:.0f}ms\n"
                f"{sq.normalized_query}\n\n"
            )
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)


# ---------------------------------------------------------------------------
# watch command (v2 enhanced)
# ---------------------------------------------------------------------------

@main.command("watch")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--alert-slow-ms", "alert_slow_ms", type=float, default=5000.0, show_default=True,
              help="Alert threshold for slow queries (ms)")
@click.option("--alert-threshold-ms", "alert_threshold_ms", type=float, default=None,
              hidden=True, help="Alias for --alert-slow-ms (backwards compat)")
@click.option("--alert-errors", "alert_errors", type=int, default=10, show_default=True,
              help="Alert after N errors per minute")
@click.option("--webhook-url", type=str, default=None,
              help="POST JSON alerts to this URL")
@click.option("--watch-llm-provider", "watch_llm_provider",
              type=click.Choice(["openai", "anthropic", "ollama", "google", "none"],
                                case_sensitive=False),
              default="none", help="Use LLM to analyze alert-triggering queries in real time")
@click.option("--llm-provider",
              type=click.Choice(["openai", "anthropic", "ollama", "google", "none"],
                                case_sensitive=False),
              default="none", hidden=True, help="Alias for --watch-llm-provider")
@click.option("--interval", type=int, default=5, show_default=True,
              help="Polling interval in seconds")
def cmd_watch(
    log_file: str,
    alert_slow_ms: float,
    alert_threshold_ms: Optional[float],
    alert_errors: int,
    webhook_url: Optional[str],
    watch_llm_provider: str,
    llm_provider: str,
    interval: int,
):
    """Watch a PostgreSQL log file in real-time (tail mode).

    Monitors the log file for new entries and alerts on slow queries,
    errors, and other issues. Optionally posts webhook alerts.

    \b
    Example:
      pgloglens watch /var/log/postgresql/postgresql.log --alert-slow-ms 3000
      pgloglens watch pg.log --webhook-url http://slack-webhook/... --alert-errors 5
      pgloglens watch pg.log --watch-llm-provider openai
    """
    # Resolve backwards-compat aliases
    effective_threshold = alert_threshold_ms or alert_slow_ms
    effective_llm = watch_llm_provider if watch_llm_provider != "none" else llm_provider

    try:
        from rich.console import Console
        from rich.live import Live
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        console = Console()
        _use_rich = True
    except ImportError:
        _use_rich = False
        console = None

    click.echo(f"[pgloglens] Watching {log_file} (threshold: {effective_threshold}ms, interval: {interval}s)")
    if webhook_url:
        click.echo(f"[pgloglens] Webhook: {webhook_url}")
    if effective_llm != "none":
        click.echo(f"[pgloglens] Real-time LLM: {effective_llm}")
    click.echo("Press Ctrl+C to stop.\n")

    path = Path(log_file)
    from .parser import (
        _parse_stderr_line, detect_format, is_slow_query, is_auth_failure,
        is_deadlock, is_lock_wait,
    )

    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0

    slow_alerts: List[dict] = []
    error_alerts: List[dict] = []
    error_timestamps: List[datetime] = []

    def _post_webhook(payload: dict) -> None:
        if not webhook_url:
            return
        try:
            import urllib.request
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            if _use_rich and console:
                console.print(f"[dim red]Webhook error: {exc}[/dim red]")

    def _llm_analyze_alert(query_text: str) -> Optional[str]:
        """Run quick LLM analysis on an alerting slow query."""
        if effective_llm == "none":
            return None
        try:
            from .llm import get_provider, SLOW_QUERY_ANALYSIS_PROMPT
            provider = get_provider(effective_llm)

            async def _run():
                prompt = SLOW_QUERY_ANALYSIS_PROMPT.format(
                    query=query_text[:500],
                    count=1,
                    avg_ms="unknown",
                    p95_ms="unknown",
                    total_ms="unknown",
                )
                return await provider.analyze(prompt)

            return asyncio.run(_run())
        except Exception:
            return None

    def _process_new_lines(new_content: str) -> None:
        """Process new log content."""
        for line in new_content.split("\n"):
            if not line.strip():
                continue
            entry = _parse_stderr_line(line, 0)
            if entry is None:
                continue

            if entry.duration_ms and entry.duration_ms >= effective_threshold:
                alert = {
                    "type": "slow_query",
                    "duration_ms": entry.duration_ms,
                    "query": (entry.query or entry.message)[:200],
                    "database": entry.database,
                    "user": entry.user,
                    "application": entry.application_name,
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                }
                slow_alerts.append(alert)
                if len(slow_alerts) > 100:
                    slow_alerts.pop(0)
                _post_webhook(alert)

                msg = (
                    f"SLOW QUERY {entry.duration_ms:,.0f}ms "
                    f"[{entry.database}@{entry.user}] "
                    f"{(entry.query or entry.message)[:80]}"
                )
                if _use_rich and console:
                    console.print(f"[yellow]{msg}[/yellow]")
                else:
                    click.echo(msg)

                # Optional LLM analysis
                if effective_llm != "none":
                    analysis = _llm_analyze_alert(entry.query or entry.message or "")
                    if analysis:
                        if _use_rich and console:
                            console.print(f"[dim cyan]  LLM: {analysis[:200]}[/dim cyan]")
                        else:
                            click.echo(f"  LLM: {analysis[:200]}")

            if is_deadlock(entry):
                alert = {
                    "type": "deadlock",
                    "message": entry.message[:300],
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                }
                error_alerts.append(alert)
                _post_webhook(alert)
                msg = f"DEADLOCK DETECTED: {entry.message[:100]}"
                if _use_rich and console:
                    console.print(f"[bold red]{msg}[/bold red]")
                else:
                    click.echo(msg)

            if is_auth_failure(entry):
                msg = f"AUTH FAILURE [{entry.user}@{entry.database}]: {entry.message[:80]}"
                if _use_rich and console:
                    console.print(f"[red]{msg}[/red]")
                else:
                    click.echo(msg)
                _post_webhook({
                    "type": "auth_failure",
                    "user": entry.user,
                    "database": entry.database,
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                })

            # Error rate tracking
            if entry.log_level and str(entry.log_level.value) in ("ERROR", "FATAL", "PANIC"):
                now = datetime.now()
                error_timestamps.append(now)
                # Keep only last minute
                cutoff = now - timedelta(minutes=1)
                while error_timestamps and error_timestamps[0] < cutoff:
                    error_timestamps.pop(0)
                if len(error_timestamps) >= alert_errors:
                    err_alert = {
                        "type": "error_rate",
                        "errors_per_minute": len(error_timestamps),
                        "timestamp": now.isoformat(),
                    }
                    _post_webhook(err_alert)
                    msg = f"ERROR RATE ALERT: {len(error_timestamps)} errors/min"
                    if _use_rich and console:
                        console.print(f"[bold red]{msg}[/bold red]")
                    else:
                        click.echo(msg)

    import time as time_mod
    try:
        while True:
            try:
                current_size = path.stat().st_size
                if current_size > file_size:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(file_size)
                        new_content = fh.read()
                    file_size = current_size
                    if new_content.strip():
                        _process_new_lines(new_content)
                elif current_size < file_size:
                    click.echo("[pgloglens] Log file rotated — resetting position")
                    file_size = 0
            except OSError as exc:
                click.echo(f"[WARNING] Could not read log file: {exc}", err=True)

            time_mod.sleep(interval)
    except KeyboardInterrupt:
        click.echo("\n[pgloglens] Watch stopped.")


# ---------------------------------------------------------------------------
# dump command
# ---------------------------------------------------------------------------

@main.command("dump")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Output file (default: stdout)")
@click.option("--format", "-f", "dump_format",
              type=click.Choice(["text", "csv", "json"], case_sensitive=False),
              default="text", show_default=True, help="Output format")
@click.option("--min-count", type=int, default=1, show_default=True,
              help="Minimum occurrence count to include")
@click.option("--min-duration-ms", type=float, default=0.0, show_default=True,
              help="Minimum avg duration to include (ms)")
@click.option("--slow-query-threshold", "slow_query_threshold", type=float,
              default=100.0, show_default=True, help="Min duration (ms) for slow query tracking")
@click.option("--database", "-d", type=str, default=None, help="Filter by database")
@click.option("--user", "-u", type=str, default=None, help="Filter by user")
def cmd_dump(
    log_file: str,
    output_file: Optional[str],
    dump_format: str,
    min_count: int,
    min_duration_ms: float,
    slow_query_threshold: float,
    database: Optional[str],
    user: Optional[str],
):
    """Dump all normalized queries with stats to stdout/file.

    \b
    Examples:
      pgloglens dump postgresql.log
      pgloglens dump postgresql.log --format csv -o queries.csv
      pgloglens dump postgresql.log --format json --min-count 5 --min-duration-ms 100
    """
    parser = LogParser(
        slow_query_threshold_ms=slow_query_threshold,
        filter_database=database,
        filter_user=user,
    )
    analyzer = Analyzer(
        log_file_paths=[log_file],
        slow_query_threshold_ms=slow_query_threshold,
        top_queries=10000,  # capture all
        top_errors=0,
    )

    def _stream():
        yield from parser.parse_file(log_file, show_progress=False)

    result = analyzer.process_entries(_stream())

    queries = [
        sq for sq in result.slow_queries
        if sq.count >= min_count and sq.avg_duration_ms >= min_duration_ms
    ]
    queries.sort(key=lambda q: q.total_duration_ms, reverse=True)

    if dump_format == "json":
        data = [
            {
                "normalized_query": sq.normalized_query,
                "count": sq.count,
                "avg_duration_ms": round(sq.avg_duration_ms, 2),
                "max_duration_ms": round(sq.max_duration_ms, 2),
                "p95_duration_ms": round(sq.p95_duration_ms, 2),
                "p99_duration_ms": round(sq.p99_duration_ms, 2),
                "total_duration_ms": round(sq.total_duration_ms, 2),
                "query_type": getattr(sq, "query_type", "unknown"),
                "databases": sorted(sq.databases),
                "users": sorted(sq.users),
            }
            for sq in queries
        ]
        content = json.dumps(data, indent=2)

    elif dump_format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "normalized_query", "count", "avg_duration_ms", "max_duration_ms",
            "p95_duration_ms", "p99_duration_ms", "total_duration_ms",
            "query_type", "databases", "users",
        ])
        writer.writeheader()
        for sq in queries:
            writer.writerow({
                "normalized_query": sq.normalized_query,
                "count": sq.count,
                "avg_duration_ms": round(sq.avg_duration_ms, 2),
                "max_duration_ms": round(sq.max_duration_ms, 2),
                "p95_duration_ms": round(sq.p95_duration_ms, 2),
                "p99_duration_ms": round(sq.p99_duration_ms, 2),
                "total_duration_ms": round(sq.total_duration_ms, 2),
                "query_type": getattr(sq, "query_type", "unknown"),
                "databases": "|".join(sorted(sq.databases)),
                "users": "|".join(sorted(sq.users)),
            })
        content = buf.getvalue()

    else:  # text
        lines = [f"pgloglens query dump — {len(queries)} queries\n\n"]
        for i, sq in enumerate(queries, 1):
            lines.append(
                f"[{i}] count={sq.count} avg={sq.avg_duration_ms:.0f}ms "
                f"max={sq.max_duration_ms:.0f}ms total={sq.total_duration_ms:.0f}ms\n"
                f"    {sq.normalized_query}\n\n"
            )
        content = "".join(lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"Queries dumped to: {output_file}")
    else:
        click.echo(content)


# ---------------------------------------------------------------------------
# index-advisor command
# ---------------------------------------------------------------------------

@main.command("index-advisor")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--llm-provider",
              type=click.Choice(["openai", "anthropic", "ollama", "google"],
                                case_sensitive=False),
              required=True, help="LLM provider")
@click.option("--llm-model", type=str, default=None, help="Model name")
@click.option("--llm-api-key", type=str, default=None, help="API key")
@click.option("--top-queries", "top_queries", type=int, default=10, show_default=True,
              help="Analyze top N slow queries")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Save recommendations to file")
@click.option("--slow-query-threshold", type=float, default=500.0, show_default=True,
              help="Slow query threshold (ms)")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["text", "json"], case_sensitive=False),
              default="text", show_default=True, help="Output format")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_index_advisor(
    log_file: str,
    llm_provider: str,
    llm_model: Optional[str],
    llm_api_key: Optional[str],
    top_queries: int,
    output_file: Optional[str],
    slow_query_threshold: float,
    output_format: str,
    verbose: bool,
):
    """AI-powered index recommendations from PostgreSQL logs.

    Analyzes the top slow queries and generates concrete CREATE INDEX
    CONCURRENTLY statements with rationale and estimated speedups.

    \b
    Examples:
      pgloglens index-advisor postgresql.log --llm-provider openai
      pgloglens index-advisor pg.log --llm-provider anthropic --top-queries 15
      pgloglens index-advisor pg.log --llm-provider openai -o indexes.json --format json
    """
    if verbose:
        click.echo(f"[pgloglens] index-advisor: parsing {log_file}...")

    parser = LogParser(slow_query_threshold_ms=slow_query_threshold)
    analyzer = Analyzer(
        log_file_paths=[log_file],
        slow_query_threshold_ms=slow_query_threshold,
        top_queries=top_queries * 2,
        top_errors=0,
    )

    def _stream():
        yield from parser.parse_file(log_file, show_progress=verbose)

    result = analyzer.process_entries(_stream())

    if not result.slow_queries:
        click.echo("[pgloglens] No slow queries found. Try lowering --slow-query-threshold.")
        return

    if verbose:
        click.echo(f"[pgloglens] Found {len(result.slow_queries)} slow query patterns. Analyzing top {top_queries}...")

    from .llm import get_provider
    from .rca import ai_generate_index_recommendations

    provider = get_provider(llm_provider, model=llm_model, api_key=llm_api_key)

    try:
        recommendations = asyncio.run(
            ai_generate_index_recommendations(result.slow_queries[:top_queries], provider)
        )
    except Exception as exc:
        click.echo(f"[ERROR] LLM call failed: {exc}", err=True)
        sys.exit(1)

    if output_format == "json":
        content = json.dumps(recommendations, indent=2)
    else:
        lines = [f"pgloglens index-advisor — {len(recommendations)} recommendations\n\n"]
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"[{i}] {rec.get('create_index_sql', '(no SQL)')}\n")
            lines.append(f"    Query: {rec.get('query', '')[:80]}\n")
            lines.append(f"    Rationale: {rec.get('rationale', '')[:200]}\n")
            lines.append(f"    Estimated speedup: {rec.get('estimated_speedup', 'unknown')}\n\n")
        content = "".join(lines)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"Recommendations written to: {output_file}")
    else:
        click.echo(content)


# ---------------------------------------------------------------------------
# config commands
# ---------------------------------------------------------------------------

@main.group("config")
def cmd_config():
    """Manage pgloglens configuration."""


@cmd_config.command("init")
@click.option("--path", type=click.Path(), default=None,
              help="Config file path (default: ~/.pgloglens.yaml)")
def cmd_config_init(path: Optional[str]):
    """Create a default v2 configuration file."""
    config_path = Path(path) if path else Path.home() / ".pgloglens.yaml"
    if config_path.exists():
        if not click.confirm(f"Config file {config_path} already exists. Overwrite?"):
            return

    default_config = """\
# pgloglens v2.0 configuration file
# Generated by: pgloglens config init

slow_query_threshold_ms: 1000

llm:
  provider: none              # openai | anthropic | ollama | google | none
  model: gpt-4o               # model name for chosen provider
  api_key: ${OPENAI_API_KEY}  # or set directly (not recommended)

report:
  format: terminal            # terminal | html | json | markdown
  top_queries: 25
  top_errors: 20

filters:
  databases: []               # limit analysis to these databases (empty = all)
  users: []                   # limit analysis to these users (empty = all)
  exclude_databases: []       # databases to exclude
  exclude_users: []           # users to exclude
  application: null           # filter by application name
  host: null                  # filter by client host/IP

analysis:
  platform: auto              # auto | postgresql | rds | redshift | cloudsql | heroku | pgbouncer
  anonymize: false            # replace literal values with placeholders
  select_only: false          # only analyze SELECT queries

ai:
  slow_queries: 0             # AI-analyze top N slow queries individually (0=disabled)
  explain_plans: false        # AI-analyze auto_explain plans
  generate_config: false      # generate postgresql.conf recommendations
  index_recommendations: false  # generate CREATE INDEX recommendations
  stream_output: false        # stream LLM output token by token

watch:
  alert_slow_ms: 5000
  alert_errors_per_minute: 10
  interval_seconds: 5
  webhook_url: null           # POST alerts to this URL
  llm_provider: none          # real-time LLM analysis of alerts

incremental:
  enabled: false
  state_file: ~/.pgloglens_state.json
"""
    config_path.write_text(default_config)
    click.echo(f"Config written to: {config_path}")
    click.echo("\nNext steps:")
    click.echo("  1. Set your LLM provider in the config or via env var")
    click.echo("  2. Run: pgloglens analyze /var/log/postgresql/postgresql.log")
    click.echo("  3. For AI features: pgloglens analyze pg.log --llm-provider openai --ai-slow-queries 5")


@cmd_config.command("show")
def cmd_config_show():
    """Show the current resolved configuration."""
    cfg = _load_config(None)
    if cfg:
        click.echo(_yaml_dump(cfg))
    else:
        click.echo("No config file found. Run 'pgloglens config init' to create one.")
        click.echo("\nDefault config values:")
        click.echo("  slow_query_threshold_ms: 1000")
        click.echo("  llm.provider: none")
        click.echo("  report.format: terminal")
        click.echo("  report.top_queries: 25")
        click.echo("  analysis.platform: auto")


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

@main.command("version")
def cmd_version():
    """Show version information."""
    import platform
    click.echo(f"pgloglens v2.0.0")
    click.echo(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}")

    # Check __version__ from package
    try:
        click.echo(f"Package version: {__version__}")
    except Exception:
        pass

    click.echo("\nInstalled LLM providers:")
    providers = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
        "ollama": None,
    }
    for name, env_var in providers.items():
        try:
            if name == "openai":
                import openai  # noqa
            elif name == "anthropic":
                import anthropic  # noqa
            elif name == "google":
                try:
                    import google.genai  # noqa
                except ImportError:
                    import google.generativeai  # noqa
            elif name == "ollama":
                pass  # uses stdlib urllib
            status = "ok"
            key_status = ""
            if env_var:
                key_status = f" (key: {'set' if os.environ.get(env_var) else 'NOT SET'})"
            click.echo(f"  [ok] {name}{key_status}")
        except ImportError:
            click.echo(f"  [missing] {name} (pip install pgloglens[{name}])")

    click.echo("\nNew in v2.0.0:")
    click.echo("  - 8 new RCA rules (Rules 15-22)")
    click.echo("  - AI-enhanced RCA: ai_analyze_slow_queries, ai_analyze_explain_plan")
    click.echo("  - AI postgresql.conf generation, AI index recommendations")
    click.echo("  - Streaming LLM output (--stream-llm)")
    click.echo("  - 5 new HTML report tabs: Sessions, Query Types, Prepare/Execute, Auto-Explain, PgBouncer")
    click.echo("  - New commands: pgloglens dump, pgloglens index-advisor")
    click.echo("  - New analyze options: --application, --host, --exclude-query, --ai-slow-queries, --platform, and more")


# ---------------------------------------------------------------------------
# diff command (comparison)
# ---------------------------------------------------------------------------

@main.command("diff")
@click.argument("before", type=str)
@click.argument("after", type=str)
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json", "markdown", "html"], case_sensitive=False),
              default="terminal", show_default=True, help="Output format")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Output file path")
@click.option("--before-label", type=str, default="before",
              help="Label for the before analysis")
@click.option("--after-label", type=str, default="after",
              help="Label for the after analysis")
@click.option("--slow-query-threshold", type=float, default=1000.0,
              help="Slow query threshold when parsing logs")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_diff(
    before: str,
    after: str,
    output_format: str,
    output_file: Optional[str],
    before_label: str,
    after_label: str,
    slow_query_threshold: float,
    verbose: bool,
):
    """Compare two log analyses and show differences.

    BEFORE and AFTER can be:
      - Paths to log files or directories
      - Paths to saved analysis artifacts (.json)

    \b
    Examples:
      pgloglens diff logs/yesterday/ logs/today/
      pgloglens diff baseline.json postgresql.log
      pgloglens diff before.json after.json --format markdown -o diff.md
      pgloglens diff prod-v1.2.json prod-v1.3.json --format html -o diff.html
    """
    from .compare import (
        compare_results, load_analysis_artifact, save_analysis_artifact,
        render_comparison_text, render_comparison_markdown,
    )

    def _load_or_analyze(path_str: str, label: str) -> AnalysisResult:
        """Load from artifact or analyze log files."""
        path = Path(path_str)

        # Check if it's a saved artifact
        if path.suffix == ".json" and path.exists():
            try:
                result, metadata = load_analysis_artifact(str(path))
                if verbose:
                    click.echo(f"[pgloglens] Loaded artifact: {path} (label: {metadata.get('label', 'unknown')})")
                return result
            except Exception as e:
                if verbose:
                    click.echo(f"[pgloglens] Could not load as artifact: {e}")

        # Treat as log file(s)
        log_files = _discover_log_files(path_str)
        if not log_files:
            raise click.UsageError(f"No log files found: {path_str}")

        if verbose:
            click.echo(f"[pgloglens] Analyzing {len(log_files)} file(s) for '{label}'...")

        return _run_analysis(
            log_files=log_files,
            slow_query_threshold=slow_query_threshold,
            from_dt=None,
            to_dt=None,
            database=None,
            user=None,
            top_queries=100,
            top_errors=50,
            verbose=verbose,
            workers=None,
        )

    # Load/analyze both
    before_result = _load_or_analyze(before, before_label)
    after_result = _load_or_analyze(after, after_label)

    # Compare
    comparison = compare_results(
        before_result, after_result,
        before_label=before_label,
        after_label=after_label,
    )

    # Render output
    if output_format == "json":
        content = json.dumps(comparison.to_dict(), indent=2, default=str)
    elif output_format == "markdown":
        content = render_comparison_markdown(comparison)
    elif output_format == "html":
        # Use markdown as fallback for HTML
        content = f"<html><body><pre>{render_comparison_markdown(comparison)}</pre></body></html>"
    else:
        content = render_comparison_text(comparison)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"Diff written to: {output_file}")
    else:
        click.echo(content)

    # Summary
    summary = comparison.summary()
    if summary["queries"]["slower"] > 0 or summary["errors"]["new"] > 0:
        if verbose:
            click.echo(f"\n[REGRESSION WARNING] {summary['queries']['slower']} queries got slower, {summary['errors']['new']} new errors", err=True)


# ---------------------------------------------------------------------------
# timeline command
# ---------------------------------------------------------------------------

@main.command("timeline")
@click.argument("log_files", nargs=-1, required=True, type=str)
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json", "markdown"], case_sensitive=False),
              default="terminal", show_default=True, help="Output format")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Output file path")
@click.option("--window-minutes", type=int, default=5, show_default=True,
              help="Time window for grouping related events (minutes)")
@click.option("--slow-query-threshold", type=float, default=1000.0,
              help="Slow query threshold (ms)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_timeline(
    log_files: Tuple[str, ...],
    output_format: str,
    output_file: Optional[str],
    window_minutes: int,
    slow_query_threshold: float,
    verbose: bool,
):
    """Generate an incident timeline from PostgreSQL logs.

    Reconstructs the flow of events including error bursts, deadlocks,
    checkpoint spikes, autovacuum events, and more.

    \b
    Examples:
      pgloglens timeline postgresql.log
      pgloglens timeline logs/*.log --format markdown -o incident.md
      pgloglens timeline postgresql.log --window-minutes 10
    """
    from .timeline import build_timeline, render_timeline_text, render_timeline_markdown

    # Discover files
    all_files = []
    for pattern in log_files:
        all_files.extend(_discover_log_files(pattern))

    if not all_files:
        raise click.UsageError("No log files found")

    if verbose:
        click.echo(f"[pgloglens] Building timeline from {len(all_files)} file(s)...")

    # Analyze
    result = _run_analysis(
        log_files=all_files,
        slow_query_threshold=slow_query_threshold,
        from_dt=None,
        to_dt=None,
        database=None,
        user=None,
        top_queries=50,
        top_errors=50,
        verbose=verbose,
        workers=None,
    )

    # Run RCA to populate findings
    run_rca(result)

    # Build timeline
    timeline = build_timeline(result, window_minutes=window_minutes)

    if verbose:
        click.echo(f"[pgloglens] Found {timeline.total_events} events ({timeline.critical_events} critical, {timeline.high_events} high)")

    # Render output
    if output_format == "json":
        content = json.dumps(timeline.to_dict(), indent=2, default=str)
    elif output_format == "markdown":
        content = render_timeline_markdown(timeline)
    else:
        content = render_timeline_text(timeline)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        click.echo(f"Timeline written to: {output_file}")
    else:
        click.echo(content)


# ---------------------------------------------------------------------------
# save command
# ---------------------------------------------------------------------------

@main.command("save")
@click.argument("log_files", nargs=-1, required=True, type=str)
@click.option("--output", "-o", "output_file", type=click.Path(), required=True,
              help="Output artifact file path (.json)")
@click.option("--label", type=str, default=None,
              help="Label for this analysis (e.g., 'prod-v1.2', 'baseline')")
@click.option("--slow-query-threshold", type=float, default=1000.0,
              help="Slow query threshold (ms)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmd_save(
    log_files: Tuple[str, ...],
    output_file: str,
    label: Optional[str],
    slow_query_threshold: float,
    verbose: bool,
):
    """Save analysis results as an artifact for later comparison.

    Creates a JSON artifact that can be used with 'pgloglens diff'.

    \b
    Examples:
      pgloglens save postgresql.log -o baseline.json --label production-baseline
      pgloglens save logs/*.log -o before-deploy.json
    """
    from .compare import save_analysis_artifact

    # Discover files
    all_files = []
    for pattern in log_files:
        all_files.extend(_discover_log_files(pattern))

    if not all_files:
        raise click.UsageError("No log files found")

    if verbose:
        click.echo(f"[pgloglens] Analyzing {len(all_files)} file(s)...")

    # Analyze
    result = _run_analysis(
        log_files=all_files,
        slow_query_threshold=slow_query_threshold,
        from_dt=None,
        to_dt=None,
        database=None,
        user=None,
        top_queries=100,
        top_errors=50,
        verbose=verbose,
        workers=None,
    )

    # Run RCA
    run_rca(result)

    # Auto-generate label if not provided
    if not label:
        label = f"analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Save
    save_analysis_artifact(result, output_file, label=label)
    click.echo(f"Analysis saved to: {output_file} (label: {label})")


# ---------------------------------------------------------------------------
# summary command (quick health check)
# ---------------------------------------------------------------------------

@main.command("summary")
@click.argument("log_files", nargs=-1, required=True, type=str)
@click.option("--slow-query-threshold", type=float, default=1000.0,
              help="Slow query threshold (ms)")
@click.option("--exit-code", is_flag=True, default=False,
              help="Exit with non-zero code if issues found")
def cmd_summary(
    log_files: Tuple[str, ...],
    slow_query_threshold: float,
    exit_code: bool,
):
    """Quick summary of log health (5-line output).

    Ideal for CI/CD, cron jobs, and quick health checks.

    Exit codes (when --exit-code is set):
      0: No critical or high severity issues
      1: Critical issues found
      2: High severity issues found

    \b
    Examples:
      pgloglens summary postgresql.log
      pgloglens summary logs/*.log --exit-code
    """
    # Discover files
    all_files = []
    for pattern in log_files:
        all_files.extend(_discover_log_files(pattern))

    if not all_files:
        raise click.UsageError("No log files found")

    # Analyze
    result = _run_analysis(
        log_files=all_files,
        slow_query_threshold=slow_query_threshold,
        from_dt=None,
        to_dt=None,
        database=None,
        user=None,
        top_queries=25,
        top_errors=20,
        verbose=False,
        workers=None,
    )

    # Run RCA
    run_rca(result)

    # Count findings by severity
    critical_count = sum(1 for f in result.rca_findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in result.rca_findings if f.severity.value == "HIGH")

    # Summary output (5 lines)
    click.echo(f"Entries: {result.total_entries:,}")
    click.echo(f"Slow queries: {len(result.slow_queries)} patterns")
    click.echo(f"Errors: {len(result.error_patterns)} patterns | Deadlocks: {result.deadlock_count}")
    click.echo(f"Findings: {critical_count} critical, {high_count} high, {len(result.rca_findings) - critical_count - high_count} other")

    # Top finding
    if result.rca_findings:
        top = result.rca_findings[0]
        click.echo(f"Top issue: [{top.severity.value}] {top.title}")
    else:
        click.echo("Top issue: None")

    # Exit code
    if exit_code:
        if critical_count > 0:
            sys.exit(1)
        elif high_count > 0:
            sys.exit(2)
        sys.exit(0)


# ---------------------------------------------------------------------------
# rules command (custom rule pack management)
# ---------------------------------------------------------------------------

@main.group("rules")
def cmd_rules():
    """Manage custom rule packs."""


@cmd_rules.command("init")
@click.option("--path", type=click.Path(), default=None,
              help="Output path (default: ~/.pgloglens/rules/custom.yaml)")
def cmd_rules_init(path: Optional[str]):
    """Create an example custom rule pack."""
    from .rules import create_example_rule_pack

    if path is None:
        rules_dir = Path.home() / ".pgloglens" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        path = str(rules_dir / "custom.yaml")

    create_example_rule_pack(path)
    click.echo(f"Example rule pack created: {path}")
    click.echo("\nTo use: pgloglens analyze logs.log --rule-pack " + path)


@cmd_rules.command("list")
def cmd_rules_list():
    """List available rule packs."""
    from .rules import discover_rule_packs, load_rule_pack

    packs = discover_rule_packs()

    if not packs:
        click.echo("No rule packs found.")
        click.echo("\nTo create one: pgloglens rules init")
        return

    click.echo(f"Found {len(packs)} rule pack(s):\n")
    for pack_path in packs:
        try:
            pack = load_rule_pack(pack_path)
            click.echo(f"  {pack.name} ({pack.version})")
            click.echo(f"    Path: {pack_path}")
            click.echo(f"    Custom rules: {len(pack.custom_rules)}")
            click.echo(f"    Severity overrides: {len(pack.severity_overrides)}")
            click.echo(f"    Ignore patterns: {len(pack.ignore_error_patterns)} errors, {len(pack.ignore_query_patterns)} queries")
            click.echo()
        except Exception as e:
            click.echo(f"  [error] {pack_path}: {e}")


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------

def _discover_log_files(pattern: str) -> List[str]:
    """Discover log files from a path or glob pattern.

    Handles:
      - Single file path
      - Directory (finds *.log, *.log.*, rotated files)
      - Glob pattern (*.log, **/*.log)
    """
    import glob

    path = Path(pattern)

    # If it's an existing file, return it
    if path.is_file():
        return [str(path)]

    # If it's a directory, find log files
    if path.is_dir():
        files = []
        # Common log file patterns
        for ext in ["*.log", "*.log.*", "postgresql-*.log", "postgresql.log.*"]:
            files.extend(glob.glob(str(path / ext)))
        # Sort by modification time (newest last for proper ordering)
        files.sort(key=lambda f: Path(f).stat().st_mtime)
        return files

    # Try as glob pattern
    files = glob.glob(pattern, recursive=True)
    if files:
        files.sort(key=lambda f: Path(f).stat().st_mtime if Path(f).exists() else 0)
        return files

    # Try with .gz suffix
    gz_pattern = pattern + ".gz" if not pattern.endswith(".gz") else pattern
    files = glob.glob(gz_pattern, recursive=True)
    if files:
        files.sort(key=lambda f: Path(f).stat().st_mtime if Path(f).exists() else 0)
        return files

    return []


# ---------------------------------------------------------------------------
# Enhanced analyze command options (add to existing)
# ---------------------------------------------------------------------------

# Note: The --summary-only and --exit-code flags are added to the analyze command
# They work with the existing analyze infrastructure


if __name__ == "__main__":
    main()
