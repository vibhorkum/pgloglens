"""Report generation for pgloglens v2.

Supports four output formats:
  - terminal   Rich-formatted colored output
  - html       Self-contained HTML with Chart.js (13 tabs in v2)
  - json       Full JSON dump of AnalysisResult
  - markdown   GitHub-compatible Markdown

v2 additions:
  - 5 new HTML tabs: Sessions, Query Types, Prepare/Execute, Auto-Explain, PgBouncer
  - Enhanced slow queries table: query type, regression indicator, applications
  - Enhanced connections tab: host breakdown, application breakdown
  - Enhanced checkpoint tab: WAL files added/removed/recycled
  - Enhanced autovacuum tab: buffer hits/misses, WAL bytes, CPU time
  - AI index recommendations and postgresql.conf section in Recommendations tab
  - Per-query AI analysis (collapsible) in slow query rows
  - Terminal: session stats panel, query type distribution, regression indicators
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import AnalysisResult, RCAFinding, Severity


# ---------------------------------------------------------------------------
# Severity colors
# ---------------------------------------------------------------------------

_SEVERITY_RICH_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_HTML_COLORS = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH: "#ffaa00",
    Severity.MEDIUM: "#ffdd57",
    Severity.LOW: "#00c9c9",
    Severity.INFO: "#888888",
}

_SEVERITY_BADGE_CSS = {
    Severity.CRITICAL: "badge-critical",
    Severity.HIGH: "badge-high",
    Severity.MEDIUM: "badge-medium",
    Severity.LOW: "badge-low",
    Severity.INFO: "badge-info",
}


# ---------------------------------------------------------------------------
# Terminal (Rich) reporter
# ---------------------------------------------------------------------------

def render_terminal(result: AnalysisResult) -> None:
    """Print a rich-formatted analysis report to the terminal."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich import box
        from rich.columns import Columns
        from rich.rule import Rule
    except ImportError:
        print("[ERROR] rich is not installed. Run: pip install rich")
        _render_plain_terminal(result)
        return

    console = Console()

    # Header
    console.print()
    console.print(Panel.fit(
        "[bold cyan]pgloglens[/bold cyan] v2.0 — PostgreSQL Log Analysis Report",
        border_style="cyan",
    ))
    console.print()

    # Time range
    if result.time_range_start and result.time_range_end:
        delta = result.time_range_end - result.time_range_start
        hours = delta.total_seconds() / 3600
        console.print(
            f"[dim]Log period:[/dim] {result.time_range_start.strftime('%Y-%m-%d %H:%M:%S')} "
            f"→ {result.time_range_end.strftime('%Y-%m-%d %H:%M:%S')} "
            f"[dim]({hours:.1f}h)[/dim]"
        )
    platform = getattr(result, "source_platform", "postgresql")
    console.print(
        f"[dim]Entries analyzed:[/dim] [bold]{result.total_entries:,}[/bold]  |  "
        f"[dim]Slow query patterns:[/dim] [bold]{len(result.slow_queries)}[/bold]  |  "
        f"[dim]Error patterns:[/dim] [bold]{len(result.error_patterns)}[/bold]  |  "
        f"[dim]Lock events:[/dim] [bold]{len(result.lock_events)}[/bold]  |  "
        f"[dim]Platform:[/dim] [bold]{platform}[/bold]"
    )
    console.print()

    # --- RCA Findings ---
    if result.rca_findings:
        console.print(Rule("[bold]Root Cause Analysis Findings[/bold]", style="bold white"))
        for finding in result.rca_findings:
            color = _SEVERITY_RICH_COLORS.get(finding.severity, "white")
            severity_badge = f"[{color}][{finding.severity.value}][/{color}]"
            console.print(f"  {severity_badge} [bold]{finding.title}[/bold]")
            console.print(f"    [dim]{finding.description[:300]}[/dim]")
            if finding.recommendations:
                console.print(f"    [green]→[/green] {finding.recommendations[0]}")
            console.print()

    # --- Session Stats ---
    ss = result.session_stats
    if ss and ss.total_sessions > 0:
        console.print(Rule("[bold]Session Statistics[/bold]", style="bold white"))
        sess_table = Table(box=box.SIMPLE, show_header=False)
        sess_table.add_column("Metric", style="dim")
        sess_table.add_column("Value", style="bold")
        sess_table.add_row("Total sessions", f"{ss.total_sessions:,}")
        sess_table.add_row("Peak concurrent", f"{ss.peak_concurrent}")
        sess_table.add_row("Avg session duration", f"{ss.avg_session_duration_ms / 1000:.1f}s")
        if ss.total_session_duration_ms > 0:
            idle_pct = ss.total_idle_time_ms / ss.total_session_duration_ms * 100
            color = "yellow" if idle_pct > 70 else "green"
            sess_table.add_row("Idle time ratio", f"[{color}]{idle_pct:.1f}%[/{color}]")
        console.print(sess_table)

    # --- Query Type Distribution ---
    qt = result.query_type_stats
    total_qt = (
        qt.select_count + qt.insert_count + qt.update_count
        + qt.delete_count + qt.copy_count + qt.ddl_count + qt.other_count
    )
    if total_qt > 0:
        console.print(Rule("[bold]Query Type Distribution[/bold]", style="bold white"))
        qt_table = Table(
            "Type", "Count", "Percentage",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
        )
        for qtype, count in [
            ("SELECT", qt.select_count),
            ("INSERT", qt.insert_count),
            ("UPDATE", qt.update_count),
            ("DELETE", qt.delete_count),
            ("COPY", qt.copy_count),
            ("DDL", qt.ddl_count),
            ("Other", qt.other_count),
        ]:
            if count > 0:
                pct = count / total_qt * 100
                bar = "█" * int(pct / 5)
                qt_table.add_row(qtype, f"{count:,}", f"{pct:.1f}% {bar}")
        if qt.cancelled_count:
            qt_table.add_row("[red]Cancelled[/red]", f"[red]{qt.cancelled_count:,}[/red]", "")
        console.print(qt_table)

    # --- Prepare/Bind/Execute Breakdown ---
    pb = result.prepare_bind_execute
    if pb.total_execute_ms > 0:
        console.print(Rule("[bold]Prepare/Bind/Execute Phases[/bold]", style="bold white"))
        pbe_table = Table(box=box.SIMPLE, show_header=False)
        pbe_table.add_column("Phase", style="dim")
        pbe_table.add_column("Total Time", style="bold")
        pbe_table.add_column("Count", style="dim")
        pbe_table.add_row("Parse", f"{pb.total_parse_ms:,.0f}ms", f"{pb.parse_count:,}")
        pbe_table.add_row("Bind", f"{pb.total_bind_ms:,.0f}ms", f"{pb.bind_count:,}")
        pbe_table.add_row("Execute", f"{pb.total_execute_ms:,.0f}ms", f"{pb.execute_count:,}")
        if pb.total_execute_ms > 0:
            parse_pct = pb.total_parse_ms / pb.total_execute_ms * 100
            if parse_pct > 20:
                pbe_table.add_row(
                    "[yellow]Parse ratio[/yellow]",
                    f"[yellow]{parse_pct:.1f}% of execute[/yellow]",
                    "[yellow]⚠ HIGH[/yellow]",
                )
        console.print(pbe_table)

    # --- Slow Queries ---
    if result.slow_queries:
        console.print(Rule("[bold]Top Slow Queries[/bold]", style="bold white"))
        sq_table = Table(
            "Rank", "Type", "Reg", "Count", "Avg (ms)", "Max (ms)", "P95 (ms)", "Query",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
        )
        for i, sq in enumerate(result.slow_queries, 1):
            reg_indicator = "[bold red]📈[/bold red]" if getattr(sq, "is_regression", False) else ""
            qtype = getattr(sq, "query_type", "unknown")
            sq_table.add_row(
                str(i),
                qtype.upper()[:6],
                reg_indicator,
                str(sq.count),
                f"{sq.avg_duration_ms:,.0f}",
                f"[bold red]{sq.max_duration_ms:,.0f}[/bold red]",
                f"{sq.p95_duration_ms:,.0f}",
                f"[dim]{sq.normalized_query[:70]}[/dim]",
            )
        console.print(sq_table)

    # --- Error Patterns ---
    if result.error_patterns:
        console.print(Rule("[bold]Top Error Patterns[/bold]", style="bold white"))
        err_table = Table(
            "Count", "SQLSTATE", "Category", "Pattern",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold yellow",
        )
        for ep in result.error_patterns[:15]:
            err_table.add_row(
                f"[bold red]{ep.count}[/bold red]",
                ep.error_code or "—",
                ep.category,
                ep.message_pattern[:80],
            )
        console.print(err_table)

    # --- Connection Stats ---
    cs = result.connection_stats
    if cs.total_connections > 0:
        console.print(Rule("[bold]Connection Statistics[/bold]", style="bold white"))
        conn_table = Table(box=box.SIMPLE, show_header=False)
        conn_table.add_column("Metric", style="dim")
        conn_table.add_column("Value", style="bold")
        conn_table.add_row("Total connections", f"{cs.total_connections:,}")
        conn_table.add_row("Peak concurrent", f"{cs.peak_concurrent}")
        conn_table.add_row("Auth failures", f"[red]{cs.auth_failures}[/red]")
        top_users = sorted(cs.connections_by_user.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_users:
            conn_table.add_row("Top users", ", ".join(f"{u}({c})" for u, c in top_users))
        # Host breakdown
        conn_by_host = getattr(result, "connection_by_host", {}) or cs.connections_by_host
        if conn_by_host:
            top_host = max(conn_by_host.items(), key=lambda x: x[1])
            conn_table.add_row("Top host", f"{top_host[0]} ({top_host[1]} conns)")
        # Application breakdown
        conn_by_app = getattr(result, "connection_by_application", {}) or cs.connections_by_application
        if conn_by_app:
            top_app = max(conn_by_app.items(), key=lambda x: x[1])
            conn_table.add_row("Top application", f"{top_app[0]} ({top_app[1]} conns)")
        console.print(conn_table)

    # --- Checkpoint Stats ---
    cp = result.checkpoint_stats
    if cp.count > 0:
        console.print(Rule("[bold]Checkpoint Statistics[/bold]", style="bold white"))
        cp_table = Table(box=box.SIMPLE, show_header=False)
        cp_table.add_column("Metric", style="dim")
        cp_table.add_column("Value", style="bold")
        cp_table.add_row("Total checkpoints", str(cp.count))
        cp_table.add_row("Avg duration", f"{cp.avg_duration_ms / 1000:.1f}s")
        cp_table.add_row("Max duration", f"{cp.max_duration_ms / 1000:.1f}s")
        cp_table.add_row(
            "Frequency warnings",
            f"[red]{cp.warning_count}[/red]" if cp.warning_count else "0",
        )
        wal_added = getattr(result, "checkpoint_wal_added", 0)
        wal_removed = getattr(result, "checkpoint_wal_removed", 0)
        wal_recycled = getattr(result, "checkpoint_wal_recycled", 0)
        if wal_added or wal_removed or wal_recycled:
            cp_table.add_row("WAL files added/removed/recycled", f"{wal_added}/{wal_removed}/{wal_recycled}")
        console.print(cp_table)

    # --- Lock Events ---
    if result.lock_events:
        console.print(Rule("[bold]Lock Events[/bold]", style="bold white"))
        dl_count = result.deadlock_count
        console.print(
            f"  Lock waits: [bold]{len(result.lock_events)}[/bold]  |  "
            f"Deadlocks: [{'bold red' if dl_count else 'dim'}]{dl_count}[/{'bold red' if dl_count else 'dim'}]"
        )
        if dl_count:
            console.print("  [red]⚠ Deadlocks detected — review transaction ordering[/red]")

    # --- Temp Files ---
    if result.temp_files:
        console.print(Rule("[bold]Temporary Files[/bold]", style="bold white"))
        total_mb = sum(t.size_mb for t in result.temp_files)
        max_mb = max(t.size_mb for t in result.temp_files)
        console.print(
            f"  Temp file events: [bold]{len(result.temp_files)}[/bold]  |  "
            f"Total: [yellow]{total_mb:.0f}MB[/yellow]  |  "
            f"Max: [yellow]{max_mb:.0f}MB[/yellow]"
        )

    # --- PgBouncer Stats ---
    pgb = result.pgbouncer_stats
    if pgb is not None:
        console.print(Rule("[bold]PgBouncer Statistics[/bold]", style="bold white"))
        pgb_table = Table(box=box.SIMPLE, show_header=False)
        pgb_table.add_column("Metric", style="dim")
        pgb_table.add_column("Value", style="bold")
        pgb_table.add_row("Total requests", f"{pgb.total_requests:,}")
        pgb_table.add_row("Avg query time", f"{pgb.avg_query_ms:.1f}ms")
        pgb_table.add_row("Pool errors", f"[red]{len(pgb.pool_errors)}[/red]" if pgb.pool_errors else "0")
        console.print(pgb_table)

    # --- LLM Analysis ---
    if result.llm_analysis:
        console.print()
        console.print(Panel(
            result.llm_analysis,
            title="[bold cyan]LLM-Powered Analysis[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))

    # --- Recommendations ---
    if result.recommendations:
        console.print()
        console.print(Panel.fit(
            "[bold green]Recommendations[/bold green]",
            border_style="green",
        ))
        for i, rec in enumerate(result.recommendations[:10], 1):
            console.print(f"  [green]{i}.[/green] {rec}")

    console.print()
    if result.analysis_start and result.analysis_end:
        console.print(f"[dim]Analysis completed in {(result.analysis_end - result.analysis_start).total_seconds():.1f}s[/dim]")


def _render_plain_terminal(result: AnalysisResult) -> None:
    """Fallback plain-text reporter when rich is not available."""
    print("=== pgloglens v2.0 Report ===")
    print(f"Entries: {result.total_entries}")
    print(f"Slow queries: {len(result.slow_queries)}")
    print(f"Errors: {len(result.error_patterns)}")
    for sq in result.slow_queries:
        reg = " [REGRESSION]" if getattr(sq, "is_regression", False) else ""
        print(f"  [{sq.count}x avg={sq.avg_duration_ms:.0f}ms{reg}] {sq.normalized_query[:80]}")
    for ep in result.error_patterns:
        print(f"  [{ep.count}x {ep.error_code}] {ep.message_pattern[:80]}")


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def _default_serializer(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, list, dict)):
        return list(obj)
    if hasattr(obj, "value"):  # Enums
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def render_json(result: AnalysisResult) -> str:
    """Return a full JSON dump of the AnalysisResult."""
    data = json.loads(result.model_dump_json())
    return json.dumps(data, indent=2, default=_default_serializer)


# ---------------------------------------------------------------------------
# Markdown reporter
# ---------------------------------------------------------------------------

def render_markdown(result: AnalysisResult) -> str:
    """Return a GitHub-compatible Markdown report."""
    lines: List[str] = []

    lines.append("# pgloglens v2.0 — PostgreSQL Log Analysis Report\n")

    if result.time_range_start and result.time_range_end:
        delta = (result.time_range_end - result.time_range_start).total_seconds()
        lines.append(
            f"**Period:** {result.time_range_start.strftime('%Y-%m-%d %H:%M')} "
            f"→ {result.time_range_end.strftime('%Y-%m-%d %H:%M')} "
            f"({delta / 3600:.1f}h)\n"
        )

    platform = getattr(result, "source_platform", "postgresql")
    lines.append(f"**Platform:** {platform}  ")
    lines.append(f"**Entries analyzed:** {result.total_entries:,}  ")
    lines.append(f"**Slow query patterns:** {len(result.slow_queries)}  ")
    lines.append(f"**Error patterns:** {len(result.error_patterns)}  ")
    lines.append(f"**Lock events:** {len(result.lock_events)}  ")
    lines.append("\n---\n")

    # RCA Findings
    if result.rca_findings:
        lines.append("## Root Cause Analysis\n")
        for finding in result.rca_findings:
            sev_emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️", "INFO": "💡"}.get(
                finding.severity.value, "•"
            )
            lines.append(f"### {sev_emoji} [{finding.severity.value}] {finding.title}\n")
            lines.append(f"{finding.description}\n")
            if finding.recommendations:
                lines.append("\n**Recommendations:**\n")
                for rec in finding.recommendations:
                    lines.append(f"- {rec}\n")
            lines.append("\n")

    # Session stats
    ss = result.session_stats
    if ss and ss.total_sessions > 0:
        lines.append("## Session Statistics\n")
        lines.append(f"- Total sessions: **{ss.total_sessions:,}**\n")
        lines.append(f"- Peak concurrent: **{ss.peak_concurrent}**\n")
        lines.append(f"- Avg session duration: {ss.avg_session_duration_ms / 1000:.1f}s\n\n")

    # Query type distribution
    qt = result.query_type_stats
    total_qt = (
        qt.select_count + qt.insert_count + qt.update_count
        + qt.delete_count + qt.copy_count + qt.ddl_count + qt.other_count
    )
    if total_qt > 0:
        lines.append("## Query Type Distribution\n")
        lines.append("| Type | Count | Percentage |\n|------|-------|------------|\n")
        for qtype, count in [
            ("SELECT", qt.select_count), ("INSERT", qt.insert_count),
            ("UPDATE", qt.update_count), ("DELETE", qt.delete_count),
            ("COPY", qt.copy_count), ("DDL", qt.ddl_count), ("Other", qt.other_count),
        ]:
            if count > 0:
                pct = count / total_qt * 100
                lines.append(f"| {qtype} | {count:,} | {pct:.1f}% |\n")
        lines.append("\n")

    # Slow Queries
    if result.slow_queries:
        lines.append("## Top Slow Queries\n")
        lines.append(
            "| # | Type | Reg | Count | Avg (ms) | Max (ms) | P95 (ms) | P99 (ms) | Query |\n"
            "|---|------|-----|-------|----------|----------|----------|----------|-------|\n"
        )
        for i, sq in enumerate(result.slow_queries, 1):
            reg = "📈" if getattr(sq, "is_regression", False) else ""
            q = sq.normalized_query[:60].replace("|", "\\|")
            qtype = getattr(sq, "query_type", "?")[:6].upper()
            lines.append(
                f"| {i} | {qtype} | {reg} | {sq.count} | {sq.avg_duration_ms:,.0f} | {sq.max_duration_ms:,.0f} | "
                f"{sq.p95_duration_ms:,.0f} | {sq.p99_duration_ms:,.0f} | `{q}` |\n"
            )
        lines.append("\n")

        lines.append("### Query Details\n")
        for i, sq in enumerate(result.slow_queries, 1):
            reg_note = " ⚠ REGRESSION" if getattr(sq, "is_regression", False) else ""
            lines.append(f"**Query {i}** (count={sq.count}, avg={sq.avg_duration_ms:.0f}ms{reg_note})\n")
            lines.append(f"```sql\n{sq.normalized_query}\n```\n\n")

    # Error Patterns
    if result.error_patterns:
        lines.append("## Error Patterns\n")
        lines.append(
            "| Count | SQLSTATE | Category | Pattern |\n"
            "|-------|----------|----------|----------|\n"
        )
        for ep in result.error_patterns[:15]:
            pat = ep.message_pattern[:80].replace("|", "\\|")
            lines.append(f"| {ep.count} | {ep.error_code or '—'} | {ep.category} | {pat} |\n")
        lines.append("\n")

    # Connection Stats
    cs = result.connection_stats
    if cs.total_connections > 0:
        lines.append("## Connection Statistics\n")
        lines.append(f"- Total connections: **{cs.total_connections:,}**\n")
        lines.append(f"- Peak concurrent: **{cs.peak_concurrent}**\n")
        lines.append(f"- Auth failures: **{cs.auth_failures}**\n")
        lines.append("\n")

    # Checkpoint Stats
    cp = result.checkpoint_stats
    if cp.count > 0:
        lines.append("## Checkpoint Statistics\n")
        lines.append(f"- Count: {cp.count}\n")
        lines.append(f"- Avg duration: {cp.avg_duration_ms / 1000:.1f}s\n")
        lines.append(f"- Max duration: {cp.max_duration_ms / 1000:.1f}s\n")
        lines.append(f"- Frequency warnings: {cp.warning_count}\n")
        wal_added = getattr(result, "checkpoint_wal_added", 0)
        if wal_added:
            lines.append(f"- WAL files added/removed/recycled: "
                         f"{wal_added}/{getattr(result, 'checkpoint_wal_removed', 0)}/{getattr(result, 'checkpoint_wal_recycled', 0)}\n")
        lines.append("\n")

    # Lock Events
    if result.lock_events:
        lines.append("## Lock Events\n")
        lines.append(f"- Lock waits: {len(result.lock_events)}\n")
        lines.append(f"- Deadlocks: **{result.deadlock_count}**\n\n")

    # Temp Files
    if result.temp_files:
        total_mb = sum(t.size_mb for t in result.temp_files)
        lines.append("## Temporary Files\n")
        lines.append(f"- Events: {len(result.temp_files)}\n")
        lines.append(f"- Total size: {total_mb:.0f}MB\n\n")

    # LLM Analysis
    if result.llm_analysis:
        lines.append("## LLM-Powered Analysis\n")
        lines.append(f"{result.llm_analysis}\n\n")

    # Recommendations
    if result.recommendations:
        lines.append("## Recommendations\n")
        for i, rec in enumerate(result.recommendations[:15], 1):
            lines.append(f"{i}. {rec}\n")
        lines.append("\n")

    lines.append(
        f"---\n*Generated by pgloglens v2.0.0 on "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
    )

    return "".join(lines)


# ---------------------------------------------------------------------------
# HTML reporter (v2 — 13 tabs)
# ---------------------------------------------------------------------------

def render_html(result: AnalysisResult) -> str:
    """Return a self-contained HTML report with dark theme, Chart.js charts, and 13 tabs."""

    def _e(s: Any) -> str:
        """HTML-escape a string."""
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _sev_badge(sev: Severity) -> str:
        css = _SEVERITY_BADGE_CSS.get(sev, "badge-info")
        return f'<span class="badge {css}">{_e(sev.value)}</span>'

    # --- Chart data ---
    # 1. Top slow queries bar chart
    sq_labels = json.dumps([f"Q{i+1}" for i in range(min(10, len(result.slow_queries)))])
    sq_avg_data = json.dumps([round(sq.avg_duration_ms, 1) for sq in result.slow_queries[:10]])
    sq_max_data = json.dumps([round(sq.max_duration_ms, 1) for sq in result.slow_queries[:10]])

    # 2. Connections by hour
    conn_hours = list(range(24))
    conn_counts = json.dumps([result.connection_stats.connections_by_hour.get(h, 0) for h in conn_hours])
    conn_labels = json.dumps([f"{h:02d}:00" for h in conn_hours])

    # 3. Error hourly distribution
    err_hourly: Dict[int, int] = {}
    for ep in result.error_patterns:
        for h, c in ep.hourly_counts.items():
            err_hourly[h] = err_hourly.get(h, 0) + c
    err_counts = json.dumps([err_hourly.get(h, 0) for h in conn_hours])

    # 4. Error category pie
    err_categories: Dict[str, int] = {}
    for ep in result.error_patterns:
        err_categories[ep.category] = err_categories.get(ep.category, 0) + ep.count
    pie_labels = json.dumps(list(err_categories.keys()))
    pie_data = json.dumps(list(err_categories.values()))

    # 5. Query type distribution pie
    qt = result.query_type_stats
    qt_type_names = ["SELECT", "INSERT", "UPDATE", "DELETE", "COPY", "DDL", "Other"]
    qt_type_counts = [
        qt.select_count, qt.insert_count, qt.update_count,
        qt.delete_count, qt.copy_count, qt.ddl_count, qt.other_count,
    ]
    qt_labels = json.dumps(qt_type_names)
    qt_data = json.dumps(qt_type_counts)

    # 6. Prepare/bind/execute bar
    pb = result.prepare_bind_execute
    pbe_labels = json.dumps(["Parse", "Bind", "Execute"])
    pbe_data = json.dumps([round(pb.total_parse_ms, 1), round(pb.total_bind_ms, 1), round(pb.total_execute_ms, 1)])

    # Checkpoint duration chart data
    _cp_events = getattr(result, "checkpoint_events", [])
    cp_chart_labels = json.dumps(
        [e.timestamp.strftime("%m-%d %H:%M") if e.timestamp else str(i)
         for i, e in enumerate(_cp_events)]
    )
    cp_chart_dur = json.dumps([round(e.duration_ms / 1000, 1) for e in _cp_events])
    cp_chart_buf = json.dumps([e.buffers_written for e in _cp_events])

    # 7. Session duration histogram (9 buckets)
    ss = result.session_stats
    hist_buckets = ["<500ms", "<1s", "<30s", "<60s", "<10m", "<30m", "<1h", "<8h", "≥8h"]
    hist_data_raw = [ss.session_duration_histogram.get(b, 0) for b in hist_buckets] if ss else [0] * 9
    hist_data = json.dumps(hist_data_raw)
    hist_labels = json.dumps(hist_buckets)

    # 8. Session concurrent over time
    sess_time_labels = json.dumps(sorted(ss.concurrent_over_time.keys()) if ss else [])
    sess_time_data = json.dumps(
        [ss.concurrent_over_time[k] for k in sorted(ss.concurrent_over_time.keys())] if ss else []
    )

    # 9. DML over time
    dml_time_labels = json.dumps(sorted(qt.dml_over_time.keys()))
    dml_time_data = json.dumps([qt.dml_over_time[k] for k in sorted(qt.dml_over_time.keys())])

    # --- Time range ---
    time_range = ""
    if result.time_range_start and result.time_range_end:
        delta = (result.time_range_end - result.time_range_start).total_seconds()
        time_range = (
            f"{result.time_range_start.strftime('%Y-%m-%d %H:%M')} → "
            f"{result.time_range_end.strftime('%Y-%m-%d %H:%M')} "
            f"({delta / 3600:.1f}h)"
        )

    platform = getattr(result, "source_platform", "postgresql")

    # --- Slow query rows (with AI analysis and regression) ---
    sq_rows = []
    for i, sq in enumerate(result.slow_queries[:100], 1):
        reg_badge = (
            '<span class="badge badge-high" title="Performance regression">&#x1F4C8; Regression</span>'
            if getattr(sq, "is_regression", False) else ""
        )
        qtype_badge = f'<span class="category-badge">{_e(getattr(sq, "query_type", "?").upper())}</span>'
        apps = ", ".join(sorted(str(a) for a in getattr(sq, "applications", set()))[:3]) or "—"
        dbs = ", ".join(sorted(str(d) for d in getattr(sq, "databases", set()))[:3]) or "—"
        users = ", ".join(sorted(str(u) for u in getattr(sq, "users", set()))[:3]) or "—"
        first_seen = sq.first_seen.strftime("%Y-%m-%d %H:%M:%S") if sq.first_seen else "—"
        last_seen = sq.last_seen.strftime("%Y-%m-%d %H:%M:%S") if sq.last_seen else "—"
        # Build sample queries section (up to 3 raw examples)
        samples_html = ""
        for s in getattr(sq, "sample_queries", [])[:3]:
            samples_html += "<pre class='sql-block'>" + _e(s[:2000]) + "</pre>"
        if not samples_html:
            samples_html = "<pre class='sql-block'>" + _e(sq.query[:2000]) + "</pre>"
        # AI analysis section
        ai_html_block = ""
        if hasattr(sq, "_ai_analysis") and sq._ai_analysis:
            ai_txt = _e(sq._ai_analysis).replace("&#10;", "<br>")
            ai_html_block = f'<div class="ai-collapse"><strong>&#x1F916; AI Analysis:</strong><br>{ai_txt}</div>'
        row_id = "sq-detail-" + str(i)
        sq_rows.append(
            f"<tr class='sq-row' onclick=\"document.getElementById('{row_id}').classList.toggle('hidden')\">"
            f"<td>{i}</td>"
            f"<td>{qtype_badge}</td>"
            f"<td>{reg_badge}</td>"
            f"<td>{sq.count:,}</td>"
            f"<td>{sq.avg_duration_ms:,.1f}</td>"
            f"<td class='slow-max'><strong>{sq.max_duration_ms:,.1f}</strong></td>"
            f"<td>{sq.p95_duration_ms:,.1f}</td>"
            f"<td>{sq.p99_duration_ms:,.1f}</td>"
            f"<td>{sq.total_duration_ms / 1000:,.1f}s</td>"
            f"<td>{dbs}</td>"
            f"<td>{users}</td>"
            f"<td class='query-cell'><code>{_e(sq.normalized_query[:120])}</code></td>"
            f"</tr>"
            f"<tr id='{row_id}' class='hidden sq-detail-row'>"
            f"<td colspan='12'>"
            f"<div class='sq-detail-card'>"
            f"<div class='sq-meta'>"
            f"<span><strong>First seen:</strong> {first_seen}</span> "
            f"<span><strong>Last seen:</strong> {last_seen}</span> "
            f"<span><strong>Apps:</strong> {_e(apps)}</span> "
            f"<span><strong>Databases:</strong> {_e(dbs)}</span> "
            f"<span><strong>Users:</strong> {_e(users)}</span>"
            f"</div>"
            f"<div class='sq-full-query'><strong>Full Normalized Query:</strong>"
            f"<pre class='sql-block'>{_e(sq.normalized_query)}</pre></div>"
            f"<div class='sq-samples'><strong>Sample Executions:</strong>{samples_html}</div>"
            f"{ai_html_block}"
            f"</div></td></tr>"
        )

    # --- Error rows ---
    err_rows = []
    for ep in result.error_patterns[:50]:
        err_rows.append(
            f"<tr>"
            f"<td><strong>{ep.count:,}</strong></td>"
            f"<td><code>{_e(ep.error_code or '—')}</code></td>"
            f"<td><span class='category-badge'>{_e(ep.category)}</span></td>"
            f"<td title='{_e(ep.message_pattern)}'>{_e(ep.message_pattern[:120])}</td>"
            f"</tr>"
        )

    # --- RCA finding cards ---
    rca_cards = []
    for finding in result.rca_findings:
        badge = _sev_badge(finding.severity)
        color = _SEVERITY_HTML_COLORS.get(finding.severity, "#888")
        recs_html = "".join(f"<li>{_e(r)}</li>" for r in finding.recommendations[:3])
        evidence_html = "".join(f"<li class='evidence'>{_e(e)}</li>" for e in finding.evidence[:3])
        evidence_block = (
            "<ul class=\"evidence-list\">" + evidence_html + "</ul>"
            if evidence_html else ""
        )
        rca_cards.append(
            f"<div class='rca-card' style='border-left: 4px solid {color}'>"
            f"  <div class='rca-header'>{badge} <strong>{_e(finding.title)}</strong></div>"
            f"  <p class='rca-desc'>{_e(finding.description)}</p>"
            f"  {evidence_block}"
            f"  <div class='rca-recs'><strong>Recommendations:</strong><ul>{recs_html}</ul></div>"
            f"</div>"
        )

    # --- Lock event rows ---
    lock_rows = []
    for ev in result.lock_events[:30]:
        lock_rows.append(
            f"<tr>"
            f"<td>{'🔴 DEADLOCK' if ev.is_deadlock else '🟡 Lock wait'}</td>"
            f"<td>{ev.waiting_pid or '—'}</td>"
            f"<td>{ev.blocking_pid or '—'}</td>"
            f"<td>{_e(ev.lock_type or '—')}</td>"
            f"<td>{ev.timestamp.strftime('%H:%M:%S') if ev.timestamp else '—'}</td>"
            f"</tr>"
        )

    # --- Autovacuum rows: aggregate by table (summary) + per-run detail ---
    av_rows = []
    av_detail_rows = []
    from .analyzer import analyze_autovacuum_frequency
    if result.autovacuum_stats:
        # Summary rows (aggregate per table)
        for table, count, avg in analyze_autovacuum_frequency(result.autovacuum_stats)[:50]:
            table_avs = [av for av in result.autovacuum_stats if av.table == table]
            total_tuples = sum(a.tuples_removed for a in table_avs)
            total_pages = sum(a.pages_removed for a in table_avs)
            max_dur = max((a.duration_ms for a in table_avs), default=0)
            total_wal_mb = sum((a.wal_bytes or 0) for a in table_avs) / (1024 * 1024)
            av0 = table_avs[0] if table_avs else None
            buf_hits = sum(a.buffer_hits for a in table_avs)
            buf_misses = sum(a.buffer_misses for a in table_avs)
            cpu_s = sum((a.cpu_user_s + a.cpu_sys_s) for a in table_avs)
            kind = "ANALYZE" if (av0 and av0.is_analyze) else "VACUUM"
            kind_badge = f'<span class="category-badge">{kind}</span>'
            av_rows.append(
                f"<tr>"
                f"<td>{_e(table)}</td>"
                f"<td>{kind_badge}</td>"
                f"<td>{count}</td>"
                f"<td>{avg / 1000:.2f}s</td>"
                f"<td>{max_dur / 1000:.2f}s</td>"
                f"<td>{total_tuples:,}</td>"
                f"<td>{total_pages:,}</td>"
                f"<td>{buf_hits:,}</td>"
                f"<td>{buf_misses:,}</td>"
                f"<td>{total_wal_mb:.2f} MB</td>"
                f"<td>{cpu_s:.2f}s</td>"
                f"</tr>"
            )
        # Per-run detail rows (all individual runs, sorted by duration)
        for av in sorted(result.autovacuum_stats, key=lambda a: a.duration_ms, reverse=True)[:200]:
            ts_str = av.timestamp.strftime("%Y-%m-%d %H:%M:%S") if av.timestamp else "—"
            dur_s = av.duration_ms / 1000.0
            dur_cls = "danger" if dur_s > 60 else ("warn" if dur_s > 10 else "")
            kind = "ANALYZE" if av.is_analyze else "VACUUM"
            kind_badge = f'<span class="category-badge">{kind}</span>'
            wal_mb = (av.wal_bytes or 0) / (1024 * 1024)
            cpu_s = av.cpu_user_s + av.cpu_sys_s
            av_detail_rows.append(
                f"<tr>"
                f"<td>{ts_str}</td>"
                f"<td>{_e(av.table)}</td>"
                f"<td>{kind_badge}</td>"
                f"<td class='{dur_cls}'>{dur_s:.2f}s</td>"
                f"<td>{av.tuples_removed:,}</td>"
                f"<td>{av.pages_removed:,}</td>"
                f"<td>{av.dead_tuples_before:,}</td>"
                f"<td>{av.buffer_hits:,}</td>"
                f"<td>{av.buffer_misses:,}</td>"
                f"<td>{wal_mb:.2f} MB</td>"
                f"<td>{cpu_s:.2f}s</td>"
                f"<td>{av.index_scans}</td>"
                f"</tr>"
            )

    # --- Temp file rows ---
    tf_rows = []
    for tf in result.temp_files[:20]:
        tf_rows.append(
            f"<tr>"
            f"<td>{tf.size_mb:.1f} MB</td>"
            f"<td>{tf.database or '—'}</td>"
            f"<td>{tf.user or '—'}</td>"
            f"<td>{tf.timestamp.strftime('%H:%M:%S') if tf.timestamp else '—'}</td>"
            f"<td><code>{_e((tf.query or '—')[:80])}</code></td>"
            f"</tr>"
        )

    # --- Checkpoint event rows ---
    cp_event_rows = []
    for ce in getattr(result, "checkpoint_events", []):
        ts = ce.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ce.timestamp else "—"
        dur_s = ce.duration_ms / 1000.0
        dur_cls = "danger" if dur_s > 300 else ("warn" if dur_s > 60 else "")
        dist_str = f"{ce.distance_kb / 1024:.0f} MB" if ce.distance_kb else "—"
        est_str = f"{ce.estimate_kb / 1024:.0f} MB" if ce.estimate_kb else "—"
        wal_str = f"+{ce.wal_added}/{ce.wal_removed}/{ce.wal_recycled}"
        type_badge = f'<span class="category-badge">{_e(ce.checkpoint_type.upper())}</span>'
        cp_event_rows.append(
            f"<tr>"
            f"<td>{ts}</td>"
            f"<td>{type_badge}</td>"
            f"<td class='{dur_cls}'><strong>{dur_s:.1f}s</strong></td>"
            f"<td>{ce.write_s:.1f}s</td>"
            f"<td>{ce.sync_s:.3f}s</td>"
            f"<td>{ce.buffers_written:,}</td>"
            f"<td>{ce.buffers_pct:.1f}%</td>"
            f"<td>{wal_str}</td>"
            f"<td>{dist_str}</td>"
            f"<td>{est_str}</td>"
            f"</tr>"
        )

    # --- All queries rows (sorted by duration desc) ---
    # Combine slow queries sample_queries + all duration entries from result
    # We use slow_queries to build a per-execution view with what we have
    all_query_rows = []
    _all_q_entries: list = []
    for sq in result.slow_queries:
        qtype = getattr(sq, "query_type", "other")
        dbs_list = sorted(str(d) for d in getattr(sq, "databases", set()))
        users_list = sorted(str(u) for u in getattr(sq, "users", set()))
        apps_list = sorted(str(a) for a in getattr(sq, "applications", set()))
        # Add one row per sampled execution if durations list available
        raw_durs = getattr(sq, "durations", [])
        for j, dur in enumerate(raw_durs[:20]):  # cap at 20 executions per pattern
            _all_q_entries.append({
                "dur": dur,
                "qtype": qtype,
                "query": sq.query,
                "norm": sq.normalized_query,
                "db": dbs_list[0] if dbs_list else "—",
                "user": users_list[0] if users_list else "—",
                "app": apps_list[0] if apps_list else "—",
                "ts": (sq.first_seen.strftime("%Y-%m-%d %H:%M:%S") if sq.first_seen else "—"),
            })
    _all_q_entries.sort(key=lambda x: x["dur"], reverse=True)
    for k, qe in enumerate(_all_q_entries[:500], 1):
        dur_ms = qe["dur"]
        dur_cls = "danger" if dur_ms > 5000 else ("warn" if dur_ms > 1000 else "")
        qtype_badge = f'<span class="category-badge">{_e(qe["qtype"].upper())}</span>'
        row_id2 = "aq-detail-" + str(k)
        all_query_rows.append(
            f"<tr class='sq-row' onclick=\"document.getElementById('{row_id2}').classList.toggle('hidden')\">"
            f"<td>{k}</td>"
            f"<td class='{dur_cls}'>{dur_ms:,.1f}</td>"
            f"<td>{qtype_badge}</td>"
            f"<td>{_e(qe['db'])}</td>"
            f"<td>{_e(qe['user'])}</td>"
            f"<td>{_e(qe['app'])}</td>"
            f"<td>{_e(qe['ts'])}</td>"
            f"<td class='query-cell'><code>{_e(qe['norm'][:120])}</code></td>"
            f"</tr>"
            f"<tr id='{row_id2}' class='hidden sq-detail-row'>"
            f"<td colspan='8'>"
            f"<div class='sq-detail-card'>"
            f"<div class='sq-meta'>"
            f"<span><strong>Database:</strong> {_e(qe['db'])}</span> "
            f"<span><strong>User:</strong> {_e(qe['user'])}</span> "
            f"<span><strong>App:</strong> {_e(qe['app'])}</span> "
            f"<span><strong>Duration:</strong> {dur_ms:,.1f} ms</span>"
            f"</div>"
            f"<strong>Full Query:</strong>"
            f"<pre class='sql-block'>{_e(qe['query'][:3000])}</pre>"
            f"</div></td></tr>"
        )

    # --- Session stats rows (by db/user/host/app) ---
    sess_db_rows = ""
    sess_user_rows = ""
    sess_host_rows = ""
    sess_app_rows = ""
    if ss:
        sess_db_rows = "".join(
            f"<tr><td>{_e(d)}</td><td>{c}</td></tr>"
            for d, c in sorted(ss.sessions_by_database.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        sess_user_rows = "".join(
            f"<tr><td>{_e(u)}</td><td>{c}</td></tr>"
            for u, c in sorted(ss.sessions_by_user.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        sess_host_rows = "".join(
            f"<tr><td>{_e(h)}</td><td>{c}</td></tr>"
            for h, c in sorted(ss.sessions_by_host.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        sess_app_rows = "".join(
            f"<tr><td>{_e(a)}</td><td>{c}</td></tr>"
            for a, c in sorted(ss.sessions_by_application.items(), key=lambda x: x[1], reverse=True)[:10]
        )

    # --- Query type by database rows ---
    qt_db_rows = ""
    for db, type_counts in list(qt.by_database.items())[:10]:
        total = sum(type_counts.values())
        sel = type_counts.get("select", 0)
        ins = type_counts.get("insert", 0)
        upd = type_counts.get("update", 0)
        dlt = type_counts.get("delete", 0)
        qt_db_rows += (
            f"<tr><td>{_e(db)}</td><td>{total:,}</td>"
            f"<td>{sel:,}</td><td>{ins:,}</td><td>{upd:,}</td><td>{dlt:,}</td></tr>"
        )

    # --- Cancellations list ---
    cancelled_rows = ""
    cancelled = getattr(result, "cancelled_queries", [])
    for c in cancelled[:20]:
        ts = c.get("timestamp", "—")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%H:%M:%S")
        cancelled_rows += (
            f"<tr><td>{_e(str(ts))}</td>"
            f"<td>{_e(str(c.get('query', '—'))[:80])}</td>"
            f"<td>{_e(str(c.get('database', '—')))}</td>"
            f"<td>{_e(str(c.get('user', '—')))}</td></tr>"
        )

    # --- Auto-explain plan rows ---
    auto_plans = getattr(result, "auto_explain_plans", [])
    explain_rows = ""
    for plan in sorted(auto_plans, key=lambda p: p.duration_ms, reverse=True)[:20]:
        ai_col = _e(plan.ai_analysis[:200]) if plan.ai_analysis else "—"
        explain_rows += (
            f"<tr>"
            f"<td>{plan.timestamp.strftime('%H:%M:%S') if plan.timestamp else '—'}</td>"
            f"<td><strong>{plan.duration_ms:,.0f}ms</strong></td>"
            f"<td>{_e(plan.database or '—')}</td>"
            f"<td><code>{_e(plan.query[:80])}</code></td>"
            f"<td><details><summary>View plan</summary><pre>{_e(plan.plan_text[:1000])}</pre></details></td>"
            f"<td>{ai_col}</td>"
            f"</tr>"
        )

    # --- PgBouncer section ---
    pgb = result.pgbouncer_stats
    pgbouncer_html = ""
    if pgb is not None:
        pgb_db_rows = "".join(
            f"<tr><td>{_e(d)}</td><td>{c}</td></tr>"
            for d, c in sorted(pgb.connections_by_db.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        pgb_user_rows = "".join(
            f"<tr><td>{_e(u)}</td><td>{c}</td></tr>"
            for u, c in sorted(pgb.connections_by_user.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        pgb_err_rows = "".join(
            f"<tr><td>{_e(e[:150])}</td></tr>"
            for e in pgb.pool_errors[:20]
        )
        pgbouncer_html = f"""
        <div class="stats-strip">
          <div class="mini-stat"><div class="val">{pgb.total_requests:,}</div><div class="lbl">Total Requests</div></div>
          <div class="mini-stat"><div class="val">{pgb.avg_query_ms:.1f}ms</div><div class="lbl">Avg Query</div></div>
          <div class="mini-stat"><div class="val">{pgb.max_query_ms:.1f}ms</div><div class="lbl">Max Query</div></div>
          <div class="mini-stat {'danger' if pgb.pool_errors else ''}"><div class="val">{len(pgb.pool_errors)}</div><div class="lbl">Pool Errors</div></div>
        </div>
        <div class="grid-2">
          <div class="card">
            <div class="card-title">🗄 PgBouncer Connections by Database</div>
            <table class="data-table">
              <thead><tr><th>Database</th><th>Connections</th></tr></thead>
              <tbody>{pgb_db_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
            </table>
          </div>
          <div class="card">
            <div class="card-title">👤 PgBouncer Connections by User</div>
            <table class="data-table">
              <thead><tr><th>User</th><th>Connections</th></tr></thead>
              <tbody>{pgb_user_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
            </table>
          </div>
        </div>
        {'<div class="card"><div class="card-title" style="color:var(--red)">⚠ Pool Errors</div><table class="data-table"><thead><tr><th>Error Message</th></tr></thead><tbody>' + pgb_err_rows + "</tbody></table></div>" if pgb.pool_errors else ""}
        """

    # --- LLM section ---
    llm_section = ""
    if result.llm_analysis:
        llm_section = f"<div class='llm-analysis'>{_e(result.llm_analysis).replace(chr(10), '<br>')}</div>"

    # --- Recommendations: AI index recs + generated config ---
    ai_index_html = ""
    ai_index_recs = getattr(result, "ai_index_recommendations", None)
    if ai_index_recs:
        ai_index_rows = ""
        for rec in ai_index_recs[:10]:
            sql = _e(rec.get("create_index_sql", ""))
            rationale = _e(rec.get("rationale", ""))
            speedup = _e(rec.get("estimated_speedup", ""))
            query = _e(str(rec.get("query", ""))[:80])
            ai_index_rows += (
                f"<tr>"
                f"<td><code>{sql}</code></td>"
                f"<td>{query}</td>"
                f"<td>{rationale[:100]}</td>"
                f"<td>{speedup}</td>"
                f"</tr>"
            )
        ai_index_html = f"""
        <div class="card">
          <div class="card-title">🤖 AI Index Recommendations</div>
          <table class="data-table">
            <thead><tr><th>CREATE INDEX Statement</th><th>Query</th><th>Rationale</th><th>Est. Speedup</th></tr></thead>
            <tbody>{ai_index_rows}</tbody>
          </table>
        </div>
        """

    ai_config_html = ""
    ai_config = getattr(result, "ai_generated_config", None)
    if ai_config:
        ai_config_html = f"""
        <div class="card">
          <div class="card-title">⚙️ AI-Generated postgresql.conf Recommendations</div>
          <pre class="code-block">{_e(ai_config)}</pre>
        </div>
        """

    recs_html = "".join(
        f'<li class="rec-item">{_e(r)}</li>' for r in result.recommendations[:20]
    )

    # --- Connection host/app rows ---
    conn_by_host = getattr(result, "connection_by_host", {}) or result.connection_stats.connections_by_host
    conn_by_app = getattr(result, "connection_by_application", {}) or result.connection_stats.connections_by_application
    conn_host_rows = "".join(
        f"<tr><td>{_e(h)}</td><td>{c}</td></tr>"
        for h, c in sorted(conn_by_host.items(), key=lambda x: x[1], reverse=True)[:15]
    )
    conn_app_rows = "".join(
        f"<tr><td>{_e(a)}</td><td>{c}</td></tr>"
        for a, c in sorted(conn_by_app.items(), key=lambda x: x[1], reverse=True)[:15]
    )

    # --- Checkpoint WAL info ---
    wal_added = getattr(result, "checkpoint_wal_added", 0)
    wal_removed = getattr(result, "checkpoint_wal_removed", 0)
    wal_recycled = getattr(result, "checkpoint_wal_recycled", 0)

    # Determine which tabs to show
    show_pgbouncer_tab = pgb is not None
    tab_count_label = f"({len(result.slow_queries)})"
    err_tab_label = f"({len(result.error_patterns)})"
    lock_tab_label = f"({len(result.lock_events)})"
    rca_tab_label = f"({len(result.rca_findings)})"
    explain_tab_label = f"({len(auto_plans)})"

    # Cancelled count for query types tab
    cancelled_count = len(cancelled)

    # Pre-compute conditional nav buttons (backslash not allowed inside f-string exprs in py3.9)
    pgbouncer_nav_btn = (
        '<button class="nav-btn" onclick="showTab(\'pgbouncer\')">PgBouncer</button>'
        if show_pgbouncer_tab else ''
    )
    llm_nav_btn = (
        '<button class="nav-btn" onclick="showTab(\'llm\')">LLM Analysis</button>'
        if result.llm_analysis else ''
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pgloglens v2 Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117;
    --bg2: #161b22;
    --bg3: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #1f6feb;
    --accent2: #388bfd;
    --green: #3fb950;
    --yellow: #d29922;
    --red: #f85149;
    --orange: #e3b341;
    --cyan: #39d353;
    --pg-blue: #336791;
    --pg-blue-light: #4a8db8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent2); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  pre {{ white-space: pre-wrap; word-break: break-all; }}
  details summary {{ cursor: pointer; color: var(--accent2); }}
  .hidden {{ display: none !important; }}

  /* Layout */
  .header {{ background: linear-gradient(135deg, var(--pg-blue) 0%, #1a3a5c 100%); padding: 24px 32px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 16px; }}
  .header-logo {{ font-size: 28px; font-weight: 700; color: white; letter-spacing: -0.5px; }}
  .header-logo span {{ color: var(--orange); }}
  .header-meta {{ color: rgba(255,255,255,0.7); font-size: 13px; margin-top: 4px; }}
  .header-stats {{ margin-left: auto; display: flex; gap: 16px; flex-wrap: wrap; justify-content: flex-end; }}
  .stat-pill {{ background: rgba(255,255,255,0.1); border-radius: 8px; padding: 8px 14px; text-align: center; }}
  .stat-pill .val {{ font-size: 20px; font-weight: 700; color: white; }}
  .stat-pill .lbl {{ font-size: 11px; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 0.5px; }}

  .nav {{ background: var(--bg2); border-bottom: 1px solid var(--border); padding: 0 32px; display: flex; gap: 0; overflow-x: auto; }}
  .nav-btn {{ padding: 12px 16px; background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 12px; font-weight: 500; border-bottom: 2px solid transparent; transition: all 0.15s; white-space: nowrap; }}
  .nav-btn:hover {{ color: var(--text); }}
  .nav-btn.active {{ color: var(--accent2); border-bottom-color: var(--accent2); }}

  .content {{ padding: 24px 32px; max-width: 1400px; margin: 0 auto; }}
  .tab-pane {{ display: none; }}
  .tab-pane.active {{ display: block; }}

  /* Cards */
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .card-title {{ font-size: 15px; font-weight: 600; margin-bottom: 16px; color: var(--text); display: flex; align-items: center; gap: 8px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
  .chart-container {{ position: relative; height: 260px; }}

  /* Tables */
  .data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .data-table th {{ background: var(--bg3); color: var(--text-muted); font-weight: 600; text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer; user-select: none; }}
  .data-table th:hover {{ color: var(--text); }}
  .data-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  .data-table tr:hover td {{ background: var(--bg3); }}
  .data-table code {{ background: var(--bg3); padding: 2px 6px; border-radius: 4px; font-size: 12px; font-family: 'SF Mono', Menlo, monospace; color: var(--accent2); }}
  .query-cell {{ max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; }}
  .ai-row td {{ background: #0d1f0d; border-left: 3px solid var(--green); }}
  .ai-collapse {{ font-size: 12px; color: var(--text-muted); padding: 8px; white-space: pre-wrap; }}
  /* Expandable query rows */
  .sq-row {{ cursor: pointer; }}
  .sq-row:hover td {{ background: rgba(58,134,255,0.07) !important; }}
  .sq-detail-row td {{ padding: 0 !important; }}
  .sq-detail-card {{ background: var(--bg2); border-left: 3px solid var(--accent2); padding: 14px 18px; margin: 4px 0; border-radius: 4px; }}
  .sq-meta {{ display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 10px; font-size: 12px; color: var(--text-muted); }}
  .sq-meta span strong {{ color: var(--text); }}
  .sq-full-query, .sq-samples {{ margin-top: 10px; }}
  .sql-block {{ background: #0a0a14; border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; font-family: 'SF Mono', Menlo, 'Cascadia Code', monospace; font-size: 12px; color: #a8d8a8; white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto; margin-top: 6px; line-height: 1.5; }}
  .slow-max {{ color: var(--orange); }}
  .danger {{ color: #ff6b6b !important; }}
  .warn {{ color: var(--orange) !important; }}
  /* Search bar */
  .search-bar {{ width: 100%; padding: 8px 14px; background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 13px; margin-bottom: 12px; }}
  .search-bar:focus {{ outline: none; border-color: var(--accent2); }}
  /* Checkpoint/AV tabs */
  .cp-stat {{ display: inline-block; background: var(--bg3); border-radius: 6px; padding: 10px 18px; margin: 4px; text-align: center; min-width: 120px; }}
  .cp-stat .val {{ font-size: 20px; font-weight: 700; color: var(--accent2); }}
  .cp-stat .lbl {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .code-block {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 16px; font-family: 'SF Mono', Menlo, monospace; font-size: 12px; color: var(--accent2); }}

  /* Badges */
  .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
  .badge-critical {{ background: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }}
  .badge-high {{ background: rgba(227, 179, 65, 0.15); color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }}
  .badge-medium {{ background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210,153,34,0.3); }}
  .badge-low {{ background: rgba(57, 211, 83, 0.15); color: #3fb950; border: 1px solid rgba(57,211,83,0.3); }}
  .badge-info {{ background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid rgba(139,148,158,0.3); }}
  .category-badge {{ background: var(--bg3); padding: 2px 8px; border-radius: 4px; font-size: 11px; color: var(--text-muted); }}

  /* RCA Cards */
  .rca-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 12px; }}
  .rca-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .rca-desc {{ color: var(--text-muted); font-size: 13px; margin-bottom: 12px; line-height: 1.6; }}
  .evidence-list {{ list-style: none; margin: 0 0 12px 0; }}
  .evidence {{ font-size: 12px; color: var(--text-muted); padding: 2px 0; }}
  .evidence::before {{ content: "▸ "; color: var(--accent2); }}
  .rca-recs ul {{ margin: 8px 0 0 16px; }}
  .rca-recs li {{ font-size: 12px; color: var(--text); margin: 4px 0; }}
  .rca-recs strong {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}

  /* Summary stats strip */
  .stats-strip {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
  .mini-stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 12px 16px; flex: 1; min-width: 110px; }}
  .mini-stat .val {{ font-size: 22px; font-weight: 700; color: var(--text); }}
  .mini-stat .lbl {{ font-size: 11px; color: var(--text-muted); margin-top: 2px; }}
  .mini-stat.danger .val {{ color: var(--red); }}
  .mini-stat.warn .val {{ color: var(--orange); }}
  .mini-stat.good .val {{ color: var(--green); }}

  /* LLM Analysis */
  .llm-analysis {{ background: var(--bg3); border: 1px solid var(--pg-blue); border-radius: 8px; padding: 20px; font-size: 14px; line-height: 1.8; white-space: pre-wrap; }}

  /* Recommendations */
  .rec-item {{ padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
  .rec-item:last-child {{ border-bottom: none; }}
  ol {{ padding-left: 20px; }}

  /* Export button */
  .export-btn {{ background: var(--pg-blue); color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }}
  .export-btn:hover {{ background: var(--pg-blue-light); }}
  .toolbar {{ display: flex; justify-content: flex-end; margin-bottom: 16px; gap: 8px; }}

  /* Sortable indicator */
  .sort-asc::after {{ content: " ▲"; }}
  .sort-desc::after {{ content: " ▼"; }}

  @media (max-width: 900px) {{
    .grid-2, .grid-3, .grid-4 {{ grid-template-columns: 1fr; }}
    .header-stats {{ display: none; }}
  }}

  @media print {{
    .nav {{ display: none; }}
    .tab-pane {{ display: block !important; page-break-before: always; }}
    .export-btn {{ display: none; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-logo">pg<span>Loglens</span> <small style="font-size:14px;opacity:0.7">v2.0</small></div>
    <div class="header-meta">PostgreSQL Log Analysis Report &bull; {_e(time_range)}</div>
    <div class="header-meta">Files: {_e(", ".join(result.log_file_paths))} &bull; Platform: {_e(platform)}</div>
  </div>
  <div class="header-stats">
    <div class="stat-pill"><div class="val">{result.total_entries:,}</div><div class="lbl">Log Entries</div></div>
    <div class="stat-pill"><div class="val">{len(result.slow_queries)}</div><div class="lbl">Slow Queries</div></div>
    <div class="stat-pill"><div class="val">{len(result.error_patterns)}</div><div class="lbl">Error Patterns</div></div>
    <div class="stat-pill"><div class="val">{len(result.lock_events)}</div><div class="lbl">Lock Events</div></div>
    <div class="stat-pill"><div class="val">{result.deadlock_count}</div><div class="lbl">Deadlocks</div></div>
    <div class="stat-pill"><div class="val">{len(auto_plans)}</div><div class="lbl">Explain Plans</div></div>
  </div>
</div>

<div class="nav">
  <button class="nav-btn active" onclick="showTab('overview')">Overview</button>
  <button class="nav-btn" onclick="showTab('slow-queries')">Slow Queries {tab_count_label}</button>
  <button class="nav-btn" onclick="showTab('all-queries')">All Queries</button>
  <button class="nav-btn" onclick="showTab('checkpoints')">Checkpoints ({len(getattr(result, 'checkpoint_events', []))})</button>
  <button class="nav-btn" onclick="showTab('errors')">Errors {err_tab_label}</button>
  <button class="nav-btn" onclick="showTab('connections')">Connections</button>
  <button class="nav-btn" onclick="showTab('locks')">Lock Events {lock_tab_label}</button>
  <button class="nav-btn" onclick="showTab('autovacuum')">Autovacuum</button>
  <button class="nav-btn" onclick="showTab('sessions')">Sessions</button>
  <button class="nav-btn" onclick="showTab('query-types')">Query Types</button>
  <button class="nav-btn" onclick="showTab('prepare-execute')">Prepare/Execute</button>
  <button class="nav-btn" onclick="showTab('auto-explain')">Auto-Explain {explain_tab_label}</button>
  {pgbouncer_nav_btn}
  <button class="nav-btn" onclick="showTab('rca')">RCA {rca_tab_label}</button>
  {llm_nav_btn}
  <button class="nav-btn" onclick="showTab('recommendations')">Recommendations</button>
</div>

<div class="content">

  <!-- OVERVIEW -->
  <div id="tab-overview" class="tab-pane active">
    <div class="stats-strip">
      <div class="mini-stat {'danger' if result.connection_stats.auth_failures > 50 else 'warn' if result.connection_stats.auth_failures > 10 else ''}">
        <div class="val">{result.connection_stats.auth_failures}</div><div class="lbl">Auth Failures</div></div>
      <div class="mini-stat">
        <div class="val">{result.connection_stats.peak_concurrent}</div><div class="lbl">Peak Connections</div></div>
      <div class="mini-stat {'danger' if result.deadlock_count > 0 else ''}">
        <div class="val">{result.deadlock_count}</div><div class="lbl">Deadlocks</div></div>
      <div class="mini-stat {'warn' if result.checkpoint_stats.warning_count > 0 else ''}">
        <div class="val">{result.checkpoint_stats.warning_count}</div><div class="lbl">Checkpoint Warnings</div></div>
      <div class="mini-stat {'warn' if len(result.temp_files) > 10 else ''}">
        <div class="val">{len(result.temp_files)}</div><div class="lbl">Temp Files</div></div>
      <div class="mini-stat {'danger' if len(result.panic_fatal_events) > 0 else ''}">
        <div class="val">{len(result.panic_fatal_events)}</div><div class="lbl">FATAL/PANIC</div></div>
      <div class="mini-stat {'warn' if cancelled_count > 20 else ''}">
        <div class="val">{cancelled_count}</div><div class="lbl">Cancelled Queries</div></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">⏱ Query Duration Distribution (Top 10)</div>
        <div class="chart-container"><canvas id="slowQueryChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">📈 Connections by Hour</div>
        <div class="chart-container"><canvas id="connChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">🚨 Errors by Hour</div>
        <div class="chart-container"><canvas id="errChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">🗂 Error Categories</div>
        <div class="chart-container"><canvas id="errPieChart"></canvas></div>
      </div>
    </div>

    {('<div class="card"><div class="card-title">⚠️ Top RCA Findings</div>' + "".join(rca_cards[:3]) + "</div>") if rca_cards else ""}
  </div>

  <!-- SLOW QUERIES -->
  <div id="tab-slow-queries" class="tab-pane">
    <div class="card">
      <div class="card-title">&#x1F422; Slow Query Patterns &mdash; click any row to expand full SQL + samples</div>
      <p style="color:var(--text-muted);font-size:12px;margin-bottom:10px">Showing top {len(result.slow_queries[:100])} patterns &bull; threshold {result.slow_query_threshold_ms:.0f} ms &bull; click column headers to sort</p>
      <input class="search-bar" id="sq-search" type="text" placeholder="Search queries, databases, users..." oninput="filterTable('sq-table','sq-search')">
      <table class="data-table" id="sq-table">
        <thead><tr>
          <th onclick="sortTable('sq-table',0)">#</th>
          <th>Type</th>
          <th>Regression</th>
          <th onclick="sortTable('sq-table',3)">Count</th>
          <th onclick="sortTable('sq-table',4)">Avg&nbsp;ms</th>
          <th onclick="sortTable('sq-table',5)">Max&nbsp;ms</th>
          <th onclick="sortTable('sq-table',6)">P95&nbsp;ms</th>
          <th onclick="sortTable('sq-table',7)">P99&nbsp;ms</th>
          <th onclick="sortTable('sq-table',8)">Total&nbsp;time</th>
          <th>Database(s)</th>
          <th>User(s)</th>
          <th>Normalized Query (click to expand)</th>
        </tr></thead>
        <tbody>{"".join(sq_rows)}</tbody>
      </table>
    </div>
  </div>

  <!-- ALL QUERIES -->
  <div id="tab-all-queries" class="tab-pane">
    <div class="card">
      <div class="card-title">&#x1F4CB; All Executed Queries &mdash; sampled executions sorted by duration</div>
      <p style="color:var(--text-muted);font-size:12px;margin-bottom:10px">Up to 500 sampled executions from tracked query patterns &bull; click row to expand full SQL</p>
      <input class="search-bar" id="aq-search" type="text" placeholder="Search queries, databases, users, apps..." oninput="filterTable('aq-table','aq-search')">
      <table class="data-table" id="aq-table">
        <thead><tr>
          <th>#</th>
          <th onclick="sortTable('aq-table',1)">Duration&nbsp;ms</th>
          <th>Type</th>
          <th onclick="sortTable('aq-table',3)">Database</th>
          <th onclick="sortTable('aq-table',4)">User</th>
          <th onclick="sortTable('aq-table',5)">Application</th>
          <th>Timestamp</th>
          <th>Query (click to expand)</th>
        </tr></thead>
        <tbody>{"".join(all_query_rows) if all_query_rows else "<tr><td colspan='8' style='text-align:center;color:var(--text-muted);padding:24px'>No query execution data &mdash; queries are only tracked when log_min_duration_statement is set</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- ERRORS -->
  <div id="tab-errors" class="tab-pane">
    <div class="card">
      <div class="card-title">🚨 Error Patterns</div>
      <table class="data-table" id="err-table">
        <thead><tr>
          <th onclick="sortTable('err-table',0)">Count</th>
          <th>SQLSTATE</th>
          <th>Category</th>
          <th>Message Pattern</th>
        </tr></thead>
        <tbody>{"".join(err_rows)}</tbody>
      </table>
    </div>
  </div>

  <!-- CONNECTIONS -->
  <div id="tab-connections" class="tab-pane">
    <div class="grid-2">
      <div class="card">
        <div class="card-title">📊 Connection Statistics</div>
        <table class="data-table">
          <tbody>
            <tr><td>Total Connections</td><td><strong>{result.connection_stats.total_connections:,}</strong></td></tr>
            <tr><td>Total Disconnections</td><td>{result.connection_stats.total_disconnections:,}</td></tr>
            <tr><td>Peak Concurrent</td><td><strong>{result.connection_stats.peak_concurrent}</strong></td></tr>
            <tr><td>Auth Failures</td><td style="color:var(--red)">{result.connection_stats.auth_failures}</td></tr>
          </tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">👤 Top Users by Connections</div>
        <table class="data-table">
          <thead><tr><th>User</th><th>Connections</th></tr></thead>
          <tbody>{"".join(f"<tr><td>{_e(u)}</td><td>{c}</td></tr>" for u,c in sorted(result.connection_stats.connections_by_user.items(), key=lambda x: x[1], reverse=True)[:10])}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">🗄 Connections by Database</div>
        <table class="data-table">
          <thead><tr><th>Database</th><th>Connections</th></tr></thead>
          <tbody>{"".join(f"<tr><td>{_e(d)}</td><td>{c}</td></tr>" for d,c in sorted(result.connection_stats.connections_by_database.items(), key=lambda x: x[1], reverse=True)[:10])}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">🌐 Connections by Host/IP</div>
        <table class="data-table">
          <thead><tr><th>Host</th><th>Connections</th></tr></thead>
          <tbody>{conn_host_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No host data</td></tr>"}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">📱 Connections by Application</div>
        <table class="data-table">
          <thead><tr><th>Application</th><th>Connections</th></tr></thead>
          <tbody>{conn_app_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No application data</td></tr>"}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">⏰ Connections by Hour</div>
        <div class="chart-container"><canvas id="connHourChart"></canvas></div>
      </div>
    </div>
  </div>

  <!-- LOCK EVENTS -->
  <div id="tab-locks" class="tab-pane">
    <div class="card">
      <div class="card-title">🔒 Lock Events</div>
      {"<p style='color:var(--red);font-weight:600;margin-bottom:16px'>⚠️ " + str(result.deadlock_count) + " deadlock(s) detected</p>" if result.deadlock_count else ""}
      <table class="data-table">
        <thead><tr><th>Type</th><th>Waiting PID</th><th>Blocking PID</th><th>Lock Type</th><th>Time</th></tr></thead>
        <tbody>{("".join(lock_rows)) if lock_rows else "<tr><td colspan='5' style='text-align:center;color:var(--text-muted)'>No lock events detected</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- CHECKPOINTS TAB -->
  <div id="tab-checkpoints" class="tab-pane">
    <div class="card">
      <div class="card-title">&#x1F4BE; Checkpoint Performance</div>
      <div style="margin-bottom:16px">
        <span class="cp-stat"><div class="val">{result.checkpoint_stats.count}</div><div class="lbl">Total</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_stats.avg_duration_ms / 1000:.1f}s</div><div class="lbl">Avg Duration</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_stats.max_duration_ms / 1000:.1f}s</div><div class="lbl">Max Duration</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_wal_added}/{result.checkpoint_wal_removed}/{result.checkpoint_wal_recycled}</div><div class="lbl">WAL add/rm/rec</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_distance_avg / 1024:.0f} MB</div><div class="lbl">Avg Distance</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_stats.buffers_checkpoint_avg:,.0f}</div><div class="lbl">Avg Buffers Written</div></span>
        <span class="cp-stat"><div class="val">{result.checkpoint_stats.warning_count}</div><div class="lbl">Frequency Warnings</div></span>
      </div>
      <div class="chart-container" style="height:220px"><canvas id="cpDurChart"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title">Per-Checkpoint Event Detail</div>
      <p style="color:var(--text-muted);font-size:12px;margin-bottom:8px">Red = duration &gt;300s &#x2022; Orange = duration &gt;60s &#x2022; newest first</p>
      <table class="data-table" id="cp-table">
        <thead><tr>
          <th onclick="sortTable('cp-table',0)">Timestamp</th>
          <th>Type</th>
          <th onclick="sortTable('cp-table',2)">Total Duration</th>
          <th onclick="sortTable('cp-table',3)">Write Time</th>
          <th>Sync Time</th>
          <th onclick="sortTable('cp-table',5)">Buffers Written</th>
          <th>% shared_buffers</th>
          <th>WAL +add/-rm/rec</th>
          <th onclick="sortTable('cp-table',8)">Distance</th>
          <th>Estimate</th>
        </tr></thead>
        <tbody>{"".join(cp_event_rows) if cp_event_rows else "<tr><td colspan='10' style='text-align:center;color:var(--text-muted);padding:24px'>No checkpoint complete events found</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- AUTOVACUUM -->
  <div id="tab-autovacuum" class="tab-pane">
    <div class="card">
      <div class="card-title">&#x1F9F9; Autovacuum / Autoanalyze Summary by Table</div>
      <input class="search-bar" id="av-search" type="text" placeholder="Search tables..." oninput="filterTable('av-table','av-search')">
      <table class="data-table" id="av-table">
        <thead><tr>
          <th onclick="sortTable('av-table',0)">Table</th>
          <th>Kind</th>
          <th onclick="sortTable('av-table',2)">Runs</th>
          <th onclick="sortTable('av-table',3)">Avg Duration</th>
          <th onclick="sortTable('av-table',4)">Max Duration</th>
          <th onclick="sortTable('av-table',5)">Total Tuples Removed</th>
          <th onclick="sortTable('av-table',6)">Total Pages Removed</th>
          <th onclick="sortTable('av-table',7)">Total Buf Hits</th>
          <th onclick="sortTable('av-table',8)">Total Buf Misses</th>
          <th onclick="sortTable('av-table',9)">Total WAL</th>
          <th onclick="sortTable('av-table',10)">Total CPU</th>
        </tr></thead>
        <tbody>{"".join(av_rows) if av_rows else "<tr><td colspan='11' style='text-align:center;color:var(--text-muted);padding:24px'>No autovacuum events detected</td></tr>"}</tbody>
      </table>
    </div>
    <div class="card" style="margin-top:20px">
      <div class="card-title">&#x1F4CB; Individual Autovacuum / Autoanalyze Runs (sorted by duration)</div>
      <input class="search-bar" id="avd-search" type="text" placeholder="Search tables..." oninput="filterTable('avd-table','avd-search')">
      <table class="data-table" id="avd-table">
        <thead><tr>
          <th onclick="sortTable('avd-table',0)">Timestamp</th>
          <th onclick="sortTable('avd-table',1)">Table</th>
          <th>Kind</th>
          <th onclick="sortTable('avd-table',3)">Duration</th>
          <th>Tuples Removed</th>
          <th>Pages Removed</th>
          <th>Dead Tuples Before</th>
          <th>Buf Hits</th>
          <th>Buf Misses</th>
          <th>WAL</th>
          <th>CPU</th>
          <th>Index Scans</th>
        </tr></thead>
        <tbody>{"".join(av_detail_rows) if av_detail_rows else "<tr><td colspan='12' style='text-align:center;color:var(--text-muted);padding:24px'>No autovacuum run details available</td></tr>"}</tbody>
      </table>
    </div>
    {"<div class='card'><div class='card-title'>&#x1F4C2; Temporary Files (work_mem candidates)</div><table class='data-table'><thead><tr><th>Size</th><th>Database</th><th>User</th><th>Time</th><th>Query</th></tr></thead><tbody>" + "".join(tf_rows) + "</tbody></table></div>" if tf_rows else ""}
  </div>

  <!-- SESSIONS TAB -->
  <div id="tab-sessions" class="tab-pane">
    <div class="stats-strip">
      <div class="mini-stat"><div class="val">{ss.total_sessions if ss else 0:,}</div><div class="lbl">Total Sessions</div></div>
      <div class="mini-stat"><div class="val">{ss.peak_concurrent if ss else 0}</div><div class="lbl">Peak Concurrent</div></div>
      <div class="mini-stat"><div class="val">{f"{ss.avg_session_duration_ms / 1000:.1f}s" if ss and ss.avg_session_duration_ms else "—"}</div><div class="lbl">Avg Duration</div></div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">📈 Concurrent Sessions Over Time</div>
        <div class="chart-container"><canvas id="sessTimeChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">⏱ Session Duration Histogram</div>
        <div class="chart-container"><canvas id="sessHistChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">🗄 Sessions by Database</div>
        <table class="data-table">
          <thead><tr><th>Database</th><th>Sessions</th></tr></thead>
          <tbody>{sess_db_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">👤 Sessions by User</div>
        <table class="data-table">
          <thead><tr><th>User</th><th>Sessions</th></tr></thead>
          <tbody>{sess_user_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">🌐 Sessions by Host</div>
        <table class="data-table">
          <thead><tr><th>Host</th><th>Sessions</th></tr></thead>
          <tbody>{sess_host_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">📱 Sessions by Application</div>
        <table class="data-table">
          <thead><tr><th>Application</th><th>Sessions</th></tr></thead>
          <tbody>{sess_app_rows or "<tr><td colspan='2' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- QUERY TYPES TAB -->
  <div id="tab-query-types" class="tab-pane">
    <div class="stats-strip">
      <div class="mini-stat"><div class="val">{qt.select_count:,}</div><div class="lbl">SELECT</div></div>
      <div class="mini-stat"><div class="val">{qt.insert_count:,}</div><div class="lbl">INSERT</div></div>
      <div class="mini-stat"><div class="val">{qt.update_count:,}</div><div class="lbl">UPDATE</div></div>
      <div class="mini-stat"><div class="val">{qt.delete_count:,}</div><div class="lbl">DELETE</div></div>
      <div class="mini-stat {'warn' if qt.cancelled_count > 20 else ''}"><div class="val">{qt.cancelled_count:,}</div><div class="lbl">Cancelled</div></div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">🍩 Query Type Distribution</div>
        <div class="chart-container"><canvas id="qtPieChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">📈 DML Over Time</div>
        <div class="chart-container"><canvas id="dmlTimeChart"></canvas></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">🗄 Query Types by Database</div>
      <table class="data-table">
        <thead><tr><th>Database</th><th>Total</th><th>SELECT</th><th>INSERT</th><th>UPDATE</th><th>DELETE</th></tr></thead>
        <tbody>{qt_db_rows or "<tr><td colspan='6' style='text-align:center;color:var(--text-muted)'>No data</td></tr>"}</tbody>
      </table>
    </div>
    {"<div class='card'><div class='card-title' style='color:var(--orange)'>⚠ Cancelled Queries</div><table class='data-table'><thead><tr><th>Time</th><th>Query</th><th>Database</th><th>User</th></tr></thead><tbody>" + (cancelled_rows or "<tr><td colspan='4' style='text-align:center;color:var(--text-muted)'>No cancelled queries</td></tr>") + "</tbody></table></div>"}
  </div>

  <!-- PREPARE/EXECUTE TAB -->
  <div id="tab-prepare-execute" class="tab-pane">
    <div class="stats-strip">
      <div class="mini-stat"><div class="val">{pb.total_parse_ms:,.0f}ms</div><div class="lbl">Total Parse</div></div>
      <div class="mini-stat"><div class="val">{pb.total_bind_ms:,.0f}ms</div><div class="lbl">Total Bind</div></div>
      <div class="mini-stat"><div class="val">{pb.total_execute_ms:,.0f}ms</div><div class="lbl">Total Execute</div></div>
      <div class="mini-stat {'warn' if pb.total_execute_ms > 0 and pb.total_parse_ms / max(pb.total_execute_ms, 1) > 0.2 else ''}">
        <div class="val">{f"{pb.total_parse_ms / max(pb.total_execute_ms, 1) * 100:.1f}%" if pb.total_execute_ms > 0 else "—"}</div>
        <div class="lbl">Parse/Execute %</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">📊 Phase Time Breakdown</div>
        <div class="chart-container"><canvas id="pbeBarChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">📋 Phase Counts</div>
        <table class="data-table">
          <tbody>
            <tr><td>Parse count</td><td><strong>{pb.parse_count:,}</strong></td></tr>
            <tr><td>Bind count</td><td><strong>{pb.bind_count:,}</strong></td></tr>
            <tr><td>Execute count</td><td><strong>{pb.execute_count:,}</strong></td></tr>
          </tbody>
        </table>
      </div>
    </div>
    {"<div class='card'><div class='card-title'>🐢 Top Parse-Heavy Queries</div><table class='data-table'><thead><tr><th>Query</th><th>Total Parse (ms)</th><th>Count</th></tr></thead><tbody>" + "".join(f"<tr><td><code>{_e(str(q.get('query',''))[:100])}</code></td><td>{q.get('total_ms',0):.0f}</td><td>{q.get('count',0)}</td></tr>" for q in pb.top_parse_queries[:10]) + "</tbody></table></div>" if pb.top_parse_queries else ""}
    {"<div class='card'><div class='card-title'>🔗 Top Bind-Heavy Queries</div><table class='data-table'><thead><tr><th>Query</th><th>Total Bind (ms)</th><th>Count</th></tr></thead><tbody>" + "".join(f"<tr><td><code>{_e(str(q.get('query',''))[:100])}</code></td><td>{q.get('total_ms',0):.0f}</td><td>{q.get('count',0)}</td></tr>" for q in pb.top_bind_queries[:10]) + "</tbody></table></div>" if pb.top_bind_queries else ""}
  </div>

  <!-- AUTO-EXPLAIN TAB -->
  <div id="tab-auto-explain" class="tab-pane">
    <div class="card">
      <div class="card-title">🔍 Captured EXPLAIN Plans ({len(auto_plans)} total)</div>
      <table class="data-table">
        <thead><tr>
          <th>Time</th>
          <th>Duration</th>
          <th>Database</th>
          <th>Query</th>
          <th>Plan</th>
          <th>AI Analysis</th>
        </tr></thead>
        <tbody>{explain_rows or "<tr><td colspan='6' style='text-align:center;color:var(--text-muted)'>No auto_explain plans captured</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- PGBOUNCER TAB (conditional) -->
  {'<div id="tab-pgbouncer" class="tab-pane">' + pgbouncer_html + '</div>' if show_pgbouncer_tab else ''}

  <!-- RCA -->
  <div id="tab-rca" class="tab-pane">
    <div class="card">
      <div class="card-title">🔍 Root Cause Analysis Findings</div>
      {"".join(rca_cards) if rca_cards else "<p style='color:var(--text-muted)'>No significant issues found by rule-based analysis.</p>"}
    </div>
  </div>

  <!-- LLM ANALYSIS -->
  {"<div id='tab-llm' class='tab-pane'><div class='card'><div class='card-title'>🤖 LLM-Powered Analysis</div>" + llm_section + "</div></div>" if result.llm_analysis else ""}

  <!-- RECOMMENDATIONS -->
  <div id="tab-recommendations" class="tab-pane">
    <div class="card">
      <div class="card-title">✅ Recommendations from RCA</div>
      <ol>{"".join(f'<li class="rec-item">{_e(r)}</li>' for r in result.recommendations[:20])}</ol>
    </div>
    {ai_index_html}
    {ai_config_html}
  </div>

</div><!-- /content -->

<script>
// Tab navigation
function showTab(name) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const pane = document.getElementById('tab-' + name);
  if (pane) pane.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => {{
    if (b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + name + "'")) {{
      b.classList.add('active');
    }}
  }});
}}

// Sortable tables
let sortState = {{}};
function sortTable(tableId, col) {{
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr:not(.ai-row)'));
  const key = tableId + '-' + col;
  const asc = sortState[key] !== true;
  sortState[key] = asc;
  rows.sort((a, b) => {{
    const av = a.cells[col]?.textContent?.trim() || '';
    const bv = b.cells[col]?.textContent?.trim() || '';
    const an = parseFloat(av.replace(/[^0-9.-]/g, ''));
    const bn = parseFloat(bv.replace(/[^0-9.-]/g, ''));
    if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
  table.querySelectorAll('th').forEach((th, i) => {{
    th.classList.remove('sort-asc', 'sort-desc');
    if (i === col) th.classList.add(asc ? 'sort-asc' : 'sort-desc');
  }});
}}

// Live search / filter for tables
function filterTable(tableId, searchId) {{
  const term = document.getElementById(searchId).value.toLowerCase();
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.forEach(function(row) {{
    // Always show detail rows that are already expanded
    if (row.classList.contains('sq-detail-row')) {{ return; }}
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(term) ? '' : 'none';
  }});
}}

// Chart.js defaults
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
const CHART_COLORS = ['#1f6feb','#f85149','#e3b341','#3fb950','#58a6ff','#8b949e','#ff7b72','#ffa657','#79c0ff','#56d364'];

// Slow query chart
const sqCtx = document.getElementById('slowQueryChart');
if (sqCtx) {{
  new Chart(sqCtx, {{
    type: 'bar',
    data: {{
      labels: {sq_labels},
      datasets: [
        {{ label: 'Avg (ms)', data: {sq_avg_data}, backgroundColor: 'rgba(31,111,235,0.7)', borderRadius: 4 }},
        {{ label: 'Max (ms)', data: {sq_max_data}, backgroundColor: 'rgba(248,81,73,0.5)', borderRadius: 4 }}
      ]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'top' }} }}, scales: {{ y: {{ beginAtZero: true, title: {{ display: true, text: 'Duration (ms)' }} }} }} }}
  }});
}}

// Connections by hour (overview)
const connCtx = document.getElementById('connChart');
if (connCtx) {{
  new Chart(connCtx, {{
    type: 'line',
    data: {{ labels: {conn_labels}, datasets: [{{ label: 'Connections', data: {conn_counts}, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.4, pointRadius: 3 }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Errors by hour
const errCtx = document.getElementById('errChart');
if (errCtx) {{
  new Chart(errCtx, {{
    type: 'bar',
    data: {{ labels: {conn_labels}, datasets: [{{ label: 'Errors', data: {err_counts}, backgroundColor: 'rgba(248,81,73,0.7)', borderRadius: 4 }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Error category pie
const pieCtx = document.getElementById('errPieChart');
if (pieCtx && {pie_labels} && {pie_labels}.length > 0) {{
  new Chart(pieCtx, {{
    type: 'doughnut',
    data: {{
      labels: {pie_labels},
      datasets: [{{ data: {pie_data}, backgroundColor: CHART_COLORS, borderWidth: 0 }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right' }} }} }}
  }});
}}

// Connections by hour (connections tab)
const connHourCtx = document.getElementById('connHourChart');
if (connHourCtx) {{
  new Chart(connHourCtx, {{
    type: 'bar',
    data: {{ labels: {conn_labels}, datasets: [{{ label: 'Connections', data: {conn_counts}, backgroundColor: 'rgba(74,141,184,0.7)', borderRadius: 4 }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Session concurrent over time
const sessTimeCtx = document.getElementById('sessTimeChart');
if (sessTimeCtx && {sess_time_labels} && {sess_time_labels}.length > 0) {{
  new Chart(sessTimeCtx, {{
    type: 'line',
    data: {{ labels: {sess_time_labels}, datasets: [{{ label: 'Concurrent Sessions', data: {sess_time_data}, borderColor: '#388bfd', backgroundColor: 'rgba(56,139,253,0.1)', fill: true, tension: 0.4, pointRadius: 2 }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Session duration histogram
const sessHistCtx = document.getElementById('sessHistChart');
if (sessHistCtx) {{
  new Chart(sessHistCtx, {{
    type: 'bar',
    data: {{
      labels: {hist_labels},
      datasets: [{{ label: 'Sessions', data: {hist_data}, backgroundColor: 'rgba(57,211,83,0.7)', borderRadius: 4 }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Query type pie
const qtPieCtx = document.getElementById('qtPieChart');
if (qtPieCtx) {{
  new Chart(qtPieCtx, {{
    type: 'doughnut',
    data: {{
      labels: {qt_labels},
      datasets: [{{ data: {qt_data}, backgroundColor: CHART_COLORS, borderWidth: 0 }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right' }} }} }}
  }});
}}

// DML over time
const dmlTimeCtx = document.getElementById('dmlTimeChart');
if (dmlTimeCtx && {dml_time_labels} && {dml_time_labels}.length > 0) {{
  new Chart(dmlTimeCtx, {{
    type: 'line',
    data: {{ labels: {dml_time_labels}, datasets: [{{ label: 'DML Queries', data: {dml_time_data}, borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.1)', fill: true, tension: 0.4, pointRadius: 2 }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
  }});
}}

// Prepare/Bind/Execute bar
const pbeBarCtx = document.getElementById('pbeBarChart');
if (pbeBarCtx) {{
  new Chart(pbeBarCtx, {{
    type: 'bar',
    data: {{
      labels: {pbe_labels},
      datasets: [{{ label: 'Total Time (ms)', data: {pbe_data}, backgroundColor: ['rgba(227,179,65,0.7)','rgba(88,166,255,0.7)','rgba(63,185,80,0.7)'], borderRadius: 4 }}]
    }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true, title: {{ display: true, text: 'ms' }} }} }} }}
  }});
}}

// Checkpoint duration chart
const cpDurCtx = document.getElementById('cpDurChart');
if (cpDurCtx && {cp_chart_labels} && {cp_chart_labels}.length > 0) {{
  new Chart(cpDurCtx, {{
    type: 'bar',
    data: {{
      labels: {cp_chart_labels},
      datasets: [
        {{ label: 'Duration (s)', data: {cp_chart_dur}, backgroundColor: 'rgba(248,81,73,0.7)', yAxisID: 'y', borderRadius: 3 }},
        {{ label: 'Buffers Written', data: {cp_chart_buf}, backgroundColor: 'rgba(88,166,255,0.5)', yAxisID: 'y2', type: 'line', borderColor: '#58a6ff', tension: 0.3, pointRadius: 3 }}
      ]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{ legend: {{ display: true, position: 'top' }} }},
      scales: {{
        y: {{ beginAtZero: true, title: {{ display: true, text: 'Duration (s)' }}, position: 'left' }},
        y2: {{ beginAtZero: true, title: {{ display: true, text: 'Buffers Written' }}, position: 'right', grid: {{ drawOnChartArea: false }} }}
      }}
    }}
  }});
}}
</script>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def generate_report(
    result: AnalysisResult,
    format: str = "terminal",
    output_path: Optional[str] = None,
) -> Optional[str]:
    """Generate a report in the specified format.

    - format='terminal': print to stdout, return None
    - Other formats: return string, optionally write to output_path
    """
    format = format.lower()

    if format == "terminal":
        render_terminal(result)
        return None

    if format == "json":
        content = render_json(result)
    elif format == "markdown":
        content = render_markdown(result)
    elif format == "html":
        content = render_html(result)
    else:
        raise ValueError(f"Unknown report format '{format}'. Choose: terminal, json, markdown, html")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

    return content
