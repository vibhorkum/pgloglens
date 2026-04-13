"""LLM integration for pgloglens v2.

Provides a unified async interface to multiple LLM providers:
  - OpenAI (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
  - Anthropic (Claude Opus/Sonnet)
  - Ollama (local models)
  - Google (Gemini Pro / 1.5 Pro)

v2 additions:
  - stream_analyze() on every provider for token-by-token terminal streaming
  - New specialized prompts: SLOW_QUERY_ANALYSIS_PROMPT, EXPLAIN_PLAN_PROMPT,
    CONFIG_GENERATION_PROMPT, INDEX_RECOMMENDATION_PROMPT
  - Improved context builder: sessions, query type distribution, prepare/bind/execute,
    PgBouncer stats, auto_explain summaries, cancelled queries, source platform
  - Improved token estimation (word-count based)
"""

from __future__ import annotations

import asyncio
import json
import os
from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Dict, List, Optional

from .models import AnalysisResult, RCAFinding, Severity


# ---------------------------------------------------------------------------
# Token estimation (improved: word-count based)
# ---------------------------------------------------------------------------

def _rough_token_count(text: str) -> int:
    """Estimate token count using word count (words * 1.3 avg tokens/word)."""
    words = len(text.split())
    return int(words * 1.3)


def _truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to approximately max_tokens tokens."""
    # Estimate: 1 token ≈ 0.77 words ≈ 4 chars
    # We use char-based truncation as a safe proxy
    max_chars = int(max_tokens * 4)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


# ---------------------------------------------------------------------------
# Specialized prompts (v2)
# ---------------------------------------------------------------------------

SLOW_QUERY_ANALYSIS_PROMPT = """
You are a PostgreSQL performance expert. Analyze this slow query and provide:

1. **What it does**: Brief description (1-2 sentences)
2. **Why it's slow**: Specific diagnosis  
3. **Index recommendation**: Exact CREATE INDEX statement(s) if applicable
4. **Query rewrite**: Optimized version if applicable
5. **Config change**: Relevant postgresql.conf parameter if applicable

Query (normalized):
{query}

Statistics:
- Executions: {count}
- Average duration: {avg_ms}ms
- P95 duration: {p95_ms}ms
- Total time consumed: {total_ms}ms

Be specific. Include exact SQL. No generic advice.
"""

EXPLAIN_PLAN_PROMPT = """
You are a PostgreSQL query optimizer. Analyze this EXPLAIN plan and provide:

1. **Bottleneck**: The single most expensive operation and why
2. **Sequential scans**: Any Seq Scans that should be Index Scans
3. **Index recommendation**: Exact CREATE INDEX statements
4. **Join strategy**: Any suboptimal join methods
5. **Estimated improvement**: Expected speedup after fixes

Query: {query}
Duration: {duration_ms}ms

Plan:
{plan_text}

Be concise and specific. Include exact DDL statements.
"""

CONFIG_GENERATION_PROMPT = """
You are a PostgreSQL DBA expert. Based on this analysis, generate an optimized postgresql.conf section.

System context:
{analysis_summary}

For each parameter, provide:
- The exact recommended value
- A one-line comment explaining why
- The current default for comparison

Focus ONLY on parameters where the analysis shows a clear need to change from default.
Format as valid postgresql.conf with comments.
"""

INDEX_RECOMMENDATION_PROMPT = """
Analyze these slow PostgreSQL queries and generate CREATE INDEX statements.
For each recommendation:
1. Exact CREATE INDEX CONCURRENTLY statement
2. Which query it helps
3. Estimated speedup (rough)
4. Any caveats (index size, write overhead)

Queries to analyze:
{queries}

Database context:
{context}
"""

SYSTEM_PROMPT = """You are a senior PostgreSQL DBA and performance engineer with 20+ years of experience. 
You analyze PostgreSQL log data and provide expert diagnosis and actionable recommendations.

When presented with log analysis data, provide:
1. Executive Summary (2-3 sentences): What is the overall health of this PostgreSQL instance?
2. Top 5 Actionable Recommendations: Specific PostgreSQL configuration changes with exact values, 
   prioritized by impact. Include the exact ALTER SYSTEM SET commands where applicable.
3. Query Optimization Suggestions: For the top slow queries, suggest index creation or query rewrites.
4. Risk Assessment: What is the risk of a production outage based on current patterns?
5. Monitoring Recommendations: What metrics/alerts should be set up?

Be specific, quantitative, and pragmatic. Focus on actionable insights over generic advice."""

USER_PROMPT_TEMPLATE = """Please analyze this PostgreSQL log data and provide expert recommendations:

{context}

Based on this data, provide your expert analysis. Focus on:
- Immediate action items (within 24 hours)
- Medium-term optimizations (within 1 week)  
- PostgreSQL configuration changes with specific values
- Specific index recommendations for slow queries
- Risk assessment for production stability
"""


# ---------------------------------------------------------------------------
# Context builder (v2 extended)
# ---------------------------------------------------------------------------

def build_analysis_context(result: AnalysisResult, max_tokens: int = 7500) -> str:
    """Build a token-efficient analysis context string from an AnalysisResult.

    v2: includes session stats, query type distribution, prepare/bind/execute,
    PgBouncer stats, auto_explain summaries, cancelled query count, source platform.
    """
    sections: List[str] = []

    # --- Summary ---
    duration_sec = 0.0
    if result.time_range_start and result.time_range_end:
        duration_sec = (result.time_range_end - result.time_range_start).total_seconds()

    platform = getattr(result, "source_platform", "postgresql")

    sections.append("## PostgreSQL Log Analysis Summary\n")
    sections.append(
        f"- Log files: {', '.join(result.log_file_paths)}\n"
        f"- Source platform: {platform}\n"
        f"- Time range: {result.time_range_start} → {result.time_range_end}\n"
        f"- Duration analyzed: {duration_sec / 3600:.1f} hours\n"
        f"- Total log entries: {result.total_entries:,}\n"
        f"- Slow queries (unique patterns): {len(result.slow_queries)}\n"
        f"- Error patterns: {len(result.error_patterns)}\n"
        f"- Lock events: {len(result.lock_events)}\n"
        f"- Deadlocks: {result.deadlock_count}\n"
        f"- Auth failures: {result.connection_stats.auth_failures}\n"
        f"- FATAL/PANIC events: {len(result.panic_fatal_events)}\n"
        f"- Peak concurrent connections: {result.connection_stats.peak_concurrent}\n"
        f"- Error rate: {result.error_rate_per_minute:.1f}/min\n"
        f"- Cancelled queries: {len(getattr(result, 'cancelled_queries', []))}\n"
    )

    # --- Session stats ---
    ss = result.session_stats
    if ss and ss.total_sessions > 0:
        sections.append("\n## Session Statistics\n")
        idle_pct = (
            (ss.total_idle_time_ms / ss.total_session_duration_ms * 100)
            if ss.total_session_duration_ms > 0 else 0
        )
        sections.append(
            f"- Total sessions: {ss.total_sessions:,}\n"
            f"- Peak concurrent: {ss.peak_concurrent}\n"
            f"- Avg session duration: {ss.avg_session_duration_ms / 1000:.1f}s\n"
            f"- Idle time ratio: {idle_pct:.1f}%\n"
        )
        top_dbs = sorted(ss.sessions_by_database.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_dbs:
            sections.append(f"- Top DBs by sessions: {', '.join(f'{d}({c})' for d,c in top_dbs)}\n")

    # --- Query type distribution ---
    qt = result.query_type_stats
    total_qt = (
        qt.select_count + qt.insert_count + qt.update_count
        + qt.delete_count + qt.copy_count + qt.ddl_count + qt.other_count
    )
    if total_qt > 0:
        sections.append("\n## Query Type Distribution\n")
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
                sections.append(f"- {qtype}: {count:,} ({pct:.1f}%)\n")
        sections.append(f"- Cancelled: {qt.cancelled_count:,}\n")

    # --- Prepare/bind/execute breakdown ---
    pb = result.prepare_bind_execute
    if pb.total_execute_ms > 0:
        sections.append("\n## Prepare/Bind/Execute Phase Breakdown\n")
        parse_pct = pb.total_parse_ms / pb.total_execute_ms * 100 if pb.total_execute_ms > 0 else 0
        sections.append(
            f"- Parse: {pb.total_parse_ms:,.0f}ms ({parse_pct:.1f}% of execute)\n"
            f"- Bind: {pb.total_bind_ms:,.0f}ms\n"
            f"- Execute: {pb.total_execute_ms:,.0f}ms\n"
            f"- Parse count: {pb.parse_count:,}\n"
            f"- Execute count: {pb.execute_count:,}\n"
        )
        if pb.top_parse_queries:
            sections.append("- Top parse-heavy queries:\n")
            for q in pb.top_parse_queries[:3]:
                sections.append(
                    f"  • {q.get('query', '')[:80]} — {q.get('total_ms', 0):.0f}ms total parse\n"
                )

    # --- Top slow queries ---
    if result.slow_queries:
        sections.append("\n## Top 10 Slow Query Patterns\n")
        for i, sq in enumerate(result.slow_queries[:10], 1):
            is_reg = " [REGRESSION]" if getattr(sq, "is_regression", False) else ""
            sections.append(
                f"{i}. Count={sq.count} | Avg={sq.avg_duration_ms:.0f}ms | "
                f"Max={sq.max_duration_ms:.0f}ms | P95={sq.p95_duration_ms:.0f}ms | "
                f"P99={sq.p99_duration_ms:.0f}ms{is_reg}\n"
                f"   Query: {sq.normalized_query[:300]}\n"
            )

    # --- Top error patterns ---
    if result.error_patterns:
        sections.append("\n## Top 10 Error Patterns\n")
        for i, ep in enumerate(result.error_patterns[:10], 1):
            sections.append(
                f"{i}. [{ep.error_code or 'N/A'}] Count={ep.count} Category={ep.category}\n"
                f"   Pattern: {ep.message_pattern[:200]}\n"
            )

    # --- RCA findings ---
    if result.rca_findings:
        sections.append("\n## Rule-Based RCA Findings\n")
        for f in result.rca_findings:
            sections.append(
                f"- [{f.severity.value}] {f.title}\n"
                f"  {f.description[:300]}\n"
            )

    # --- Checkpoint stats ---
    cp = result.checkpoint_stats
    if cp.count > 0:
        wal_added = getattr(result, "checkpoint_wal_added", 0)
        wal_removed = getattr(result, "checkpoint_wal_removed", 0)
        wal_recycled = getattr(result, "checkpoint_wal_recycled", 0)
        sections.append(
            f"\n## Checkpoint Statistics\n"
            f"- Count: {cp.count}\n"
            f"- Avg duration: {cp.avg_duration_ms / 1000:.1f}s\n"
            f"- Max duration: {cp.max_duration_ms / 1000:.1f}s\n"
            f"- Warnings: {cp.warning_count}\n"
            f"- WAL added/removed/recycled: {wal_added}/{wal_removed}/{wal_recycled}\n"
        )

    # --- Autovacuum ---
    if result.autovacuum_stats:
        sections.append(
            f"\n## Autovacuum Statistics\n"
            f"- Total runs: {len(result.autovacuum_stats)}\n"
        )
        from .analyzer import analyze_autovacuum_frequency
        freq = analyze_autovacuum_frequency(result.autovacuum_stats)[:5]
        for table, count, avg in freq:
            sections.append(f"  - {table}: {count} runs, avg {avg / 1000:.1f}s\n")

    # --- Temp files ---
    if result.temp_files:
        total_mb = sum(t.size_mb for t in result.temp_files)
        max_mb = max(t.size_mb for t in result.temp_files)
        sections.append(
            f"\n## Temp File Statistics\n"
            f"- Total temp file events: {len(result.temp_files)}\n"
            f"- Total size: {total_mb:.0f}MB\n"
            f"- Largest file: {max_mb:.0f}MB\n"
        )

    # --- Lock events ---
    if result.lock_events:
        sections.append(
            f"\n## Lock Events\n"
            f"- Total lock waits: {len(result.lock_events)}\n"
            f"- Deadlocks: {result.deadlock_count}\n"
        )

    # --- PgBouncer stats ---
    pgb = result.pgbouncer_stats
    if pgb is not None:
        pool_error_count = len(pgb.pool_errors)
        sections.append(
            f"\n## PgBouncer Statistics\n"
            f"- Total requests: {pgb.total_requests:,}\n"
            f"- Avg query time: {pgb.avg_query_ms:.1f}ms\n"
            f"- Max query time: {pgb.max_query_ms:.1f}ms\n"
            f"- Pool errors: {pool_error_count}\n"
        )

    # --- Top 3 auto_explain plan summaries ---
    auto_plans = getattr(result, "auto_explain_plans", [])
    if auto_plans:
        sections.append(f"\n## Auto-Explain Plans (top 3 by duration)\n")
        top_plans = sorted(auto_plans, key=lambda p: p.duration_ms, reverse=True)[:3]
        for i, plan in enumerate(top_plans, 1):
            sections.append(
                f"{i}. Duration={plan.duration_ms:.0f}ms | "
                f"Query: {plan.query[:200]}\n"
                f"   Plan preview: {plan.plan_text[:300]}\n"
            )

    # Assemble and check token budget
    full_context = "".join(sections)
    current_tokens = _rough_token_count(full_context)

    if current_tokens > max_tokens:
        full_context = _truncate_to_tokens(full_context, max_tokens)

    return full_context


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key

    @abstractmethod
    async def analyze(self, context: str) -> str:
        """Send context to LLM and return analysis text."""
        ...

    @abstractmethod
    async def stream_analyze(self, context: str) -> AsyncGenerator[str, None]:
        """Stream analysis tokens as they arrive."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...


# ---------------------------------------------------------------------------
# OpenAI provider
# ---------------------------------------------------------------------------

class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(model or self.DEFAULT_MODEL, api_key)

    @property
    def provider_name(self) -> str:
        return "openai"

    async def analyze(self, context: str) -> str:
        try:
            import openai
        except ImportError:
            return "Error: openai package not installed. Run: pip install openai"

        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            return "Error: OPENAI_API_KEY not set. Set the environment variable or use --llm-api-key."

        client = openai.AsyncOpenAI(api_key=key)
        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": USER_PROMPT_TEMPLATE.format(context=context)},
                ],
                max_tokens=2000,
                temperature=0.3,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            return f"Error calling OpenAI API: {exc}"

    async def stream_analyze(self, context: str) -> AsyncGenerator[str, None]:
        """Stream analysis tokens from OpenAI."""
        try:
            import openai
        except ImportError:
            yield "Error: openai package not installed. Run: pip install openai"
            return

        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            yield "Error: OPENAI_API_KEY not set."
            return

        client = openai.AsyncOpenAI(api_key=key)
        try:
            stream = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": USER_PROMPT_TEMPLATE.format(context=context)},
                ],
                max_tokens=2000,
                temperature=0.3,
                stream=True,
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield delta.content
        except Exception as exc:
            yield f"\nError streaming from OpenAI: {exc}"


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------

class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    DEFAULT_MODEL = "claude-opus-4-5"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(model or self.DEFAULT_MODEL, api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def analyze(self, context: str) -> str:
        try:
            import anthropic
        except ImportError:
            return "Error: anthropic package not installed. Run: pip install anthropic"

        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return "Error: ANTHROPIC_API_KEY not set."

        client = anthropic.AsyncAnthropic(api_key=key)
        try:
            message = await client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": USER_PROMPT_TEMPLATE.format(context=context)},
                ],
            )
            return message.content[0].text if message.content else ""
        except Exception as exc:
            return f"Error calling Anthropic API: {exc}"

    async def stream_analyze(self, context: str) -> AsyncGenerator[str, None]:
        """Stream analysis tokens from Anthropic."""
        try:
            import anthropic
        except ImportError:
            yield "Error: anthropic package not installed. Run: pip install anthropic"
            return

        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            yield "Error: ANTHROPIC_API_KEY not set."
            return

        client = anthropic.AsyncAnthropic(api_key=key)
        try:
            async with client.messages.stream(
                model=self.model,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": USER_PROMPT_TEMPLATE.format(context=context)},
                ],
            ) as stream:
                async for text in stream.text_stream:
                    yield text
        except Exception as exc:
            yield f"\nError streaming from Anthropic: {exc}"


# ---------------------------------------------------------------------------
# Ollama provider (local)
# ---------------------------------------------------------------------------

class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""

    DEFAULT_MODEL = "llama3"

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:11434",
    ):
        super().__init__(model or self.DEFAULT_MODEL, api_key)
        self.base_url = base_url

    @property
    def provider_name(self) -> str:
        return "ollama"

    async def analyze(self, context: str) -> str:
        import json as _json
        import urllib.request
        import urllib.error

        prompt = SYSTEM_PROMPT + "\n\n" + USER_PROMPT_TEMPLATE.format(context=context)
        payload = _json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 2000},
        }).encode()

        loop = asyncio.get_event_loop()
        try:
            def _call() -> str:
                req = urllib.request.Request(
                    f"{self.base_url}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=300) as resp:
                    data = _json.loads(resp.read().decode())
                    return data.get("response", "")

            return await loop.run_in_executor(None, _call)
        except Exception as exc:
            return f"Error calling Ollama API at {self.base_url}: {exc}"

    async def stream_analyze(self, context: str) -> AsyncGenerator[str, None]:
        """Stream tokens from Ollama's streaming API."""
        import json as _json
        import urllib.request

        prompt = SYSTEM_PROMPT + "\n\n" + USER_PROMPT_TEMPLATE.format(context=context)
        payload = _json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": 0.3, "num_predict": 2000},
        }).encode()

        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def _stream_thread() -> None:
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=300) as resp:
                    for raw_line in resp:
                        try:
                            obj = _json.loads(raw_line.decode())
                            token = obj.get("response", "")
                            if token:
                                loop.call_soon_threadsafe(queue.put_nowait, token)
                            if obj.get("done", False):
                                break
                        except Exception:
                            continue
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, f"\nError: {exc}")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

        import threading
        thread = threading.Thread(target=_stream_thread, daemon=True)
        thread.start()

        while True:
            token = await queue.get()
            if token is None:
                break
            yield token


# ---------------------------------------------------------------------------
# Google Gemini provider
# ---------------------------------------------------------------------------

class GoogleProvider(LLMProvider):
    """Google Gemini provider."""

    DEFAULT_MODEL = "gemini-1.5-pro"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(model or self.DEFAULT_MODEL, api_key)

    @property
    def provider_name(self) -> str:
        return "google"

    async def analyze(self, context: str) -> str:
        key = self.api_key or os.environ.get("GOOGLE_API_KEY")
        if not key:
            return "Error: GOOGLE_API_KEY not set."

        prompt = USER_PROMPT_TEMPLATE.format(context=context)
        loop = asyncio.get_event_loop()

        # Try newer google-genai SDK first, fall back to google-generativeai
        try:
            import google.genai as genai  # type: ignore
            try:
                client = genai.Client(api_key=key)
                response = await loop.run_in_executor(
                    None,
                    lambda: client.models.generate_content(
                        model=self.model,
                        contents=SYSTEM_PROMPT + "\n\n" + prompt,
                        config={"max_output_tokens": 2000, "temperature": 0.3},
                    ),
                )
                return response.text or ""
            except Exception as exc:
                return f"Error calling Google Gemini API: {exc}"
        except ImportError:
            pass

        try:
            import google.generativeai as genai_legacy  # type: ignore
            try:
                genai_legacy.configure(api_key=key)
                model_obj = genai_legacy.GenerativeModel(
                    model_name=self.model,
                    system_instruction=SYSTEM_PROMPT,
                )
                response = await loop.run_in_executor(
                    None,
                    lambda: model_obj.generate_content(
                        prompt,
                        generation_config={"max_output_tokens": 2000, "temperature": 0.3},
                    ),
                )
                return response.text or ""
            except Exception as exc:
                return f"Error calling Google Gemini API: {exc}"
        except ImportError:
            return "Error: Google AI package not installed. Run: pip install 'pgloglens[google]'"

    async def stream_analyze(self, context: str) -> AsyncGenerator[str, None]:
        """Stream tokens from Google Gemini."""
        key = self.api_key or os.environ.get("GOOGLE_API_KEY")
        if not key:
            yield "Error: GOOGLE_API_KEY not set."
            return

        prompt = USER_PROMPT_TEMPLATE.format(context=context)
        loop = asyncio.get_event_loop()

        try:
            import google.generativeai as genai_legacy  # type: ignore
            genai_legacy.configure(api_key=key)
            model_obj = genai_legacy.GenerativeModel(
                model_name=self.model,
                system_instruction=SYSTEM_PROMPT,
            )

            queue: asyncio.Queue = asyncio.Queue()

            def _stream_thread() -> None:
                try:
                    response = model_obj.generate_content(
                        prompt,
                        generation_config={"max_output_tokens": 2000, "temperature": 0.3},
                        stream=True,
                    )
                    for chunk in response:
                        text = getattr(chunk, "text", None)
                        if text:
                            loop.call_soon_threadsafe(queue.put_nowait, text)
                except Exception as exc:
                    loop.call_soon_threadsafe(queue.put_nowait, f"\nError: {exc}")
                finally:
                    loop.call_soon_threadsafe(queue.put_nowait, None)

            import threading
            thread = threading.Thread(target=_stream_thread, daemon=True)
            thread.start()

            while True:
                token = await queue.get()
                if token is None:
                    break
                yield token

        except ImportError:
            yield "Error: Google AI package not installed. Run: pip install 'pgloglens[google]'"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS: Dict[str, type] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "google": GoogleProvider,
}


def get_provider(
    provider_name: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> LLMProvider:
    """Instantiate an LLM provider by name."""
    cls = _PROVIDERS.get(provider_name.lower())
    if cls is None:
        raise ValueError(
            f"Unknown LLM provider '{provider_name}'. "
            f"Available: {', '.join(_PROVIDERS.keys())}"
        )
    return cls(model=model, api_key=api_key, **kwargs)


async def run_llm_analysis(
    result: AnalysisResult,
    provider_name: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    max_context_tokens: int = 7500,
) -> str:
    """High-level helper: build context and call LLM, return analysis string."""
    provider = get_provider(provider_name, model=model, api_key=api_key)
    context = build_analysis_context(result, max_tokens=max_context_tokens)
    analysis = await provider.analyze(context)
    return analysis


async def stream_llm_analysis(
    result: AnalysisResult,
    provider_name: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    max_context_tokens: int = 7500,
) -> AsyncGenerator[str, None]:
    """High-level helper: build context and stream LLM tokens to caller."""
    provider = get_provider(provider_name, model=model, api_key=api_key)
    context = build_analysis_context(result, max_tokens=max_context_tokens)
    async for token in provider.stream_analyze(context):
        yield token
