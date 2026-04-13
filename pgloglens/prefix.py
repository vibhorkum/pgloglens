"""
pgloglens log_line_prefix engine.

Implements a complete parser/compiler for PostgreSQL's ``log_line_prefix``
setting — giving pgloglens the same ``--prefix`` capability as pgBadger.

Public API
----------
PrefixCompiler              Compile a prefix string and parse log-line headers.
detect_prefix_from_log      Auto-detect the prefix from sample lines.
infer_prefix_fields_heuristically
                            Heuristically detect which fields are present.
build_entry_from_prefix     Parse a full log line into (fields, level, message).
get_common_prefix           Return a named common prefix string.
prefix_to_description       Human-readable summary of a prefix string.
patch_parser                Monkey-patch parser.py's _STDERR_RE at runtime.
COMMON_PREFIXES             Dict of well-known prefix strings.
"""

from __future__ import annotations

import re
import sys
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Escape-sequence table
# ---------------------------------------------------------------------------
# Each entry: (field_name, regex_pattern, is_session_only)
# is_session_only=True  → the field is empty / absent in background processes
#                         and must be made optional when %q is present.
# ---------------------------------------------------------------------------

_ESCAPE_TABLE: Dict[str, Tuple[str, str, bool]] = {
    # fmt: off
    "a": ("application_name",    r"(?:[^\s\[]+)",                               True),
    "u": ("user",                r"(?:[^\s@\[]+)",                              True),
    "d": ("database",            r"(?:[^\s\[]+)",                               True),
    "r": ("remote_host_port",    r"(?:[\w.\-:]+(?:\(\d+\))?)",                 True),
    "h": ("remote_host",         r"(?:[\w.\-]+)",                               True),
    "b": ("backend_type",        r"(?:\w+(?:\s+\w+)*)",                        False),
    "p": ("pid",                 r"(?:\d+)",                                    False),
    "P": ("parallel_leader_pid", r"(?:\d+)",                                   False),
    "t": ("timestamp",
          r"(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\s[A-Z]{2,5}[+\-]?\d*)?)",
          False),
    "m": ("timestamp_ms",
          r"(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+(?:\s[A-Z]{2,5}[+\-]?\d*)?)",
          False),
    "n": ("timestamp_epoch",     r"(?:\d+\.\d+)",                              False),
    "i": ("command_tag",         r"(?:\w*)",                                    True),
    "e": ("sql_state",           r"(?:[A-Z0-9]{5})",                           False),
    "c": ("session_id",          r"(?:[0-9a-f]+\.[0-9a-f]+)",                 False),
    "l": ("line_num",            r"(?:\d+)",                                    False),
    "s": ("session_start",
          r"(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
          True),
    "v": ("virtual_txid",        r"(?:\d+/\d+)",                               False),
    "x": ("txid",                r"(?:\d+)",                                    False),
    "Q": ("query_id",            r"(?:\d+)",                                    False),
    # fmt: on
}

# Timestamp field names (at least one required)
_TIMESTAMP_FIELDS = {"timestamp", "timestamp_ms", "timestamp_epoch"}
# Process-ID field names (at least one required)
_PID_FIELDS = {"pid", "session_id"}


# ---------------------------------------------------------------------------
# PrefixCompiler
# ---------------------------------------------------------------------------


class PrefixCompiler:
    """
    Compile a PostgreSQL ``log_line_prefix`` string into a Python regex
    that extracts all named fields from a log line header.

    Usage::

        compiler = PrefixCompiler('%m [%p] %q%u@%d/%a ')
        regex    = compiler.compile()
        fields   = compiler.parse_line(
            "2024-01-15 08:00:01.234 UTC [1234] app@mydb/rails LOG:  message"
        )
        # -> {"timestamp_ms": "2024-01-15 08:00:01.234 UTC",
        #     "pid": "1234", "user": "app",
        #     "database": "mydb", "application_name": "rails"}
    """

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self._regex: Optional[re.Pattern] = None  # type: ignore[type-arg]
        self._fields: List[str] = []
        self._has_timestamp: bool = False
        self._has_pid: bool = False
        self._q_position: int = -1  # index in prefix string where %q appears
        # field_name -> True if that field appears after %q
        self._after_q: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # compile()
    # ------------------------------------------------------------------

    def compile(self) -> re.Pattern:  # type: ignore[type-arg]
        """Convert the prefix string to a compiled regex with named groups."""
        if self._regex is not None:
            return self._regex

        self._fields = []
        self._after_q = {}
        self._has_timestamp = False
        self._has_pid = False

        # Split the prefix at the first %q (if present).
        before_q_raw, after_q_raw = self._split_at_q(self.prefix)

        # Compile the before-%q segment (required)
        seen: Dict[str, int] = {}
        before_parts = self._compile_segment(before_q_raw, after_q=False, seen=seen)
        before_pattern = "".join(before_parts)

        # Compile the after-%q segment (optional as a whole)
        if after_q_raw is not None:
            after_parts = self._compile_segment(after_q_raw, after_q=True, seen=seen)
            after_inner = "".join(after_parts)
            after_pattern = f"(?:{after_inner})?" if after_inner else ""
        else:
            after_pattern = ""

        full_pattern = "^" + before_pattern + after_pattern
        self._regex = re.compile(full_pattern)
        return self._regex

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _split_at_q(prefix: str) -> Tuple[str, Optional[str]]:
        """
        Return ``(before_q, after_q)`` where *after_q* is ``None`` if ``%q``
        is not present, or the substring following the first ``%q`` escape.
        Width specifiers (``-?\\d*``) between ``%`` and ``q`` are recognised.
        """
        i = 0
        while i < len(prefix):
            if prefix[i] == "%" and i + 1 < len(prefix):
                j = i + 1
                # skip optional width specifier
                if j < len(prefix) and prefix[j] in ("-", "+"):
                    j += 1
                while j < len(prefix) and prefix[j].isdigit():
                    j += 1
                if j < len(prefix) and prefix[j] == "q":
                    return prefix[:i], prefix[j + 1:]
                # advance past this escape letter
                i = j + 1 if j < len(prefix) else j
            else:
                i += 1
        return prefix, None

    def _compile_segment(
        self,
        segment: str,
        after_q: bool,
        seen: Dict[str, int],
    ) -> List[str]:
        """
        Compile one segment of the prefix string into a list of regex
        sub-pattern strings, updating ``self._fields`` and ``seen`` in-place.

        If *after_q* is True all named groups become optional
        (they are then wrapped by a surrounding ``(?:...)?`` in ``compile()``).
        """
        parts: List[str] = []
        i = 0

        while i < len(segment):
            ch = segment[i]

            if ch == "%" and i + 1 < len(segment):
                i += 1
                # consume optional width specifier
                j = i
                if j < len(segment) and segment[j] in ("-", "+"):
                    j += 1
                while j < len(segment) and segment[j].isdigit():
                    j += 1
                escape_char = segment[j] if j < len(segment) else ""

                if escape_char == "%":
                    parts.append(re.escape("%"))
                    i = j + 1
                    continue

                if escape_char == "q":
                    # Nested %q — skip gracefully
                    i = j + 1
                    continue

                if escape_char in _ESCAPE_TABLE:
                    field_name, pat, is_session_only = _ESCAPE_TABLE[escape_char]

                    # Build a unique name if the same field appears more than once
                    if field_name in seen:
                        seen[field_name] += 1
                        unique_name = f"{field_name}_{seen[field_name]}"
                    else:
                        seen[field_name] = 1
                        unique_name = field_name

                    self._fields.append(unique_name)

                    if field_name in _TIMESTAMP_FIELDS:
                        self._has_timestamp = True
                    if field_name in _PID_FIELDS:
                        self._has_pid = True

                    # In the after-%q segment, or for inherently session-only
                    # fields, the individual group is optional so it can be
                    # absent while still allowing the surrounding wrapper to match.
                    if after_q or is_session_only:
                        group = f"(?P<{unique_name}>{pat})?"
                        self._after_q[unique_name] = True
                    else:
                        group = f"(?P<{unique_name}>{pat})"

                    parts.append(group)
                    i = j + 1
                else:
                    # Unknown escape — treat as literal characters
                    parts.append(re.escape("%" + escape_char))
                    i = j + 1
            else:
                # Literal character — spaces become \s*
                if ch == " ":
                    parts.append(r"\s*")
                else:
                    parts.append(re.escape(ch))
                i += 1

        return parts

    # ------------------------------------------------------------------
    # parse_line()
    # ------------------------------------------------------------------

    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Parse a log line and extract all prefix fields.

        Returns a dict of ``{field_name: value}`` or ``None`` if no match.
        Empty / absent optional groups are excluded from the result.
        """
        if self._regex is None:
            self.compile()
        assert self._regex is not None

        m = self._regex.match(line)
        if m is None:
            return None

        result: Dict[str, str] = {}
        for key, val in m.groupdict().items():
            if val is not None and val != "":
                result[key] = val.strip()
        return result

    # ------------------------------------------------------------------
    # validate()
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        """
        Validate the prefix for required fields.

        Returns a list of warning strings; empty list means the prefix is valid.
        Requirements:

        * At least one timestamp field: ``%t``, ``%m``, or ``%n``.
        * At least one process-ID field: ``%p`` or ``%c``.
        """
        if self._regex is None:
            self.compile()

        warnings: List[str] = []
        field_set = set(self._fields)

        if not (field_set & _TIMESTAMP_FIELDS):
            warnings.append(
                "log_line_prefix has no timestamp field (%t, %m, or %n); "
                "log entries will lack timestamps."
            )
        if not (field_set & _PID_FIELDS):
            warnings.append(
                "log_line_prefix has no process-ID field (%p or %c); "
                "multi-line log entries cannot be associated."
            )
        return warnings

    # ------------------------------------------------------------------
    # properties
    # ------------------------------------------------------------------

    @property
    def fields(self) -> List[str]:
        """Return the ordered list of field names this prefix captures."""
        if self._regex is None:
            self.compile()
        return list(self._fields)

    def _has_field(self, name: str) -> bool:
        if self._regex is None:
            self.compile()
        return name in self._fields

    @property
    def has_user(self) -> bool:
        return self._has_field("user")

    @property
    def has_database(self) -> bool:
        return self._has_field("database")

    @property
    def has_application(self) -> bool:
        return self._has_field("application_name")

    @property
    def has_host(self) -> bool:
        return self._has_field("remote_host") or self._has_field("remote_host_port")

    @property
    def has_sqlstate(self) -> bool:
        return self._has_field("sql_state")

    @property
    def has_session_id(self) -> bool:
        return self._has_field("session_id")

    @property
    def has_line_num(self) -> bool:
        return self._has_field("line_num")

    def __repr__(self) -> str:
        return f"PrefixCompiler({self.prefix!r})"


# ---------------------------------------------------------------------------
# Common prefixes
# ---------------------------------------------------------------------------

COMMON_PREFIXES: Dict[str, str] = {
    "default_pg10":     "%m [%p] ",
    "default_legacy":   "%t [%p]: ",
    "with_user_db":     "%m [%p] %q%u@%d ",
    "with_user_db_app": "%m [%p] %q%u@%d/%a ",
    "debian":           "%t [%p-%l] %q%u@%d ",
    "edb_recommended":  "%m [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ",
    # EDB / EnterpriseDB syslog style: delivered via syslog with double-header;
    # the PostgreSQL log_line_prefix embedded inside the syslog message is:
    #   %t [%p]: [%l-1] user=%u,db=%d,sessid=%c
    # Note: pgAnalyzer auto-detects this as LogFormat.SYSLOG and handles it
    # in _parse_syslog_line (variant B). The prefix below is for --log-line-prefix
    # documentation / --list-prefixes display only.
    "edb_syslog":       "%t [%p]: [%l-1] user=%u,db=%d,sessid=%c ",
    "pgbadger_classic": "%t [%p]: [%l-1] ",
    "rds":              "%t:%r:%u@%d:[%p]:",
    "full":             "%m [%p] %q[user=%u,db=%d,app=%a,client=%h] ",
}


def get_common_prefix(name: str) -> Optional[str]:
    """Return a named common prefix string, or ``None`` if unknown."""
    return COMMON_PREFIXES.get(name)


# ---------------------------------------------------------------------------
# prefix_to_description()
# ---------------------------------------------------------------------------

_FIELD_LABELS: Dict[str, str] = {
    "timestamp":            "timestamp",
    "timestamp_ms":         "timestamp_ms",
    "timestamp_epoch":      "timestamp_epoch",
    "pid":                  "pid",
    "parallel_leader_pid":  "parallel_leader_pid",
    "user":                 "user",
    "database":             "database",
    "application_name":     "application",
    "remote_host":          "host",
    "remote_host_port":     "host:port",
    "backend_type":         "backend_type",
    "command_tag":          "command_tag",
    "sql_state":            "sqlstate",
    "session_id":           "session_id",
    "line_num":             "line_num",
    "session_start":        "session_start",
    "virtual_txid":         "virtual_txid",
    "txid":                 "txid",
    "query_id":             "query_id",
}


def prefix_to_description(prefix: str) -> str:
    """
    Return a human-readable description of what a prefix captures.

    Example::

        prefix_to_description('%m [%p] %q%u@%d/%a ')
        # -> 'timestamp_ms, pid, [user, database, application]'
    """
    before_q_raw, after_q_raw = PrefixCompiler._split_at_q(prefix)

    def _labels_in_segment(segment: str) -> List[str]:
        labels: List[str] = []
        i = 0
        while i < len(segment):
            if segment[i] == "%" and i + 1 < len(segment):
                j = i + 1
                if j < len(segment) and segment[j] in ("-", "+"):
                    j += 1
                while j < len(segment) and segment[j].isdigit():
                    j += 1
                esc = segment[j] if j < len(segment) else ""
                if esc in _ESCAPE_TABLE:
                    field_name = _ESCAPE_TABLE[esc][0]
                    labels.append(_FIELD_LABELS.get(field_name, field_name))
                i = j + 1
            else:
                i += 1
        return labels

    before_labels = _labels_in_segment(before_q_raw)
    parts: List[str] = list(before_labels)

    if after_q_raw is not None:
        after_labels = _labels_in_segment(after_q_raw)
        if after_labels:
            parts.append("[" + ", ".join(after_labels) + "]")

    return ", ".join(parts) if parts else "(empty prefix)"


# ---------------------------------------------------------------------------
# detect_prefix_from_log()
# ---------------------------------------------------------------------------

_KNOWN_PREFIXES_ORDERED: List[str] = [
    "%m [%p] ",
    "%t [%p]: ",
    "%m [%p] %q%u@%d ",
    "%m [%p] %q%u@%d/%a ",
    "%t [%p-%l] %q%u@%d ",
    "%m [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ",
    "%t [%p]: [%l-1] ",
    "%m [%p] %quser=%u,db=%d,app=%a,client=%h ",
    "time=%t, pid=%p %q db=%d, usr=%u, client=%h , app=%a, line=%l ",
    "%t:%r:%u@%d:[%p]:",
]


def detect_prefix_from_log(sample_lines: List[str]) -> Optional[str]:
    """
    Try to infer the ``log_line_prefix`` from sample log lines by testing
    common known prefix patterns and returning the best match.

    Returns the prefix string that matches the most lines, or ``None`` if no
    pattern matches more than 50 % of the non-blank sample lines.
    """
    clean_lines = [line.rstrip("\n") for line in sample_lines if line.strip()]
    if not clean_lines:
        return None

    compiled: List[Tuple[str, re.Pattern]] = []  # type: ignore[type-arg]
    for pfx in _KNOWN_PREFIXES_ORDERED:
        try:
            regex = PrefixCompiler(pfx).compile()
            compiled.append((pfx, regex))
        except re.error:
            pass

    best_prefix: Optional[str] = None
    best_score = 0

    for pfx, regex in compiled:
        score = sum(1 for line in clean_lines if regex.match(line))
        if score > best_score:
            best_score = score
            best_prefix = pfx

    if best_score > len(clean_lines) * 0.5:
        return best_prefix
    return None


# ---------------------------------------------------------------------------
# infer_prefix_fields_heuristically()
# ---------------------------------------------------------------------------

_HEURISTIC_PATTERNS: Dict[str, re.Pattern] = {  # type: ignore[type-arg]
    "user":         re.compile(r"(?:user=|(?:^|\s)(\w+)@\w+)"),
    "database":     re.compile(r"(?:db=|@(\w+)(?:/|\s|$))"),
    "application":  re.compile(r"(?:app=|/(\w+)\s)"),
    "host":         re.compile(r"(?:client=|host=|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    "session_id":   re.compile(r"[0-9a-f]{8,}\.[0-9a-f]+"),
    "sqlstate":     re.compile(r"\b[A-Z0-9]{5}\b"),
}


def infer_prefix_fields_heuristically(sample_lines: List[str]) -> Dict[str, bool]:
    """
    Detect which fields are likely present by pattern matching against the
    first part of log lines (up to 120 characters before the log level).

    Returns::

        {
            "user":        True/False,
            "database":    True/False,
            "application": True/False,
            "host":        True/False,
            "session_id":  True/False,
            "sqlstate":    True/False,
        }
    """
    _level_split = re.compile(
        r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG|DETAIL|HINT|CONTEXT|STATEMENT):",
        re.IGNORECASE,
    )
    prefixes: List[str] = []
    for line in sample_lines:
        m = _level_split.search(line)
        prefixes.append(line[: m.start()] if m else line[:120])

    result: Dict[str, bool] = {}
    for field, pat in _HEURISTIC_PATTERNS.items():
        matches = sum(1 for p in prefixes if pat.search(p))
        result[field] = matches > len(prefixes) * 0.3
    return result


# ---------------------------------------------------------------------------
# Log-level pattern (shared)
# ---------------------------------------------------------------------------

_LOG_LEVEL_RE = re.compile(
    r"(DEBUG\d?|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC|LOG|DETAIL|HINT|CONTEXT|STATEMENT)"
    r":\s*(.*)",
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# build_entry_from_prefix()
# ---------------------------------------------------------------------------


def build_entry_from_prefix(
    line: str,
    compiler: PrefixCompiler,
    log_level_pattern: Optional[re.Pattern] = None,  # type: ignore[type-arg]
) -> Optional[Tuple[Dict[str, str], str, str]]:
    """
    Parse a full log line using a compiled prefix + the log-level pattern.

    Returns ``(fields_dict, level_str, message_str)`` or ``None`` if no match.

    The log level appears AFTER the prefix in the format::

        <prefix>LEVEL:  message

    or sometimes::

        <prefix>[level label] LEVEL:  message
    """
    if log_level_pattern is None:
        log_level_pattern = _LOG_LEVEL_RE

    if compiler._regex is None:
        compiler.compile()

    regex = compiler._regex
    assert regex is not None

    m = regex.match(line)
    if m is None:
        return None

    fields: Dict[str, str] = {
        k: v.strip()
        for k, v in m.groupdict().items()
        if v is not None and v != ""
    }

    # Remainder of the line after the prefix
    remainder = line[m.end():]

    # Strip optional bracket-wrapped label that some prefixes emit before level
    remainder = re.sub(r"^\[[^\]]*\]\s*", "", remainder)

    lm = log_level_pattern.match(remainder)
    if lm is None:
        return None

    level = lm.group(1).upper()
    message = lm.group(2)
    return fields, level, message


# ---------------------------------------------------------------------------
# patch_parser()
# ---------------------------------------------------------------------------


def patch_parser(compiler: PrefixCompiler) -> None:
    """
    Monkey-patch ``parser._STDERR_RE`` at runtime so that the main parser
    uses the compiled prefix regex instead of the built-in heuristic.

    This enables the ``--log-line-prefix`` CLI option to work transparently.

    The patched regex must still expose group 1 as the timestamp and
    group 2 as the PID to remain compatible with ``parser.py``'s internals.
    We reconstruct a compatible two-group pattern from the compiler's fields.
    """
    try:
        from pgloglens import parser as _parser_module  # type: ignore[import]
    except ImportError:
        return

    if compiler._regex is None:
        compiler.compile()

    fields = compiler.fields
    ts_field = next((f for f in fields if f in _TIMESTAMP_FIELDS), None)
    pid_field = next((f for f in fields if f in _PID_FIELDS), None)

    if ts_field is None or pid_field is None:
        # Cannot build a compatible two-group regex; leave _STDERR_RE alone.
        return

    original_pattern = compiler._regex.pattern

    # Replace the named groups for timestamp and pid with plain capturing groups
    new_pattern = original_pattern.replace(f"(?P<{ts_field}>", "(", 1)
    new_pattern = new_pattern.replace(f"(?P<{pid_field}>", "(", 1)

    try:
        _parser_module._STDERR_RE = re.compile(new_pattern)
    except re.error:
        pass


# ---------------------------------------------------------------------------
# _test()  — embedded test suite
# ---------------------------------------------------------------------------


def _test() -> None:  # noqa: C901
    """Run embedded correctness tests.  Call ``python -m pgloglens.prefix`` to run."""

    failures: List[str] = []

    def _assert(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    def _check(
        prefix: str,
        line: str,
        expected: Dict[str, str],
        test_name: str,
    ) -> None:
        compiler = PrefixCompiler(prefix)
        result = compiler.parse_line(line)
        if result is None:
            failures.append(
                f"{test_name}: parse_line returned None\n"
                f"  prefix={prefix!r}\n"
                f"  line={line!r}\n"
                f"  pattern={compiler._regex.pattern if compiler._regex else '<not compiled>'}"
            )
            return
        for field, value in expected.items():
            got = result.get(field)
            if got != value:
                failures.append(
                    f"{test_name}: field {field!r}: expected {value!r}, got {got!r}\n"
                    f"  prefix={prefix!r}\n"
                    f"  line={line!r}\n"
                    f"  full result={result}"
                )

    # ------------------------------------------------------------------ #
    # Test 1: basic default prefix
    # ------------------------------------------------------------------ #
    _check(
        prefix="%m [%p] ",
        line="2024-01-15 08:00:01.234 UTC [1234] LOG:  message",
        expected={"timestamp_ms": "2024-01-15 08:00:01.234 UTC", "pid": "1234"},
        test_name="test1_default_prefix",
    )

    # ------------------------------------------------------------------ #
    # Test 2: client backend with %q (has user/db/app)
    # ------------------------------------------------------------------ #
    _check(
        prefix="%m [%p] %q%u@%d/%a ",
        line="2024-01-15 08:00:01.234 UTC [1234] app@mydb/rails LOG:  duration: 1234 ms",
        expected={
            "timestamp_ms": "2024-01-15 08:00:01.234 UTC",
            "pid": "1234",
            "user": "app",
            "database": "mydb",
            "application_name": "rails",
        },
        test_name="test2_client_backend",
    )

    # ------------------------------------------------------------------ #
    # Test 3: background process stops at %q (no user/db/app)
    # ------------------------------------------------------------------ #
    c3 = PrefixCompiler("%m [%p] %q%u@%d/%a ")
    r3 = c3.parse_line("2024-01-15 08:00:01.234 UTC [5678] LOG:  automatic vacuum of table")
    _assert(r3 is not None, f"test3: parse_line returned None\n  pattern={c3._regex.pattern if c3._regex else '<not compiled>'}")
    if r3 is not None:
        _assert(r3.get("pid") == "5678", f"test3: pid={r3.get('pid')!r}, want '5678'")
        _assert("user" not in r3, f"test3: user should be absent, got {r3.get('user')!r}")
        _assert("database" not in r3, f"test3: database should be absent")
        _assert("application_name" not in r3, f"test3: application_name should be absent")

    # ------------------------------------------------------------------ #
    # Test 4: legacy prefix with line_num
    # ------------------------------------------------------------------ #
    _check(
        prefix="%t [%p]: [%l-1] ",
        line="2024-01-15 08:00:01 UTC [1234]: [1-1] LOG:  message",
        expected={
            "timestamp": "2024-01-15 08:00:01 UTC",
            "pid": "1234",
            "line_num": "1",
        },
        test_name="test4_legacy_prefix",
    )

    # ------------------------------------------------------------------ #
    # Test 5: EDB/pganalyze recommended prefix
    # ------------------------------------------------------------------ #
    _check(
        prefix="%m [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ",
        line=(
            "2024-01-15 08:00:01.234 UTC [1234]: [5-1] "
            "user=alice,db=myapp,app=psql,client=192.168.1.10 "
            "LOG:  statement: SELECT 1"
        ),
        expected={
            "timestamp_ms": "2024-01-15 08:00:01.234 UTC",
            "pid": "1234",
            "line_num": "5",
            "user": "alice",
            "database": "myapp",
            "application_name": "psql",
            "remote_host": "192.168.1.10",
        },
        test_name="test5_edb_recommended",
    )

    # ------------------------------------------------------------------ #
    # Test 6: EDB blog-style prefix with named keys
    # ------------------------------------------------------------------ #
    _check(
        prefix="time=%t, pid=%p %q db=%d, usr=%u, client=%h , app=%a, line=%l ",
        line=(
            "time=2024-01-15 08:00:01 UTC, pid=1234 "
            "db=myapp, usr=alice, client=10.0.0.1 , app=webapp, line=3 "
            "LOG:  duration: 100 ms"
        ),
        expected={
            "timestamp": "2024-01-15 08:00:01 UTC",
            "pid": "1234",
            "database": "myapp",
            "user": "alice",
            "remote_host": "10.0.0.1",
            "application_name": "webapp",
            "line_num": "3",
        },
        test_name="test6_edb_blog_style",
    )

    # ------------------------------------------------------------------ #
    # Test 7: width-padded fields
    # ------------------------------------------------------------------ #
    # %-15u means left-aligned in 15-char field; the actual value is "app"
    # The regex matches greedily; parse_line strips trailing spaces.
    _check(
        prefix="%-15u %p ",
        line="app             1234 LOG:  message",
        expected={"user": "app", "pid": "1234"},
        test_name="test7_width_padded",
    )

    # ------------------------------------------------------------------ #
    # validate()
    # ------------------------------------------------------------------ #
    warns = PrefixCompiler("%m [%p] ").validate()
    _assert(len(warns) == 0, f"validate() should be clean for '%m [%p] ', got {warns}")

    warns_no_ts = PrefixCompiler("[%p] ").validate()
    _assert(
        any("timestamp" in w for w in warns_no_ts),
        f"validate() should warn about missing timestamp, got {warns_no_ts}",
    )

    warns_no_pid = PrefixCompiler("%m ").validate()
    _assert(
        any("process-ID" in w for w in warns_no_pid),
        f"validate() should warn about missing pid, got {warns_no_pid}",
    )

    # ------------------------------------------------------------------ #
    # properties
    # ------------------------------------------------------------------ #
    c = PrefixCompiler("%m [%p] %q%u@%d/%a ")
    _assert(c.has_user, "has_user should be True")
    _assert(c.has_database, "has_database should be True")
    _assert(c.has_application, "has_application should be True")
    _assert(not c.has_host, "has_host should be False")
    _assert(not c.has_sqlstate, "has_sqlstate should be False")
    _assert(not c.has_session_id, "has_session_id should be False")
    _assert(not c.has_line_num, "has_line_num should be False")

    # ------------------------------------------------------------------ #
    # build_entry_from_prefix()
    # ------------------------------------------------------------------ #
    bcompiler = PrefixCompiler("%m [%p] ")
    bline = "2024-01-15 08:00:01.234 UTC [9999] LOG:  slow query detected"
    result = build_entry_from_prefix(bline, bcompiler)
    _assert(result is not None, "build_entry_from_prefix returned None")
    if result is not None:
        fields, level, message = result
        _assert(fields.get("pid") == "9999", f"build: pid={fields.get('pid')!r}")
        _assert(level == "LOG", f"build: level={level!r}")
        _assert("slow query" in message, f"build: message={message!r}")

    # ------------------------------------------------------------------ #
    # detect_prefix_from_log()
    # ------------------------------------------------------------------ #
    sample = [
        "2024-01-15 08:00:01.234 UTC [1234] LOG:  connection received",
        "2024-01-15 08:00:01.235 UTC [1234] LOG:  connection authorized",
        "2024-01-15 08:00:02.100 UTC [5678] LOG:  checkpoint complete",
    ]
    detected = detect_prefix_from_log(sample)
    _assert(detected == "%m [%p] ", f"detect: expected '%m [%p] ', got {detected!r}")

    # ------------------------------------------------------------------ #
    # prefix_to_description()
    # ------------------------------------------------------------------ #
    desc = prefix_to_description("%m [%p] %q%u@%d/%a ")
    _assert("timestamp_ms" in desc, f"description missing timestamp_ms: {desc!r}")
    _assert("pid" in desc, f"description missing pid: {desc!r}")
    _assert("user" in desc, f"description missing user: {desc!r}")

    # ------------------------------------------------------------------ #
    # COMMON_PREFIXES / get_common_prefix()
    # ------------------------------------------------------------------ #
    _assert(get_common_prefix("default_pg10") == "%m [%p] ", "get_common_prefix default_pg10")
    _assert(get_common_prefix("nonexistent") is None, "get_common_prefix nonexistent")

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        raise AssertionError(f"{len(failures)} test(s) failed — see above.")
    else:
        print(f"All tests passed ({len(_KNOWN_PREFIXES_ORDERED)} common prefixes registered).")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _test()
