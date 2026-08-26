"""Structured logging pipeline with correlation IDs (issue #135, PLAN §13/§16).

Design decisions (per AGENTS.md):

- JSON-line records so `system logs` can filter precisely and run bundles
  (#57) can embed logs losslessly. One line per record: timestamp, level,
  component, correlation ID, campaign/agent UUIDs, message, and optional
  detail payloads.
- Every write passes through a redaction gate BEFORE the record is built or
  stored — secrets/PII must never reach disk even in a crashed record. The
  real redaction pipeline (issue #29) is injectable via ``redactor=``;
  until it lands we fail closed only when ``enforce_redaction=True`` (same
  shape as routers/decision_log.py).
- Error records carry two detail fields: ``detail`` (sanitized, always safe
  to display) and ``detail_internal`` (extended diagnostics). The internal
  field is only emitted when the sink is created with ``debug=True``, so
  operator-facing output never leaks internals by default.
- Levels are configurable per component; a component without an override
  falls back to the global level. Filtering is cheap (string compare) and
  happens before redaction so a dropped debug record costs nothing.
- Sinks are pluggable callables receiving the JSON line — file sink for
  persistence, list sink for tests. Rotation/retention hooks are exposed as
  a ``max_bytes``/``max_files`` rotating file sink aligned with #52.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Pluggable redaction function: takes a JSON-compatible object, returns the
# same shape with sensitive values masked.
Redactor = Callable[[Any], Any]

RedactionError = RuntimeError

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def default_redactor(payload: Any) -> Any:
    """Identity redactor.

    Replaced by the issue #29 pipeline via ``StructuredLogger(redactor=…)``.
    """
    return payload


def new_correlation_id() -> str:
    """Fresh correlation ID joining agent task → provider call → log records."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class LogContext:
    """Ambient correlation context attached to every record written in scope.

    Carries the IDs that tie a log line back to the work it belongs to:
    correlation ID (one per user-visible operation), plus the agent task,
    event, and finding it touches. Stored in a ContextVar so asyncio tasks
    and threads inherit it without threading parameters through every call
    (issue #209).
    """

    correlation_id: str | None = None
    campaign_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None
    event_id: str | int | None = None
    finding_id: str | None = None

    def merged(self, **overrides: Any) -> LogContext:
        """Copy with non-None override values applied (inner scope wins)."""
        fields = {f: getattr(self, f) for f in self.__dataclass_fields__}
        for k, v in overrides.items():
            if v is not None and k in fields:
                fields[k] = v
        return LogContext(**fields)


# Module-level ambient context. ContextVar means each asyncio task gets its
# own copy at spawn time — a child task's set_log_context cannot leak back
# into its parent, and unrelated tasks stay isolated. LogContext is immutable
# (frozen dataclass), so sharing one default instance is safe despite B039.
_current_context: ContextVar[LogContext] = ContextVar(
    "log_correlation_context",
    default=LogContext(),  # noqa: B039 — frozen dataclass
)


def get_log_context() -> LogContext:
    """The ambient LogContext for the current execution context."""
    return _current_context.get()


def set_log_context(ctx: LogContext) -> Token:
    """Replace the ambient context; returns a token for reset_log_context."""
    return _current_context.set(ctx)


def reset_log_context(token: Token) -> None:
    _current_context.reset(token)


@contextmanager
def log_context(**fields: Any):
    """Scoped context manager: merges fields into the ambient context.

    Example::

        with log_context(correlation_id=cid, campaign_id=camp):
            log.info("agent", "started")  # carries cid + camp automatically
    """
    token = set_log_context(get_log_context().merged(**fields))
    try:
        yield get_log_context()
    finally:
        reset_log_context(token)


def current_correlation_id() -> str | None:
    """Shorthand used by callers that need just the correlation ID."""
    return _current_context.get().correlation_id


def new_log_context(correlation_id: str | None = None, **fields: Any) -> LogContext:
    """Fresh context with a generated correlation ID unless one is given."""
    return LogContext(correlation_id=correlation_id or new_correlation_id(), **fields)


@dataclass
class LogRecord:
    """One structured log entry (JSON-line serializable)."""

    ts: float
    level: str
    component: str
    message: str
    correlation_id: str | None = None
    campaign_id: str | None = None
    agent_id: str | None = None
    # Work-unit linkage so one operation's records can be joined across
    # subsystems (issue #209): the agent task, event-store entry, and finding.
    task_id: str | None = None
    event_id: str | int | None = None
    finding_id: str | None = None
    # Sanitized detail: safe for display everywhere.
    detail: dict[str, Any] | None = None
    # Extended internal diagnostics: only persisted/emitted when debug=True.
    detail_internal: dict[str, Any] | None = None

    def to_dict(self, include_internal: bool = False) -> dict[str, Any]:
        d = {
            "ts": self.ts,
            "level": self.level,
            "component": self.component,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "campaign_id": self.campaign_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "event_id": self.event_id,
            "finding_id": self.finding_id,
            "detail": self.detail,
        }
        if include_internal:
            d["detail_internal"] = self.detail_internal
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogRecord:
        # Tolerate records written before task/event/finding fields existed.
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


def _level_num(level: str) -> int:
    return LEVELS.index(level)


class StructuredLogger:
    """Central structured-log writer.

    ``sinks`` receive each serialized JSON line. ``levels`` maps component
    name → minimum level, overriding ``level`` for that component only.
    """

    def __init__(
        self,
        sinks: list[Callable[[str], None]] | None = None,
        level: str = "INFO",
        levels: dict[str, str] | None = None,
        redactor: Redactor = default_redactor,
        enforce_redaction: bool = False,
        debug: bool = False,
    ) -> None:
        if level not in LEVELS:
            raise ValueError(f"unknown level '{level}'")
        for comp, lvl in (levels or {}).items():
            if lvl not in LEVELS:
                raise ValueError(f"unknown level '{lvl}' for component '{comp}'")
        self.sinks = sinks or []
        self.level = level
        self.levels = levels or {}
        self.redactor = redactor
        self.enforce_redaction = enforce_redaction
        self.debug = debug

    def _enabled(self, component: str, level: str) -> bool:
        threshold = self.levels.get(component, self.level)
        return _level_num(level) >= _level_num(threshold)

    def log(
        self,
        level: str,
        component: str,
        message: str,
        *,
        correlation_id: str | None = None,
        campaign_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
        event_id: str | int | None = None,
        finding_id: str | None = None,
        detail: dict[str, Any] | None = None,
        detail_internal: dict[str, Any] | None = None,
    ) -> LogRecord | None:
        """Write one record through the redaction gate. Returns the record,
        or None when filtered out by level.

        Correlation fields not passed explicitly fall back to the ambient
        LogContext (issue #209) so subsystems inherit IDs without threading
        them through every signature. An explicit argument always wins.
        """
        if level not in LEVELS:
            raise ValueError(f"unknown level '{level}'")
        if not self._enabled(component, level):
            return None
        ambient = get_log_context()
        try:
            rec = LogRecord(
                ts=time.time(),
                level=level,
                component=component,
                message=message,
                correlation_id=correlation_id or ambient.correlation_id,
                campaign_id=campaign_id or ambient.campaign_id,
                agent_id=agent_id or ambient.agent_id,
                task_id=task_id or ambient.task_id,
                event_id=event_id or ambient.event_id,
                finding_id=finding_id or ambient.finding_id,
                detail=_redact_value(detail, self.redactor),
                # Internal detail is gated behind debug AND redacted too — it
                # may carry stack context but still must not carry secrets.
                detail_internal=(
                    _redact_value(detail_internal, self.redactor) if self.debug else None
                ),
            )
        except RedactionError:
            # Fail closed: refuse to persist anything rather than store a
            # record that failed its redaction check (PLAN §15).
            raise
        line = json.dumps(rec.to_dict(include_internal=True), sort_keys=False)
        for sink in self.sinks:
            sink(line)
        return rec

    def debug_log(self, component: str, message: str, **kw: Any) -> LogRecord | None:
        return self.log("DEBUG", component, message, **kw)

    def info(self, component: str, message: str, **kw: Any) -> LogRecord | None:
        return self.log("INFO", component, message, **kw)

    def warning(self, component: str, message: str, **kw: Any) -> LogRecord | None:
        return self.log("WARNING", component, message, **kw)

    def error(self, component: str, message: str, **kw: Any) -> LogRecord | None:
        return self.log("ERROR", component, message, **kw)

    def critical(self, component: str, message: str, **kw: Any) -> LogRecord | None:
        return self.log("CRITICAL", component, message, **kw)


def _redact_value(value: Any, redactor: Redactor) -> Any:
    """Run the redaction gate on a payload before it touches storage."""
    if value is None:
        return None
    try:
        return redactor(value)
    except Exception as e:
        if redactor is default_redactor:
            raise  # identity redactor failing means non-serializable input
        raise RedactionError(f"log record rejected by redaction gate: {e}") from e


# --- sinks -------------------------------------------------------------------


def file_sink(path: str | Path) -> Callable[[str], None]:
    """Append-only JSON-lines file sink."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    def _write(line: str) -> None:
        with p.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    return _write


class RotatingFileSink:
    """Size-based rotating JSON-lines sink (retention hooks, #52).

    Keeps up to ``max_files`` files of at most ``max_bytes`` bytes each;
    oldest is deleted. Not process-safe by design — single-writer like the
    rest of the storage layer.
    """

    def __init__(self, path: str | Path, max_bytes: int = 5_000_000, max_files: int = 5):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate(self) -> None:
        # Shift logs.1 ← log, logs.2 ← logs.1 … then drop the overflow file.
        for i in range(self.max_files - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            dst = self.path.with_name(f"{self.path.name}.{i + 1}")
            if src.exists():
                src.replace(dst)
        if self.path.exists():
            self.path.replace(self.path.with_name(f"{self.path.name}.1"))
        # Delete any file beyond max_files.
        overflow = self.path.with_name(f"{self.path.name}.{self.max_files + 1}")
        if overflow.exists():
            overflow.unlink()

    def __call__(self, line: str) -> None:
        if self.path.exists() and self.path.stat().st_size + len(line) + 1 > self.max_bytes:
            self._rotate()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class MemorySink:
    """In-memory sink for tests / `system logs --follow` buffering."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    def records(self, include_internal: bool = False) -> list[LogRecord]:
        out = []
        for ln in self.lines:
            d = json.loads(ln)
            if not include_internal:
                d.pop("detail_internal", None)
            out.append(LogRecord.from_dict(d))
        return out


# --- query side (`system logs`) -----------------------------------------------


@dataclass
class LogFilter:
    """Filters for the `system logs` command (PLAN §17)."""

    correlation_id: str | None = None
    agent_id: str | None = None
    campaign_id: str | None = None
    task_id: str | None = None
    finding_id: str | None = None
    level: str | None = None  # minimum level
    component: str | None = None
    since: float | None = None
    until: float | None = None
    include_internal: bool = False  # debug flag gates extended detail

    def matches(self, rec: LogRecord) -> bool:
        if self.correlation_id and rec.correlation_id != self.correlation_id:
            return False
        if self.agent_id and rec.agent_id != self.agent_id:
            return False
        if self.campaign_id and rec.campaign_id != self.campaign_id:
            return False
        if self.task_id and rec.task_id != self.task_id:
            return False
        if self.finding_id and rec.finding_id != self.finding_id:
            return False
        if self.level and _level_num(rec.level) < _level_num(self.level):
            return False
        if self.component and rec.component != self.component:
            return False
        if self.since is not None and rec.ts < self.since:
            return False
        if self.until is not None and rec.ts > self.until:
            return False
        return True


def query_logs(
    sources: list[IterableStr],
    flt: LogFilter | None = None,
) -> list[LogRecord]:
    """Read JSON-line log files, apply the filter, return matching records
    ordered by time."""
    flt = flt or LogFilter()
    out: list[LogRecord] = []
    for src in sources:
        path = Path(src)
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue  # tolerate torn final lines after crashes
                if not flt.include_internal:
                    d.pop("detail_internal", None)
                rec = LogRecord.from_dict(d)
                if flt.matches(rec):
                    out.append(rec)
    out.sort(key=lambda r: r.ts)
    return out


IterableStr = Any  # paths (str|Path); kept simple for typing


def render_human(records: list[LogRecord]) -> str:
    """Human-readable rendering for `system logs` (default mode)."""
    rows = []
    for r in records:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(r.ts))
        corr = f" corr={r.correlation_id}" if r.correlation_id else ""
        camp = f" campaign={r.campaign_id}" if r.campaign_id else ""
        agt = f" agent={r.agent_id}" if r.agent_id else ""
        task = f" task={r.task_id}" if r.task_id else ""
        fnd = f" finding={r.finding_id}" if r.finding_id else ""
        det = ""
        if r.detail:
            det = " " + json.dumps(r.detail, sort_keys=True)
        rows.append(
            f"{ts} [{r.level:<8}] {r.component}: {r.message}{corr}{camp}{agt}{task}{fnd}{det}"
        )
    return "\n".join(rows)


# --- CLI (`system logs`, PLAN §17) --------------------------------------------


def build_logs_parser(sources: list[str]) -> argparse.ArgumentParser:
    """`system logs` CLI: filter by correlation ID, agent, campaign, time
    range, level, component; --follow; human or JSON output."""
    p = argparse.ArgumentParser(prog="system logs", description="Query structured logs")
    p.add_argument("--correlation-id", default=None)
    p.add_argument("--agent", dest="agent_id", default=None)
    p.add_argument("--campaign", dest="campaign_id", default=None)
    p.add_argument("--level", choices=LEVELS, default=None, help="minimum level")
    p.add_argument("--component", default=None)
    p.add_argument("--since", type=float, default=None, help="unix timestamp")
    p.add_argument("--until", type=float, default=None, help="unix timestamp")
    p.add_argument("--follow", action="store_true", help="poll for new records")
    p.add_argument("--json", action="store_true", dest="as_json", help="JSON output")
    p.add_argument(
        "--debug-internal",
        action="store_true",
        help="include internal-only detail (debug flag gated)",
    )
    p.set_defaults(_sources=sources)
    return p


def run_logs_cli(
    args: argparse.Namespace,
    sources: list[str],
    poll_seconds: float = 1.0,
    max_iterations: int | None = None,
) -> int:
    """Execute the parsed `system logs` command. ``max_iterations`` bounds
    --follow polling (tests); None means follow forever."""
    flt = LogFilter(
        correlation_id=args.correlation_id,
        agent_id=args.agent_id,
        campaign_id=args.campaign_id,
        level=args.level,
        component=args.component,
        since=args.since,
        until=args.until,
        include_internal=args.debug_internal,
    )
    seen_ts = args.since
    iterations = 0
    while True:
        if seen_ts is not None:
            flt.since = seen_ts
        recs = query_logs(sources, flt)
        if recs:
            # Remember the newest ts so a follow pass only shows new records.
            seen_ts = max(r.ts for r in recs)
        if args.as_json:
            for r in recs:
                print(json.dumps(r.to_dict(include_internal=args.debug_internal)))
        else:
            text = render_human(recs)
            if text:
                print(text)
        if not args.follow:
            return 0
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            return 0
        time.sleep(poll_seconds)
