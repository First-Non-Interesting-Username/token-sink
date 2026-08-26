"""Unit tests for ambient correlation context (issue #209).

The #135 structured logger already carried correlation IDs per-call; #209 adds
a ContextVar-based LogContext so agent/task/event/finding IDs propagate across
subsystems without threading parameters through every signature.
"""

from __future__ import annotations

import asyncio
import json

from observability.logs import (
    LogFilter,
    MemorySink,
    StructuredLogger,
    current_correlation_id,
    get_log_context,
    log_context,
    new_log_context,
    reset_log_context,
    set_log_context,
)


def _logger() -> tuple[StructuredLogger, MemorySink]:
    sink = MemorySink()
    return StructuredLogger(sinks=[sink], level="DEBUG"), sink


# --- ambient context ----------------------------------------------------------


def test_default_context_is_empty():
    ctx = get_log_context()
    assert ctx.correlation_id is None
    assert ctx.task_id is None
    assert ctx.finding_id is None


def test_log_context_scopes_fields_and_restores():
    with log_context(correlation_id="c1", campaign_id="camp"):
        assert current_correlation_id() == "c1"
        assert get_log_context().campaign_id == "camp"
        # inner scope merges; outer fields survive
        with log_context(task_id="t9"):
            assert get_log_context().correlation_id == "c1"
            assert get_log_context().task_id == "t9"
        assert get_log_context().task_id is None
    assert current_correlation_id() is None


def test_none_overrides_do_not_shadow_outer_scope():
    with log_context(correlation_id="c1", finding_id="f1"):
        # passing None means "inherit", not "clear" — prevents accidental
        # unlinking when a helper passes through kwargs it did not fill.
        with log_context(task_id="t1", finding_id=None):
            ctx = get_log_context()
            assert ctx.finding_id == "f1"
            assert ctx.task_id == "t1"


def test_set_and_reset_token_roundtrip():
    token = set_log_context(new_log_context(correlation_id="cX"))
    try:
        assert current_correlation_id() == "cX"
    finally:
        reset_log_context(token)
    assert current_correlation_id() is None


def test_new_log_context_generates_correlation_id_once():
    ctx = new_log_context()
    assert ctx.correlation_id  # a fresh uuid
    again = new_log_context()
    assert again.correlation_id != ctx.correlation_id
    explicit = new_log_context(correlation_id="fixed")
    assert explicit.correlation_id == "fixed"


# --- logger fallback to ambient context ----------------------------------------


def test_logger_fills_ids_from_ambient_context():
    log, sink = _logger()
    with log_context(
        correlation_id="c1",
        campaign_id="camp1",
        agent_id="ag1",
        task_id="tk1",
        event_id=42,
        finding_id="fnd1",
    ):
        rec = log.info("agent", "did work")
    assert rec is not None
    line = json.loads(sink.lines[0])
    assert line["correlation_id"] == "c1"
    assert line["campaign_id"] == "camp1"
    assert line["agent_id"] == "ag1"
    assert line["task_id"] == "tk1"
    assert line["event_id"] == 42
    assert line["finding_id"] == "fnd1"


def test_explicit_argument_wins_over_ambient():
    log, sink = _logger()
    with log_context(correlation_id="ambient", task_id="ambient-task"):
        log.info("router", "picked model", correlation_id="explicit")
    line = json.loads(sink.lines[0])
    assert line["correlation_id"] == "explicit"
    assert line["task_id"] == "ambient-task"


def test_no_context_means_no_ids_in_line():
    log, sink = _logger()
    log.info("router", "plain")
    line = json.loads(sink.lines[0])
    for key in ("correlation_id", "campaign_id", "agent_id", "task_id", "finding_id"):
        assert key not in line


# --- async isolation ------------------------------------------------------------


def test_asyncio_tasks_inherit_and_stay_isolated():
    log, sink = _logger()

    async def child(name: str, cid: str):
        # Each task inherits the parent's ambient context at spawn time...
        assert current_correlation_id() == "parent-cid"
        # ...and its own set_log_context cannot leak back into the parent or
        # a sibling task (ContextVar semantics).
        with log_context(correlation_id=cid, task_id=name):
            await asyncio.sleep(0.01)
            log.info("agent", f"hello from {name}")

    async def main():
        with log_context(correlation_id="parent-cid"):
            await asyncio.gather(child("a", "cid-a"), child("b", "cid-b"))

    asyncio.run(main())
    lines = [json.loads(x) for x in sink.lines]
    by_task = {r["task_id"]: r["correlation_id"] for r in lines}
    assert by_task == {"a": "cid-a", "b": "cid-b"}
    assert all(r.get("campaign_id") is None for r in lines)


def test_thread_isolation_via_contextvars_copy_context():
    """Threads spawned via copy_context also inherit without cross-talk."""
    import contextvars
    import threading

    log, sink = _logger()
    seen: list[str] = []

    def worker():
        seen.append(current_correlation_id() or "")
        with log_context(task_id="thread-work"):
            log.info("agent", "from thread")

    with log_context(correlation_id="thrid"):
        ctx = contextvars.copy_context()
        t = threading.Thread(target=lambda: ctx.run(worker))
        t.start()
        t.join()

    assert seen == ["thrid"]
    line = json.loads(sink.lines[0])
    assert line["correlation_id"] == "thrid"
    assert line["task_id"] == "thread-work"


# --- filter / rendering ---------------------------------------------------------


def test_filter_by_task_and_finding():
    flt = LogFilter(task_id="tk1", finding_id="fnd1")
    from observability.logs import LogRecord

    hit = LogRecord(
        ts=1.0, level="INFO", component="c", message="m", task_id="tk1", finding_id="fnd1"
    )
    wrong_task = LogRecord(
        ts=2.0, level="INFO", component="c", message="m", task_id="other", finding_id="fnd1"
    )
    miss = LogRecord(ts=3.0, level="INFO", component="c", message="m")
    assert flt.matches(hit)
    assert not flt.matches(wrong_task)
    assert not flt.matches(miss)


def test_render_human_shows_task_and_finding():
    from observability.logs import LogRecord

    out = __import__("observability.logs", fromlist=["render_human"]).render_human(
        [
            LogRecord(
                ts=1000.0,
                level="INFO",
                component="agent",
                message="hi",
                correlation_id="c1",
                task_id="tk1",
                finding_id="fnd9",
            )
        ]
    )
    assert "corr=c1" in out
    assert "task=tk1" in out
    assert "finding=fnd9" in out


def test_old_records_without_new_fields_still_parse():
    """Records written before #209 must keep loading."""
    from observability.logs import LogRecord

    old = {"ts": 1.0, "level": "INFO", "component": "c", "message": "m", "correlation_id": "old"}
    rec = LogRecord.from_dict(old)
    assert rec.correlation_id == "old"
    assert rec.task_id is None
