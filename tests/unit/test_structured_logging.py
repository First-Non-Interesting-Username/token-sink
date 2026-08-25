"""Unit tests for structured logging + `system logs` (issue #135)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from observability.logs import (
    LEVELS,
    LogFilter,
    LogRecord,
    MemorySink,
    RedactionError,
    RotatingFileSink,
    StructuredLogger,
    build_logs_parser,
    file_sink,
    new_correlation_id,
    query_logs,
    render_human,
    run_logs_cli,
)


def _rec_dict(**over):
    d = {
        "ts": 1000.0,
        "level": "INFO",
        "component": "router",
        "message": "picked model",
        "correlation_id": "corr-1",
        "campaign_id": "camp-1",
        "agent_id": "agent-1",
        "detail": {"k": "v"},
    }
    d.update(over)
    return d


# --- writer --------------------------------------------------------------------


def test_json_line_record_shape():
    sink = MemorySink()
    log = StructuredLogger(sinks=[sink], level="DEBUG")
    rec = log.info(
        "router",
        "picked model",
        correlation_id="c1",
        campaign_id="ca1",
        agent_id="ag1",
        detail={"model": "m"},
    )
    assert rec is not None
    line = json.loads(sink.lines[0])
    for key in ("ts", "level", "component", "message", "correlation_id"):
        assert key in line
    assert line["component"] == "router"
    assert line["detail"] == {"model": "m"}


def test_level_filtering_global_and_per_component():
    sink = MemorySink()
    log = StructuredLogger(sinks=[sink], level="WARNING", levels={"noisy": "ERROR"})
    assert log.info("quiet", "dropped") is None
    assert log.debug_log("noisy", "dropped") is None
    assert log.error("noisy", "kept") is not None
    assert len(sink.lines) == 1
    with pytest.raises(ValueError, match="unknown level"):
        StructuredLogger(level="LOUD")


def test_redaction_gate_runs_on_every_write():
    seen = {}

    def redactor(payload):
        if payload is None:
            return None
        seen["called"] = True
        return {**payload, "api_key": "***"}

    sink = MemorySink()
    log = StructuredLogger(sinks=[sink], redactor=redactor)
    log.error("provider", "call failed", detail={"api_key": "sk-real", "code": 500})
    line = json.loads(sink.lines[0])
    assert line["detail"]["api_key"] == "***"
    assert line["detail"]["code"] == 500


def test_redaction_failure_fails_closed():
    def bad_redactor(payload):
        raise RuntimeError("leak detected")

    sink = MemorySink()
    log = StructuredLogger(sinks=[sink], redactor=bad_redactor)
    with pytest.raises(RedactionError):
        log.error("x", "boom", detail={"a": 1})
    assert sink.lines == []  # nothing persisted


def test_internal_detail_gated_behind_debug():
    plain = StructuredLogger(sinks=[MemorySink()])
    dbg = StructuredLogger(sinks=[MemorySink()], debug=True)
    kw = dict(detail_internal={"stack": "frame1"})
    r1 = plain.error("orchestrator", "crashed", **kw)
    r2 = dbg.error("orchestrator", "crashed", **kw)
    assert r1.detail_internal is None
    assert r2.detail_internal == {"stack": "frame1"}


def test_correlation_ids_join_records():
    corr = new_correlation_id()
    sink = MemorySink()
    log = StructuredLogger(sinks=[sink])
    log.info("agent", "task start", correlation_id=corr, campaign_id="c", agent_id="a")
    log.info("provider", "call sent", correlation_id=corr, campaign_id="c", agent_id="a")
    recs = [json.loads(line) for line in sink.lines]
    assert {r["correlation_id"] for r in recs} == {corr}
    assert len(corr) == 36


# --- sinks ---------------------------------------------------------------------


def test_file_sink_and_query(tmp_path: Path):
    f = tmp_path / "logs.jsonl"
    log = StructuredLogger(sinks=[file_sink(f)], level="DEBUG")
    log.info("a", "first")
    log.warning("b", "second", detail={"x": 1})
    recs = query_logs([f], LogFilter(level="WARNING"))
    assert [r.component for r in recs] == ["b"]


def test_rotating_sink(tmp_path: Path):
    f = tmp_path / "logs.jsonl"
    sink = RotatingFileSink(f, max_bytes=200, max_files=2)
    for i in range(10):
        sink(json.dumps(_rec_dict(ts=float(i), message=f"m{i} * 30")))
    files = sorted(p.name for p in tmp_path.iterdir())
    assert "logs.jsonl" in files
    assert "logs.jsonl.1" in files and "logs.jsonl.2" in files
    assert "logs.jsonl.3" not in files  # overflow deleted
    # newest records are in the live file
    live = json.loads(f.read_text().strip().splitlines()[-1])
    assert live["ts"] == 9.0


# --- query side (`system logs`) --------------------------------------------------


def test_query_filters(tmp_path: Path):
    f = tmp_path / "l.jsonl"
    rows = [
        _rec_dict(),
        _rec_dict(correlation_id="corr-2", level="ERROR", component="provider"),
        _rec_dict(agent_id="agent-2", ts=999.0),
        _rec_dict(detail_internal={"secret_stack": True}),
    ]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    by_corr = query_logs([f], LogFilter(correlation_id="corr-1"))
    assert len(by_corr) == 3

    by_level = query_logs([f], LogFilter(level="ERROR"))
    assert [r.message for r in by_level] == ["picked model"]

    by_agent = query_logs([f], LogFilter(agent_id="agent-2"))
    assert by_agent[0].ts == 999.0

    time_ranged = query_logs([f], LogFilter(until=999.5))
    assert all(r.ts <= 999.5 for r in time_ranged)

    # internal detail stripped unless explicitly requested (safe-for-display)
    default_view = query_logs([f], LogFilter())
    assert all(r.detail_internal is None for r in default_view)
    debug_view = query_logs([f], LogFilter(include_internal=True))
    assert any(r.detail_internal is not None for r in debug_view)


def test_query_tolerates_torn_lines_and_missing_files(tmp_path: Path):
    f = tmp_path / "l.jsonl"
    f.write_text(json.dumps(_rec_dict()) + "\n{torn\n")
    missing = query_logs([tmp_path / "nope.jsonl"], LogFilter())
    assert missing == []
    assert len(query_logs([f], LogFilter())) == 1


def test_render_human():
    recs = query_logs([])  # empty sources fine
    text = render_human([LogRecord.from_dict(_rec_dict())])
    assert "[INFO    ] router: picked model" in text
    assert "corr=corr-1" in text and "campaign=camp-1" in text and "agent=agent-1" in text
    assert render_human(recs) == ""


def test_cli_parser_and_run(tmp_path: Path, capsys):
    f = tmp_path / "l.jsonl"
    rows = [_rec_dict(), _rec_dict(level="ERROR", message="err-line")]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    parser = build_logs_parser([str(f)])

    args = parser.parse_args(["--level", "ERROR"])
    assert run_logs_cli(args, [str(f)]) == 0
    out = capsys.readouterr().out
    assert "err-line" in out and "picked model" not in out

    args = parser.parse_args(["--json"])
    run_logs_cli(args, [str(f)])
    lines = [json.loads(x) for x in capsys.readouterr().out.strip().splitlines()]
    assert len(lines) == 2 and lines[0]["level"] == "INFO"

    args = parser.parse_args(["--follow"])
    run_logs_cli(args, [str(f)], poll_seconds=0.01, max_iterations=2)
    assert capsys.readouterr().out  # produced output without hanging


def test_levels_constant_ordering():
    assert LEVELS.index("ERROR") > LEVELS.index("INFO")
