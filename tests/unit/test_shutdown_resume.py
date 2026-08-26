"""Tests for campaign shutdown checkpoints & restart resumption (issue #138).

Scenario coverage per the issue's acceptance criteria:
- clean stop vs crash are distinguishable (marker semantics)
- kill -TERM mid-run → restart → no task executed twice (journal dedupe)
- double-restart safety (state cleared after resume)
- corrupt checkpoint refuses to guess
"""

from __future__ import annotations

import json

import pytest

from orchestrator.shutdown_resume import (
    CampaignShutdownManager,
    CheckpointError,
    ShutdownCheckpoint,
    resume_campaign,
)


@pytest.fixture()
def mgr(tmp_path):
    return CampaignShutdownManager(tmp_path)


def test_checkpoint_roundtrip_and_atomicity(mgr):
    cp = mgr.write_checkpoint(
        "camp-1",
        agent_steps={"agent-a": "step-fetch", "agent-b": "step-report"},
        pending_task_ids=["t1", "t2", "t3"],
        event_stream_position=42,
        clean_stop=False,
    )
    loaded = mgr.load_checkpoint()
    assert loaded == cp
    assert loaded.agent_steps["agent-b"] == "step-report"
    assert loaded.event_stream_position == 42
    # No temp files left behind by the atomic write.
    assert not list(mgr.state_dir.glob("*.tmp"))


def test_clean_stop_marker_distinguishes_stop_from_crash(mgr):
    # Clean stop: marker present.
    mgr.write_checkpoint("camp-1", pending_task_ids=["t1"], clean_stop=True)
    assert mgr.was_clean_stop() is True
    # Crash simulation: checkpoint rewritten with clean_stop=False → marker gone.
    mgr.write_checkpoint("camp-1", pending_task_ids=["t1"], clean_stop=False)
    assert mgr.was_clean_stop() is False
    # Crash *between* checkpoint write and marker: simulate by writing the
    # checkpoint file directly without touching the marker.
    mgr2 = CampaignShutdownManager(mgr.state_dir)
    (mgr2.state_dir / "campaign_checkpoint.json").write_text(
        json.dumps(ShutdownCheckpoint(campaign_uuid="c", clean_stop=True).to_dict())
    )
    assert mgr2.load_checkpoint().clean_stop is True  # checkpoint claims clean…
    assert not mgr2.was_clean_stop()  # …but the missing marker says interrupted


def test_resume_requeues_only_incomplete_tasks_and_reports(mgr):
    mgr.write_checkpoint(
        "camp-1",
        pending_task_ids=["done-pre-crash", "in-flight", "never-started"],
        clean_stop=False,
    )
    requeued: list[str] = []
    report = resume_campaign(mgr, done_tasks={"done-pre-crash"}, requeue=requeued.append)
    assert report.interrupted is True
    assert report.requeued_task_ids == ["in-flight", "never-started"]
    assert requeued == ["in-flight", "never-started"]
    assert report.skipped_done_task_ids == ["done-pre-crash"]
    assert "1 already complete" in report.summary()
    assert "unclean interruption" in report.summary()


def test_no_duplicate_execution_across_restart_cycle(mgr):
    """The issue's core acceptance: no task executes twice across a stop/restart.

    Simulated via an execution counter keyed by task id: resume must never
    hand the same task to `requeue` twice across two consecutive restarts.
    """
    executions: dict[str, int] = {}

    def run(task_id: str) -> None:
        executions[task_id] = executions.get(task_id, 0) + 1

    def one_cycle(pending: list[str], done: set[str]) -> list[str]:
        mgr.write_checkpoint("camp-1", pending_task_ids=pending, clean_stop=False)
        requeued: list[str] = []
        report = resume_campaign(mgr, done_tasks=done, requeue=requeued.append)
        for t in report.requeued_task_ids:
            if t in done:
                continue  # journal says already done — must not run again
            done.add(t)
            run(t)  # worker picks it up; journal marks completed after
        return [t for t in requeued if t not in done] or []

    one_cycle(["t1", "t2", "t3"], set())
    # Crash again mid-second-run: t1 done, t2 in flight again. The second
    # cycle's checkpoint still lists t2/t3, but the journal (done_tasks)
    # marks them complete so resume must skip them — no second execution.
    second_pending_before_journal = ["t2", "t3", "t4"]
    mgr.write_checkpoint("camp-1", pending_task_ids=second_pending_before_journal, clean_stop=False)
    second_requeued: list[str] = []
    done_after_first = {"t1", "t2", "t3"}
    report2 = resume_campaign(mgr, done_tasks=done_after_first, requeue=second_requeued.append)
    for t in report2.requeued_task_ids:
        assert t not in ("t1", "t2", "t3")  # never re-executed
        run(t)

    all_runs = sorted(executions)
    assert all(v == 1 for v in executions.values())  # nothing ran twice
    assert "t4" in all_runs and "t1" in all_runs


def test_double_resume_is_safe_noop_after_state_cleared(mgr):
    mgr.write_checkpoint("camp-1", pending_task_ids=["t1"], clean_stop=True)
    calls: list[str] = []
    resume_campaign(mgr, done_tasks=set(), requeue=calls.append)
    with pytest.raises(CheckpointError):
        # Second restart finds no checkpoint: startup proceeds normally
        # instead of replaying old state (and definitely not re-running t1).
        resume_campaign(mgr, done_tasks=set(), requeue=calls.append)
    assert calls == ["t1"]


def test_clean_stop_resume_reports_not_interrupted(mgr):
    mgr.write_checkpoint("camp-1", pending_task_ids=["t9"], clean_stop=True)
    report = resume_campaign(mgr, done_tasks=set(), requeue=lambda t: None)
    assert report.interrupted is False
    assert "clean stop" in report.summary()


def test_corrupt_checkpoint_refuses_to_guess(mgr, tmp_path):
    mgr.write_checkpoint("camp-1", clean_stop=False)
    (mgr.state_dir / "campaign_checkpoint.json").write_text("{not json")
    with pytest.raises(CheckpointError, match="corrupt"):
        resume_campaign(mgr, done_tasks=set(), requeue=lambda t: None)


def test_unknown_checkpoint_version_rejected(mgr):
    (mgr.state_dir / "campaign_checkpoint.json").write_text(json.dumps({"version": 99}))
    with pytest.raises(CheckpointError, match="version"):
        mgr.load_checkpoint()


def test_load_checkpoint_when_never_written(mgr):
    assert mgr.load_checkpoint() is None
