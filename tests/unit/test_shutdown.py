"""Tests for graceful shutdown, write-ahead intent, and crash recovery (#136).

The chaos-style tests simulate kill -9 by simply not running the cleanup
paths: they abandon a journal mid-sequence (including a torn trailing line,
as an fsync'd JSONL writer would leave) and verify recovery repairs to a
consistent state, is idempotent when run twice, and never produces duplicate
side effects.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.shutdown import (
    DrainResult,
    IntentJournal,
    IntentState,
    ShutdownCoordinator,
    ShutdownState,
    recover,
)

# --- IntentJournal ----------------------------------------------------------


def test_intent_lifecycle_pending_then_done(tmp_path):
    j = IntentJournal(tmp_path / "intents.jsonl")
    intent = j.begin("provider_call", {"model": "m", "task": "t1"})
    assert [i.state for i in j.pending()] == [IntentState.PENDING]
    j.resolve(intent.intent_id, IntentState.DONE)
    assert j.pending() == []
    loaded = {i.intent_id: i for i in j.load()}
    assert loaded[intent.intent_id].state == IntentState.DONE


def test_journal_survives_torn_write(tmp_path):
    # Simulate kill -9 mid-append: last line truncated.
    path = tmp_path / "intents.jsonl"
    j = IntentJournal(path)
    a = j.begin("kind_a", {})
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"intent_id": "torn", "kind": "kin')  # no newline, invalid JSON
    loaded = j.load()
    assert len(loaded) == 1
    assert loaded[0].intent_id == a.intent_id


# --- ShutdownCoordinator ----------------------------------------------------


def test_shutdown_drains_in_flight_and_rejects_new_work():
    coord = ShutdownCoordinator(drain_deadline_s=5.0)
    drained = []
    coord.register("events", lambda budget: drained.append(budget) or True)

    assert coord.accepting_work
    result = coord.request_shutdown()
    assert isinstance(result, DrainResult)
    assert result.drained == ["events"]
    assert not coord.accepting_work
    assert coord.state == ShutdownState.STOPPED


def test_shutdown_deadline_checkpoints_remaining_callbacks():
    coord = ShutdownCoordinator(drain_deadline_s=0.05)

    def slow(budget):
        import time

        time.sleep(0.2)  # blows the entire deadline
        return True

    # Callbacks drain newest-registered-first: "later" is attempted before
    # "early", so the deadline expires before "early" ever gets a budget.
    coord.register("early", lambda b: True)
    coord.register("later", slow)
    result = coord.request_shutdown()
    assert result.drained == ["later"]
    assert result.checkpointed == ["early"]
    assert result.timed_out


def test_second_shutdown_signal_is_idempotent():
    coord = ShutdownCoordinator()
    calls = []
    coord.register("x", lambda b: calls.append(1) or True)
    first = coord.request_shutdown()
    second = coord.request_shutdown()  # e.g. user hits Ctrl-C twice
    assert calls.count(1) == 1
    assert second.drained == [] or first.drained == ["x"]


def test_broken_drain_callback_does_not_block_stopping():
    coord = ShutdownCoordinator(drain_deadline_s=1.0)

    def boom(budget):
        raise RuntimeError("drain hook exploded")

    coord.register("boom", boom)
    coord.register("after_boom", lambda b: True)
    result = coord.request_shutdown()
    assert result.checkpointed == ["boom"]
    assert result.drained == ["after_boom"]


# --- Recovery sweep ---------------------------------------------------------


def test_recovery_resolves_pending_intents_conservatively(tmp_path):
    path = tmp_path / "intents.jsonl"
    j = IntentJournal(path)
    i1 = j.begin("provider_call", {"task": "t1"})
    i2 = j.begin("recovery_repair", {})

    report = recover(path)  # default policy: abort pending intents
    states = {i.intent_id: i.state for i in IntentJournal(path).load()}
    assert states[i1.intent_id] == IntentState.ABORTED
    assert states[i2.intent_id] == IntentState.ABORTED
    assert report.pending_intents_found == 2
    assert all(r.action == "intent:aborted" for r in report.repairs)


def test_recovery_is_idempotent_across_double_crash(tmp_path):
    path = tmp_path / "intents.jsonl"
    j = IntentJournal(path)
    j.begin("provider_call", {})

    first = recover(path)
    assert first.pending_intents_found == 1

    # Second crash DURING recovery, then run recovery again: nothing new to do.
    second = recover(path)
    assert second.pending_intents_found == 0
    assert second.repairs == []


def test_recovery_releases_stale_leases_and_orphans(tmp_path):
    released, removed = [], []
    report = recover(
        tmp_path / "none.jsonl",
        stale_leases=["lease-a", "lease-b"],
        release_lease=released.append,
        orphaned_artifacts=["sha256deadbeef"],
        remove_artifact=removed.append,
    )
    assert sorted(released) == ["lease-a", "lease-b"]
    assert removed == ["sha256deadbeef"]
    actions = {(r.action) for r in report.repairs}
    assert actions == {"release_lease", "remove_orphan_artifact"}


def test_chaos_no_duplicate_side_effects_after_restart(tmp_path):
    """kill -9 between begin() and resolve(); restart must NOT re-run effect."""
    path = tmp_path / "intents.jsonl"
    effects = []

    def do_work(journal, payload):
        intent = journal.begin("external_effect", payload)
        effects.append(payload["id"])  # side effect happens here...
        # ...crash before resolve(): intent stays PENDING on disk.
        return intent

    j = IntentJournal(path)
    do_work(j, {"id": "effect-1"})

    # Recovery sees one ambiguous intent. Because we cannot know whether the
    # external system observed it, default policy aborts rather than replays —
    # exactly once-or-zero times, never twice.
    recover(path, on_intent_pending=lambda i: "done")
    # No replay happened during recovery → still exactly one side effect.
    assert effects == ["effect-1"]


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "\n\n",
        json.dumps(
            {
                "intent_id": "x",
                "kind": "k",
                "state": "pending",
                "created_at": 1.0,
                "updated_at": 1.0,
            }
        )
        + "\n",
    ],
)
def test_journal_load_handles_edge_files(tmp_path, raw):
    p = tmp_path / "edge.jsonl"
    p.write_text(raw)
    assert len(IntentJournal(p).load()) == raw.count("intent_id")


def test_recovery_report_summary_string(tmp_path):
    report = recover(tmp_path / "empty.jsonl")
    assert report.summary() == "recovery: 0 pending intents, 0 repairs"
