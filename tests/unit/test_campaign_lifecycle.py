"""Tests for campaign lifecycle semantics (#205, PLAN §5/§17/§19.6).

Table-driven coverage of the state machine: legal/illegal transition
matrix, drain semantics on pause/stop, resumability from snapshots, and
the "campaign can resume after restart" acceptance criterion.
"""

from __future__ import annotations

import uuid

import pytest

from orchestrator.campaign_lifecycle import (
    CampaignLifecycle,
    CampaignState,
    DrainOutcome,
    IllegalTransitionError,
)


def make_machine(**kw) -> CampaignLifecycle:
    return CampaignLifecycle(now_ns=lambda: 1_000, **kw)


# --- legal / illegal transitions --------------------------------------------

LEGAL = [
    (CampaignState.DRAFT, CampaignState.RUNNING),
    (CampaignState.RUNNING, CampaignState.PAUSED),
    (CampaignState.RUNNING, CampaignState.STOPPED),
    (CampaignState.RUNNING, CampaignState.COMPLETED),
    (CampaignState.PAUSED, CampaignState.RUNNING),
    (CampaignState.PAUSED, CampaignState.STOPPED),
]

ILLEGAL = [
    (CampaignState.DRAFT, CampaignState.PAUSED),
    (CampaignState.DRAFT, CampaignState.STOPPED),
    (CampaignState.DRAFT, CampaignState.COMPLETED),
    (CampaignState.RUNNING, CampaignState.DRAFT),
    (CampaignState.PAUSED, CampaignState.DRAFT),
    (CampaignState.PAUSED, CampaignState.COMPLETED),
    (CampaignState.STOPPED, CampaignState.RUNNING),
    (CampaignState.STOPPED, CampaignState.PAUSED),
    (CampaignState.COMPLETED, CampaignState.RUNNING),
    (CampaignState.COMPLETED, CampaignState.STOPPED),
]


@pytest.mark.parametrize("src,dst", LEGAL)
def test_legal_transition(src, dst):
    m = make_machine(initial_state=src)
    r = m.transition(dst, actor="op")
    assert m.state is dst
    assert r.from_state is src and r.to_state is dst


@pytest.mark.parametrize("src,dst", ILLEGAL)
def test_illegal_transition_rejected(src, dst):
    m = make_machine(initial_state=src)
    with pytest.raises(IllegalTransitionError):
        m.transition(dst, actor="op")
    assert m.state is src  # unchanged
    assert m.history == []  # nothing recorded


def test_illegal_transition_message_lists_allowed():
    m = make_machine()
    try:
        m.transition(CampaignState.PAUSED, actor="op")
    except IllegalTransitionError as e:
        assert "draft -> paused" in str(e)
        assert "running" in str(e)
    else:
        pytest.fail("expected IllegalTransitionError")


def test_require_transition_validates_without_mutating():
    m = make_machine()
    assert m.require_transition(CampaignState.RUNNING) is True
    assert m.state is CampaignState.DRAFT


def test_transition_rejects_non_enum_target():
    m = make_machine()
    with pytest.raises(TypeError):
        m.transition("running", actor="op")  # type: ignore[arg-type]


# --- helpers -----------------------------------------------------------------


def test_start_pause_resume_stop_helpers():
    m = make_machine()
    m.start(actor="op", reason="kickoff")
    m.pause(actor="op", reason="maintenance")
    assert m.state is CampaignState.PAUSED
    m.resume(actor="op", reason="back")
    assert m.state is CampaignState.RUNNING
    m.stop(actor="op", reason="done early")
    assert m.state is CampaignState.STOPPED


def test_complete_only_from_running():
    m = make_machine()
    m.start(actor="op")
    m.complete(actor="op")
    assert m.state is CampaignState.COMPLETED


def test_history_is_append_only_with_metadata():
    m = make_machine(campaign_uuid=str(uuid.uuid4()))
    m.start(actor="alice", reason="go")
    m.pause(actor="bob", reason="hold")
    assert [h.to_state for h in m.history] == [CampaignState.RUNNING, CampaignState.PAUSED]
    assert m.history[0].actor == "alice"
    assert m.history[1].reason == "hold"


# --- in-flight draining -------------------------------------------------------


def test_pause_drains_in_flight_tasks():
    seen = {}

    def drain(deadline: float) -> DrainOutcome:
        seen["deadline"] = deadline
        return DrainOutcome(ok=True, drained=2)

    m = make_machine(drain_callback=drain)
    m.start(actor="op")
    m.mark_started("t1")
    m.mark_started("t2")
    assert m.in_flight_count == 2
    r = m.pause(actor="op", drain_deadline_seconds=5.0)
    assert seen["deadline"] == 5.0
    assert r.drain is not None and r.drain.ok and r.drain.drained == 2
    assert m.in_flight_count == 0


def test_failed_drain_records_outcome_but_still_transitions():
    def drain(deadline: float) -> DrainOutcome:
        return DrainOutcome(ok=False, abandoned=1, detail="stuck task")

    m = make_machine(drain_callback=drain)
    m.start(actor="op")
    m.mark_started("stuck")
    r = m.pause(actor="op", reason="force")
    assert m.state is CampaignState.PAUSED  # operator decision wins...
    assert r.drain.ok is False and r.drain.abandoned == 1  # ...but visibly
    # stuck task stays tracked so resume/recovery can see it was abandoned
    assert m.in_flight_count == 1


def test_drain_exception_does_not_crash_transition():
    def drain(deadline: float) -> DrainOutcome:
        raise RuntimeError("boom")

    m = make_machine(drain_callback=drain)
    m.start(actor="op")
    m.mark_started("x")
    r = m.stop(actor="op")
    assert m.state is CampaignState.STOPPED
    assert r.drain is not None and not r.drain.ok and "boom" in r.drain.detail


def test_no_callback_drain_trivially_ok():
    m = make_machine()
    m.start(actor="op")
    r = m.pause(actor="op")
    assert r.drain is not None and r.drain.ok


def test_start_and_resume_do_not_drain():
    calls = []

    def drain(deadline):
        calls.append(deadline)
        return DrainOutcome(ok=True)

    m = make_machine(drain_callback=drain)
    m.start(actor="op")
    m.pause(actor="op")
    assert len(calls) == 1  # only pause drained so far
    m.resume(actor="op")
    assert len(calls) == 1  # resume does not drain


def test_mark_started_only_while_running():
    m = make_machine()
    with pytest.raises(IllegalTransitionError):
        m.mark_started("t1")


# --- snapshot / restart resume -------------------------------------------------


def test_snapshot_roundtrip_preserves_state_and_history():
    m = make_machine(campaign_uuid="12345678-1234-5678-1234-567812345678")
    m.start(actor="a", reason="r1")
    m.pause(actor="b", reason="r2")
    snap = m.snapshot()

    m2 = CampaignLifecycle.from_snapshot(snap)
    assert m2.campaign_uuid == m.campaign_uuid
    assert m2.state is CampaignState.PAUSED
    assert len(m2.history) == 2
    assert m2.history[1].actor == "b"


def test_acceptance_campaign_resumes_after_restart():
    """PLAN acceptance: a campaign can resume after restart."""
    m = make_machine()
    m.start(actor="op")
    m.pause(actor="op", reason="restart window")

    snap = m.snapshot()  # persist; process dies; new process loads snapshot
    revived = CampaignLifecycle.from_snapshot(snap)
    revived.resume(actor="op", reason="back after restart")
    assert revived.state is CampaignState.RUNNING
    assert [h.to_state.value for h in revived.history] == ["running", "paused", "running"]


def test_snapshot_is_json_serializable():
    import json

    m = make_machine()
    m.start(actor="a")
    m.pause(actor="b")
    round_trip = json.loads(json.dumps(m.snapshot()))
    assert CampaignLifecycle.from_snapshot(round_trip).state is CampaignState.PAUSED


def test_invalid_uuid_rejected():
    with pytest.raises(ValueError):
        CampaignLifecycle(campaign_uuid="not-a-uuid")


def test_generated_uuid_when_absent():
    m = make_machine()
    uuid.UUID(m.campaign_uuid)  # must parse
