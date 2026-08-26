"""Tests for the real-time approval stream (issue #237, PLAN §13 view 6)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from api.approval_stream import ApprovalStream
from policy.approvals import ApprovalBackend, RequestState
from policy.audit import AuditLog


@pytest.fixture()
def backend(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    return ApprovalBackend(log)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        self.t += 0.001
        return self.t


# --- snapshot + revision --------------------------------------------------------


def test_snapshot_lists_pending_requests(backend):
    st = ApprovalStream(backend)
    req = backend.create_request("active_testing", "camp-1", requested_by="agent-1")
    snap = st.snapshot()
    assert [r["id"] for r in snap["requests"]] == [req.id]
    assert snap["requests"][0]["state"] == "pending"
    assert snap["revision"] >= 1


def test_revision_bumps_on_mutation(backend):
    st = ApprovalStream(backend)
    req = backend.create_request("x", "c", requested_by="a")
    r1 = st.snapshot()["revision"]
    backend.grant(req.id, decided_by="human")
    st.notify_changed()
    r2 = st.snapshot()["revision"]
    backend.create_request("y", "c", requested_by="a")
    st.notify_changed()
    r3 = st.snapshot()["revision"]
    assert r1 < r2 < r3


def test_no_change_no_revision_bump(backend):
    st = ApprovalStream(backend)
    backend.create_request("x", "c", requested_by="a")
    st.snapshot()
    r = st.refresh()
    assert st.snapshot()["revision"] == r


def test_subscription_returns_none_when_unchanged(backend):
    st = ApprovalStream(backend)
    sub = st.subscribe()
    first = sub.next_snapshot()
    assert first is not None
    assert sub.next_snapshot() is None  # nothing changed


def test_subscription_delivers_change(backend):
    st = ApprovalStream(backend)
    sub = st.subscribe()
    sub.next_snapshot()
    req = backend.create_request("active_testing", "c", requested_by="a")
    st.notify_changed()
    snap = sub.next_snapshot()
    assert snap is not None and len(snap["requests"]) == 1
    assert snap["requests"][0]["id"] == req.id


# --- expiry surfaced as a push ----------------------------------------------------


def test_ttl_expiry_pushes_new_revision(tmp_path):
    fixed = datetime.now(UTC)

    class DT:
        def __init__(self):
            self.now = fixed

        def __call__(self):
            return self.now

    dt = DT()
    be = ApprovalBackend(AuditLog(tmp_path / "a.jsonl"), clock=dt)
    mono = FakeClock()
    st = ApprovalStream(be, clock=mono)
    req = be.create_request("active_testing", "c", requested_by="a", ttl_seconds=10)
    before = st.snapshot()["revision"]
    dt.now = fixed + timedelta(seconds=11)  # past the TTL
    after = st.refresh()
    assert after > before
    assert be.get(req.id).state is RequestState.EXPIRED
    # expired request left the pending queue
    assert all(r["id"] != req.id for r in st.snapshot()["requests"])


# --- wait_for_decision: grant unblocks exactly the waiting agent --------------------


def test_grant_unblocks_waiting_agent(backend):
    import threading

    st = ApprovalStream(backend)
    req = backend.create_request("active_testing", "c", requested_by="agent-7")
    results = {}

    def waiter(agent, out):
        out[agent] = st.wait_for_decision(req.id, timeout_s=5, poll_s=0.01)

    t = threading.Thread(target=waiter, args=("agent-7", results))
    t.start()
    backend.grant(req.id, decided_by="human")
    st.notify_changed()
    t.join(timeout=5)
    assert not t.is_alive()
    assert results["agent-7"]["state"] == "granted"


def test_only_the_matching_waiter_unblocks(backend):
    """An approval for request A must not unblock an agent waiting on B."""
    import threading

    st = ApprovalStream(backend)
    req_a = backend.create_request("action_a", "c", requested_by="agent-A")
    req_b = backend.create_request("action_b", "c", requested_by="agent-B")

    outcome = {}

    def waiter_b():
        try:
            outcome["b"] = st.wait_for_decision(req_b.id, timeout_s=0.4, poll_s=0.01)
        except TimeoutError:
            outcome["b"] = "timeout"

    tb = threading.Thread(target=waiter_b)
    tb.start()
    # Grant A only — B's waiter must keep waiting.
    backend.grant(req_a.id, decided_by="human")
    st.notify_changed()
    tb.join(timeout=3)
    assert outcome["b"] == "timeout"  # stayed blocked
    # Now granting B unblocks it promptly.
    backend.grant(req_b.id, decided_by="human")
    st.notify_changed()
    res = st.wait_for_decision(req_b.id, timeout_s=2, poll_s=0.01)
    assert res["state"] == "granted"


def test_deny_terminates_waiter(backend):
    import threading

    st = ApprovalStream(backend)
    req = backend.create_request("x", "c", requested_by="a")
    out = {}

    def w():
        out["r"] = st.wait_for_decision(req.id, timeout_s=5, poll_s=0.01)

    t = threading.Thread(target=w)
    t.start()
    backend.deny(req.id, decided_by="human")
    st.notify_changed()
    t.join(timeout=5)
    assert out["r"]["state"] == "denied"


def test_unknown_approval_raises(backend):
    from policy.approvals import ApprovalError

    st = ApprovalStream(backend)
    with pytest.raises(ApprovalError):
        st.wait_for_decision("does-not-exist", timeout_s=0.2)


def test_timeout_raises_while_pending(backend):
    st = ApprovalStream(backend)
    req = backend.create_request("x", "c", requested_by="a")
    with pytest.raises(TimeoutError):
        st.wait_for_decision(req.id, timeout_s=0.15, poll_s=0.01)


# --- decisions go through the audited path ------------------------------------------


def test_stream_decisions_are_audited(backend):
    st = ApprovalStream(backend)
    req = backend.create_request("active_testing", "c", requested_by="a")
    backend.grant(req.id, decided_by="human-1", decision_reason="ok")
    st.notify_changed()
    entries = backend.audit.entries()
    assert any(
        e.get("event_type") == "approval_granted" or "granted" in str(e.get("event_type", ""))
        for e in entries
    )


def test_expiry_tick_thread_pushes(tmp_path):
    fixed = datetime.now(UTC)

    class DT:
        def __init__(self):
            self.now = fixed

        def __call__(self):
            return self.now

    dt = DT()
    be = ApprovalBackend(AuditLog(tmp_path / "a.jsonl"), clock=dt)
    mono = FakeClock()
    st = ApprovalStream(be, expiry_tick_s=0.05, clock=mono)
    req = be.create_request("x", "c", requested_by="a", ttl_seconds=10)
    before = st.snapshot()["revision"]
    st.start_ticker()
    try:
        dt.now = fixed + timedelta(seconds=60)
        import time as _t

        _t.sleep(0.3)
        assert st.snapshot()["revision"] > before
        assert be.get(req.id).state is RequestState.EXPIRED
    finally:
        st.stop_ticker()
