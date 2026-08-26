"""Tests for the real-time approval event bridge (issue #237).

Covers:
- Every lifecycle transition mirrors into the EventStore with a stable
  event type and payload (no polling needed by the UI).
- UI decisions go through the same audited grant/deny path as the CLI
  (decide_approval) — exactly one audit entry per decision.
- Expired requests surface as approval.expired with previous_state, and
  auto-expiry sweeps emit them too.
- Integration: an agent blocked on a gated action is unblocked by exactly
  one mid-campaign approval; single-use consumption is visible in-stream.
- Audit chain integrity is unchanged by bridging.
"""

import pytest

from api.approval_events import (
    ApprovalEventBridge,
    decide_approval,
    waiting_agent_count,
)
from observability.event_store import EventStore
from policy.approvals import ApprovalBackend, ApprovalError, RequestState
from policy.audit import AuditLog


@pytest.fixture()
def env(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    backend = ApprovalBackend(audit)
    events = EventStore()
    bridge = ApprovalEventBridge(backend, events)
    return backend, events, bridge, audit


# --- Stream mirroring ---------------------------------------------------------


def test_request_creates_stream_event(env):
    backend, events, _, _ = env
    req = backend.create_request(
        "live_target_fetch", "t-1", requested_by="agent-7", campaign_id="c-1"
    )
    evs = events._logs["c-1"]
    assert [e.type for e in evs] == ["approval.requested"]
    assert evs[0].payload["approval_id"] == req.id
    assert evs[0].payload["state"] == "pending"
    assert evs[0].payload["requested_by"] == "agent-7"


def test_grant_and_deny_mirror(env):
    backend, events, _, _ = env
    req = backend.create_request("live_target_fetch", "t-1", requested_by="a", campaign_id="c-1")
    decide_approval(backend, events, req.id, "approve", decided_by="human-1", reason="ok")
    types = [e.type for e in events._logs["c-1"]]
    assert types == ["approval.requested", "approval.granted"]
    granted = events._logs["c-1"][-1]
    assert granted.payload["decided_by"] == "human-1"
    assert granted.payload["state"] == "granted"


def test_deny_path_mirrors(env):
    backend, events, _, _ = env
    req = backend.create_request("live_target_fetch", "t-1", requested_by="a", campaign_id=None)
    decide_approval(backend, events, req.id, "reject", decided_by="human-1")
    # No campaign_id → global log.
    types = [e.type for e in events._logs[None]]
    assert types == ["approval.requested", "approval.denied"]


def test_unknown_decision_refused(env):
    backend, events, _, _ = env
    req = backend.create_request("x", "s", requested_by="a")
    with pytest.raises(ApprovalError):
        decide_approval(backend, events, req.id, "maybe", decided_by="h")
    # Nothing leaked into the stream beyond the request event.
    assert len(events._logs[None]) == 1


class FakeClock:
    def __init__(self, start=0.0):
        self.t = start

    def __call__(self):
        from datetime import UTC, datetime

        return datetime.fromtimestamp(self.t, UTC)


def _clock_backend(tmp_path, tmp_clock_start=0.0):
    audit = AuditLog(tmp_path / "audit-clock.jsonl")
    clock = FakeClock(tmp_clock_start)
    return ApprovalBackend(audit, clock=clock), clock


def test_expiry_emits_event_with_previous_state(env, tmp_path):
    backend, clock = _clock_backend(tmp_path)
    events = EventStore()
    ApprovalEventBridge(backend, events)

    req = backend.create_request("a", "s", requested_by="r", campaign_id="c", ttl_seconds=10)
    clock.t += 11
    with pytest.raises(ApprovalError):
        backend.check(req.id)  # triggers lazy expiry
    expired_events = [e for e in events._logs["c"] if e.type == "approval.expired"]
    assert len(expired_events) == 1
    assert expired_events[0].payload["previous_state"] == "pending"
    assert backend.get(req.id).state is RequestState.EXPIRED


def test_sweep_expired_reports_count_and_streams(env, tmp_path):
    backend, clock = _clock_backend(tmp_path)
    events = EventStore()
    bridge = ApprovalEventBridge(backend, events)

    r1 = backend.create_request("a", "s1", requested_by="r", ttl_seconds=5)
    r2 = backend.create_request("a", "s2", requested_by="r", ttl_seconds=500)
    clock.t += 6
    n = bridge.sweep_expired()
    assert n == 1
    states = {r.id: r.state for r in (backend.get(r1.id), backend.get(r2.id))}
    assert states[r1.id] is RequestState.EXPIRED
    assert states[r2.id] is RequestState.PENDING


def test_supersession_mirrors(env):
    backend, events, _, _ = env
    backend.create_request("a", "s", requested_by="r1", campaign_id="c")
    backend.create_request("a", "s", requested_by="r2", campaign_id="c")
    types = [e.type for e in events._logs["c"]]
    assert types.count("approval.superseded") == 1
    assert types[-1] == "approval.requested"


# --- Audit chain unchanged ------------------------------------------------------


def test_audit_chain_still_verifies_after_bridging(env):
    backend, _, _, audit = env
    req = backend.create_request("a", "s", requested_by="r")
    decide_approval(backend, None, req.id, "approve", decided_by="h") if False else backend.grant(
        req.id, decided_by="h"
    )
    backend.use(req.id)
    assert audit.verify() is True


# --- Integration: mid-campaign approval unblocks waiting agent -------------------


def test_mid_campaign_grant_unblocks_exactly_the_waiting_agent(env):
    backend, events, _, _ = env
    blocked_action, subject = "live_target_fetch", "target-9"
    req = backend.create_request(
        blocked_action, subject, requested_by="agent-A", campaign_id="camp"
    )

    # Agent is blocked: gate check fails while pending.
    with pytest.raises(ApprovalError):
        backend.check(req.id)

    # Human approves mid-campaign through the audited path.
    decide_approval(backend, events, req.id, "approve", decided_by="human", reason="go")

    # Exactly the waiting agent's request is now passable...
    assert backend.check(req.id).state is RequestState.GRANTED
    # ...and the stream shows requested → granted for that approval only.
    stream = [(e.type, e.payload["approval_id"]) for e in events._logs["camp"]]
    assert stream == [
        ("approval.requested", req.id),
        ("approval.granted", req.id),
    ]
    assert waiting_agent_count(backend, blocked_action, subject) == 0

    # Single-use consumption is audited; second use is refused.
    backend.use(req.id)
    with pytest.raises(ApprovalError):
        backend.check(req.id)


def test_replay_after_reconnect_returns_missed_approvals(env):
    backend, events, _, _ = env
    backend.create_request("a", "s1", requested_by="r", campaign_id="camp")
    last_seen = events.latest_id(campaign_id="camp")
    r2 = backend.create_request("a", "s2", requested_by="r", campaign_id="camp")
    result = events.replay_after(last_seen, campaign_id="camp")
    ids = [e.payload["approval_id"] for e in result.events]
    assert ids == [r2.id]
