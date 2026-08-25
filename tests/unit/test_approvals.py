"""Unit tests for policy/approvals.py (issue #85, PLAN §2.5/§13/§15/§17)."""

from datetime import UTC, datetime, timedelta

import pytest

from policy.approvals import ApprovalBackend, ApprovalError, RequestState
from policy.audit import AuditLog


@pytest.fixture()
def backend(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    return ApprovalBackend(log)


def test_full_lifecycle_pending_grant_execute(backend):
    req = backend.create_request("active_testing", "campaign-1", requested_by="agent-1")
    assert req.state is RequestState.PENDING
    with pytest.raises(ApprovalError):
        backend.check(req.id)  # not granted yet
    backend.grant(req.id, decided_by="human", decision_reason="ok")
    assert backend.check(req.id) is req
    backend.use(req.id)
    # single-use default: consumed after execution
    with pytest.raises(ApprovalError):
        backend.check(req.id)


def test_denied_request_blocks(backend):
    req = backend.create_request("external_submission", "f-1", requested_by="agent-1")
    backend.deny(req.id, decided_by="human")
    with pytest.raises(ApprovalError):
        backend.check(req.id)
    # denial is final; re-granting a denied request is impossible
    with pytest.raises(ApprovalError):
        backend.grant(req.id, decided_by="human")


def test_expiry_blocks_retroactive_application():
    fixed = datetime.now(UTC)

    class FakeClock:
        def __init__(self):
            self.now = fixed

        def __call__(self):
            return self.now

    clock = FakeClock()
    backend = ApprovalBackend(AuditLog("/tmp/approval-test-audit.jsonl"), clock=clock)
    req = backend.create_request("scope_change", "c-1", "agent-1", ttl_seconds=60)
    clock.now = fixed + timedelta(seconds=120)
    with pytest.raises(ApprovalError):  # expired even though never granted
        backend.check(req.id)
    assert req.state is RequestState.EXPIRED
    # expired grants cannot be applied retroactively — must re-request
    with pytest.raises(ApprovalError):
        backend.grant(req.id, decided_by="late-human")


def test_granted_request_expires_if_unused(backend):
    # default ttl 24h: simulate by creating with tiny ttl
    req = backend.create_request("finding_deletion", "f-9", "agent-1", ttl_seconds=1)
    from time import sleep

    sleep(1.1)
    backend.grant(req.id, decided_by="h")  # granted after expiry moment
    with pytest.raises(ApprovalError):  # lazy expiry wins over stale grant
        backend.check(req.id)


def test_supersession_replaces_pending_duplicate(backend):
    r1 = backend.create_request("active_testing", "c-1", "agent-1")
    r2 = backend.create_request("active_testing", "c-1", "agent-2")
    assert r1.state is RequestState.SUPERSEDED
    assert r1.superseded_by == r2.id
    assert [r.id for r in backend.pending()] == [r2.id]
    # superseded request can no longer be decided
    with pytest.raises(ApprovalError):
        backend.grant(r1.id, decided_by="h")


def test_multi_use_grant_allows_repeated_execution(backend):
    req = backend.create_request("poc_execution_live_target", "t-1", "agent-1", single_use=False)
    backend.grant(req.id, decided_by="h")
    for _ in range(3):
        backend.check(req.id)
        backend.use(req.id)
    assert req.state is RequestState.GRANTED


def test_audit_completeness_every_transition_logged(backend, tmp_path):
    log = backend.audit
    req = backend.create_request("active_testing", "c-2", "agent-1", policy_rule="gate.active")
    backend.deny(req.id, decided_by="human")
    r2 = backend.create_request("active_testing", "c-2", "agent-1")
    backend.grant(r2.id, decided_by="human")
    try:
        backend.check(r2.id)
        backend.use(r2.id)
    except ApprovalError:
        pass

    types = [e["event_type"] for e in log.entries()]
    # r1: requested → denied. r2 replaces nothing (r1 already decided),
    # so its chain is requested → granted → executed.
    assert types == [
        "approval_requested",
        "approval_denied",
        "approval_requested",
        "approval_granted",
        "gated_action_executed",
    ]
    # every audit record carries approval id + action + subject
    for e in log.entries():
        assert e["payload"]["approval_id"]
        assert e["payload"]["action"]
        assert e["payload"]["subject"]


def test_no_gated_action_executes_without_grant(backend):
    req = backend.create_request("active_testing", "c-3", "agent-1")
    executed = False
    try:
        backend.check(req.id)
        backend.use(req.id)
        executed = True
    except ApprovalError:
        backend.blocked_event("active_testing", "c-3", f"approval {req.id} pending")
    assert not executed
    blocked = [e for e in backend.audit.entries() if e["event_type"] == "gated_action_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["payload"]["why"].startswith("approval")


def test_sweep_expires_past_due_requests(backend):
    r1 = backend.create_request("active_testing", "s-1", "a", ttl_seconds=0)
    r2 = backend.create_request("active_testing", "s-2", "a")  # 24h ttl, stays pending
    swept = {r.id for r in backend.sweep_expired()}
    assert r1.id in swept or r1.state is RequestState.EXPIRED
    assert r2.state is RequestState.PENDING
