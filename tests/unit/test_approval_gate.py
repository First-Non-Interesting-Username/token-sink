"""Tests for the agent-side approval & intervention gate (issue #249, PLAN §3.1)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from orchestrator.approval_gate import ApprovalGate, GateDenied, InterventionPoint
from policy.audit import AuditLog
from policy.controls import Controls
from policy.kill_switch import KillSwitch


@pytest.fixture()
def controls(tmp_path: Path) -> Controls:
    return Controls(audit_log=AuditLog(tmp_path / "audit.jsonl"), kill_switch=KillSwitch())


CAMP = "c-1"
AGENT = "11111111-1111-1111-1111-111111111111"
HUMAN = "human-operator"


def _request(controls, action="active_testing", subject=CAMP):
    return controls.request_approval(action, subject, requested_by=AGENT)


# --- blocking gate ----------------------------------------------------------


def test_gate_blocks_until_granted_then_proceeds(controls):
    gate = ApprovalGate(controls)
    req = _request(controls)

    def decide():
        time.sleep(0.05)
        controls.decide_approval(req.id, granted=True, decided_by=HUMAN)
        gate.notify(req.id)

    t = threading.Thread(target=decide)
    t.start()
    got = gate.wait(req.id, timeout_seconds=2.0)
    t.join()
    assert got.id == req.id and got.status == "granted"


def test_gate_denied_when_operator_denies(controls):
    gate = ApprovalGate(controls)
    req = _request(controls)

    def decide():
        time.sleep(0.05)
        controls.decide_approval(
            req.id, granted=False, decided_by=HUMAN, decision_reason="too risky"
        )
        gate.notify(req.id)

    t = threading.Thread(target=decide)
    t.start()
    with pytest.raises(GateDenied, match="denied"):
        gate.wait(req.id, timeout_seconds=2.0)
    t.join()


def test_gate_timeout_when_undecided(controls):
    gate = ApprovalGate(controls)
    req = _request(controls)
    with pytest.raises(TimeoutError):
        gate.wait(req.id, timeout_seconds=0.15)


# --- intervention beats a stale grant ---------------------------------------


def test_kill_switch_activation_interrupts_wait_even_after_grant(controls):
    gate = ApprovalGate(controls)
    req = _request(controls)

    outcome = {}

    def wait():
        try:
            gate.wait(req.id, timeout_seconds=3.0)
            outcome["result"] = "proceeded"
        except GateDenied as exc:
            outcome["result"] = f"denied: {exc}"

    t = threading.Thread(target=wait)
    t.start()
    time.sleep(0.1)  # waiter is now blocked on the pending request
    controls.activate_kill_switch(actor=HUMAN, reason="emergency stop")
    # A grant arriving AFTER the kill switch is a stale grant and must not
    # unblock the gated action.
    controls.decide_approval(req.id, granted=True, decided_by=HUMAN)
    gate.notify(req.id)
    t.join(timeout=2.0)
    assert "denied" in outcome["result"]
    assert "kill switch" in outcome["result"]


def test_expired_request_never_proceeds(controls):
    gate = ApprovalGate(controls)
    req = _request(controls)
    req.status = "expired"  # simulate sweeper expiry (audited path owns this in prod)
    with pytest.raises(GateDenied):
        gate.wait(req.id, timeout_seconds=0.5)


# --- cooperative intervention checkpoints ------------------------------------


def test_intervention_point_stops_on_kill_switch(controls):
    controls.register_campaign(CAMP)
    ip = InterventionPoint(controls)
    ip.check(CAMP)  # no-op while healthy
    controls.activate_kill_switch(actor=HUMAN)
    with pytest.raises(GateDenied, match="kill switch"):
        ip.check(CAMP)


def test_intervention_point_stops_on_pause_and_stop(controls):
    controls.register_campaign(CAMP)
    ip = InterventionPoint(controls)
    controls.pause_campaign(CAMP, actor=HUMAN)
    with pytest.raises(GateDenied, match="paused"):
        ip.check(CAMP)
    controls.resume_campaign(CAMP, actor=HUMAN)
    ip.check(CAMP)
    controls.stop_campaign(CAMP, actor=HUMAN)
    with pytest.raises(GateDenied, match="stopped"):
        ip.check(CAMP)


def test_gated_action_requires_explicit_human_grant_end_to_end(controls):
    """The full path: request → block → grant → assert_approved passes."""
    gate = ApprovalGate(controls)
    req = gate.request(
        "external_submission",
        subject="finding-9",
        requested_by=AGENT,
        reason="submit report to vendor portal",
    )
    assert controls.pending_approvals()[0].id == req.id
    controls.decide_approval(req.id, granted=True, decided_by=HUMAN)
    gate.notify(req.id)
    assert gate.wait(req.id, timeout_seconds=1.0).status == "granted"
    # Audit trail proves both transitions happened.
    kinds = [e["event_type"] for e in controls.audit.entries()]
    assert "approval_request" in kinds and "approval_grant" in kinds
