"""Kill-switch durability & restart-stays-killed tests (PLAN §15; issue #65).

Covers the guarantees #65 adds on top of the process-local switch:
- persisted engagement survives process restart (new instance starts active)
- crash windows cannot produce a silently re-armed system (disk wins, and a
  corrupt state file fails closed)
- rearm is operator-explicit, audited via Controls, and actually clears
- policy-layer integration: gated actions refused after restart-while-killed
"""

from __future__ import annotations

import json

import pytest

from policy.audit import AuditLog
from policy.controls import Controls
from policy.durable_kill_switch import DurableKillSwitch
from policy.kill_switch import KillSwitchActive


@pytest.fixture
def switch(tmp_path):
    return DurableKillSwitch(tmp_path / "kill" / "state.json")


def test_fresh_install_persists_disengaged_baseline(switch, tmp_path):
    data = json.loads((tmp_path / "kill" / "state.json").read_text())
    assert data["engaged"] is False


def test_activate_persists_and_restart_stays_killed(tmp_path):
    s1 = DurableKillSwitch(tmp_path / "state.json")
    assert not s1.active
    s1.activate(reason="operator panic")

    # Simulate full process restart: brand-new instance, same state file.
    s2 = DurableKillSwitch(tmp_path / "state.json")
    assert s2.active
    assert s2.reason == "operator panic"
    with pytest.raises(KillSwitchActive):
        s2.check("network_action")


def test_rearm_clears_state_and_allows_new_actions(tmp_path):
    s = DurableKillSwitch(tmp_path / "state.json")
    s.activate("test")
    assert s.rearm(actor="op") is True
    restarted = DurableKillSwitch(tmp_path / "state.json")
    assert not restarted.active
    restarted.check()  # no raise


def test_rearm_when_not_engaged_is_reported(tmp_path):
    s = DurableKillSwitch(tmp_path / "state.json")
    assert s.rearm() is False
    s.activate("x")
    s.rearm()
    assert s.rearm() is False  # second re-arm: nothing left to clear


def test_corrupt_state_file_fails_closed(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not json at all")
    s = DurableKillSwitch(path)
    assert s.active  # fail closed, never silently re-armed
    assert "corrupt" in s.reason


def test_deactivate_is_disabled_on_durable_switch(switch):
    switch.activate("x")
    with pytest.raises(RuntimeError, match="rearm"):
        switch.deactivate()


def test_activation_callbacks_not_rerun_on_restart(tmp_path):
    s1 = DurableKillSwitch(tmp_path / "state.json")
    calls = []
    s1.on_activate(lambda reason: calls.append(reason))
    s1.activate("boom")
    assert calls == ["boom"]

    s2 = DurableKillSwitch(tmp_path / "state.json")
    s2.on_activate(lambda reason: calls.append("restart-callback"))
    assert s2.active
    assert calls == ["boom"]  # no callbacks fired for restored latch


# --- Controls integration ----------------------------------------------------


def _controls(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    ks = DurableKillSwitch(tmp_path / "state.json")
    return Controls(audit_log=audit, kill_switch=ks)


def test_controls_activate_is_durable_and_audited(tmp_path):
    c1 = _controls(tmp_path)
    c1.activate_kill_switch(actor="alice", reason="incident")

    # Restart: fresh Controls over same files must come up killed.
    c2 = _controls(tmp_path)
    assert c2.kill_switch.active

    entries = AuditLog(tmp_path / "audit.jsonl").entries()
    kinds = [e["event_type"] for e in entries]
    assert "kill_switch_activate" in kinds


def test_controls_rearm_is_audited_with_actor(tmp_path):
    c = _controls(tmp_path)
    c.activate_kill_switch(actor="alice", reason="drill")
    n_before = len(AuditLog(tmp_path / "audit.jsonl").entries())
    c.rearm_kill_switch(actor="bob")
    entries = AuditLog(tmp_path / "audit.jsonl").entries()
    last = entries[-1]
    assert last["event_type"] == "kill_switch_rearm"
    assert last["actor"] == "bob"
    assert len(entries) == n_before + 1
    assert not c.kill_switch.active


def test_policy_gate_blocks_after_restart_while_killed(tmp_path):
    """Defense-in-depth requirement (#65 item 4): even after a full process
    restart, any action routed through gate()/check() is refused."""
    s1 = DurableKillSwitch(tmp_path / "state.json")
    s1.activate("halt")
    del s1

    @DurableKillSwitch(tmp_path / "state.json").gate
    def send_request():
        return "sent"

    with pytest.raises(KillSwitchActive):
        send_request()
