"""Unit tests for the human-control surface (issue #30, PLAN §2.5/§15)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from policy.audit import AuditLog
from policy.cli import run_cli
from policy.controls import ControlError, Controls
from policy.kill_switch import KillSwitch, KillSwitchActive


@pytest.fixture()
def controls(tmp_path: Path) -> Controls:
    return Controls(audit_log=AuditLog(tmp_path / "audit.jsonl"), kill_switch=KillSwitch())


def _campaign(controls: Controls) -> str:
    controls.register_campaign("c-1")
    return "c-1"


# --- kill switch -----------------------------------------------------------


def test_kill_switch_blocks_network_action_after_activation():
    ks = KillSwitch()

    @ks.gate
    def fetch_url(url):  # stand-in for any network egress path
        return "payload"

    assert fetch_url("https://example.com") == "payload"
    ks.activate(reason="incident")
    with pytest.raises(KillSwitchActive):
        fetch_url("https://example.com")


def test_kill_switch_cancels_registered_active_tasks():
    ks = KillSwitch()
    cancelled = []
    ks.on_activate(lambda reason: cancelled.append("task-a"))
    ks.on_activate(lambda reason: cancelled.append("task-b"))
    # One hook raising must not prevent the other from running (fail-safe).
    ks.on_activate(lambda reason: (_ for _ in ()).throw(RuntimeError("hook boom")))
    n = ks.cancel_active_tasks()
    assert cancelled == ["task-a", "task-b"]
    assert n == 3


def test_kill_switch_is_latched_and_requires_explicit_reset():
    ks = KillSwitch()
    ks.activate()
    ks.deactivate()  # operator action only — no auto-reset exists
    assert not ks.active
    ks.activate()
    with pytest.raises(KillSwitchActive):
        ks.check()


def test_controls_resume_blocked_while_kill_switch_engaged(controls):
    camp = _campaign(controls)
    controls.pause_campaign(camp)
    controls.activate_kill_switch(actor="human")
    with pytest.raises(ControlError):
        controls.resume_campaign(camp)


# --- campaign controls -------------------------------------------------------


def test_pause_resume_stop_lifecycle(controls):
    camp = _campaign(controls)
    st = controls.campaign_state(camp)
    controls.pause_campaign(camp)
    assert not st.running
    controls.resume_campaign(camp)
    assert st.running
    controls.stop_campaign(camp)
    assert st.stopped and not st.running
    with pytest.raises(ControlError):
        controls.pause_campaign(camp)


def test_cannot_resume_stopped_campaign(controls):
    camp = _campaign(controls)
    controls.stop_campaign(camp)
    with pytest.raises(ControlError):
        controls.resume_campaign(camp)


# --- agent cancellation + propagation ----------------------------------------


def test_cancel_agent_propagates_to_subagents(controls):
    camp = _campaign(controls)
    controls.register_agent(camp, "parent")
    controls.register_agent(camp, "child")
    controls.register_agent(camp, "grandchild")
    controls.campaign_state(camp).agents["child"]["parent"] = "parent"
    controls.campaign_state(camp).agents["grandchild"]["parent"] = "child"

    controls.cancel_agent(camp, "parent")
    statuses = {u: a["status"] for u, a in controls.campaign_state(camp).agents.items()}
    assert statuses == {"parent": "cancelled", "child": "cancelled", "grandchild": "cancelled"}


def test_cancel_terminal_agent_rejected(controls):
    camp = _campaign(controls)
    controls.register_agent(camp, "a1")
    controls.campaign_state(camp).agents["a1"]["status"] = "completed"
    with pytest.raises(ControlError):
        controls.cancel_agent(camp, "a1")


def test_retry_agent_mints_new_task_and_requeues(controls):
    camp = _campaign(controls)
    controls.register_agent(camp, "a1")
    controls.cancel_agent(camp, "a1")
    new_task = controls.retry_agent(camp, "a1")
    assert new_task
    assert controls.campaign_state(camp).agents["a1"]["status"] == "queued"


def test_retry_running_agent_rejected(controls):
    camp = _campaign(controls)
    controls.register_agent(camp, "a1")
    controls.campaign_state(camp).agents["a1"]["status"] = "running"
    with pytest.raises(ControlError):
        controls.retry_agent(camp, "a1")


def test_retry_blocked_while_kill_switch_engaged(controls):
    camp = _campaign(controls)
    controls.register_agent(camp, "a1")
    controls.cancel_agent(camp, "a1")
    controls.activate_kill_switch()
    with pytest.raises(KillSwitchActive):
        controls.retry_agent(camp, "a1")


# --- quarantine ---------------------------------------------------------------


def test_quarantine_preserves_record_with_audit(controls):
    camp = _campaign(controls)
    controls.register_finding(camp, "f-1")
    controls.quarantine_finding(camp, "f-1", reason="all four reviewers rejected")
    finding = controls.campaign_state(camp).findings["f-1"]
    assert finding["state"] == "quarantined"
    # Quarantine is not deletion: record still present.
    assert "f-1" in controls.campaign_state(camp).findings


# --- approval gates -------------------------------------------------------------


def test_guarded_action_blocked_until_human_grants(controls):
    req = controls.request_approval(
        "poc_execution_live_target", subject="finding-9", requested_by="agent-1"
    )
    with pytest.raises(ControlError):
        controls.assert_approved(req.id)
    controls.decide_approval(req.id, granted=False, decided_by="human")
    with pytest.raises(ControlError):
        controls.assert_approved(req.id)
    # New request, this time granted by the human.
    req2 = controls.request_approval(
        "external_submission", subject="report-1", requested_by="agent-2"
    )
    controls.decide_approval(req2.id, granted=True, decided_by="human")
    assert controls.assert_approved(req2.id).status == "granted"


def test_approval_required_for_plan_listed_actions_only(controls):
    with pytest.raises(ControlError):
        controls.request_approval("web_search", subject="x", requested_by="agent-1")
    for action in ("active_testing", "external_submission", "finding_deletion", "scope_change"):
        controls.request_approval(action, subject="s", requested_by="a")


def test_double_decision_rejected(controls):
    req = controls.request_approval("active_testing", "s", "a")
    controls.decide_approval(req.id, granted=True, decided_by="h")
    with pytest.raises(ControlError):
        controls.decide_approval(req.id, granted=False, decided_by="h")


def test_granted_approval_invalid_while_kill_switch_engaged(controls):
    req = controls.request_approval("active_testing", "s", "a")
    controls.decide_approval(req.id, granted=True, decided_by="h")
    controls.activate_kill_switch()
    with pytest.raises(KillSwitchActive):
        controls.assert_approved(req.id)


# --- audit trail -----------------------------------------------------------------


def test_every_control_action_emits_audit_event(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    cs = Controls(audit_log=log, kill_switch=KillSwitch())
    cs.register_campaign("c-1")
    cs.register_agent("c-1", "a1")
    cs.register_finding("c-1", "f1")

    cs.pause_campaign("c-1", actor="op")
    cs.resume_campaign("c-1", actor="op")
    cs.cancel_agent("c-1", "a1", actor="op")
    cs.quarantine_finding("c-1", "f1", actor="op")
    req = cs.request_approval("active_testing", "s", "agent")
    cs.decide_approval(req.id, granted=False, decided_by="human")
    cs.activate_kill_switch(actor="op")

    types = [e["event_type"] for e in log.entries()]
    assert types == [
        "campaign_pause",
        "campaign_resume",
        "agent_cancel",
        "finding_quarantine",
        "approval_request",
        "approval_deny",
        "kill_switch_activate",
    ]
    assert all(e["actor"] for e in log.entries())
    assert log.verify()


def test_audit_chain_detects_tampering(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("campaign_pause", {"campaign": "c"})
    log.append("campaign_stop", {"campaign": "c"})

    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["payload"]["campaign"] = "forged"  # retroactive edit
    lines[0] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    assert not AuditLog(path).verify()


# --- CLI equivalents --------------------------------------------------------------


def test_cli_kill_switch_blocks_gated_actions(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    cs = Controls(audit_log=log, kill_switch=KillSwitch())
    out = io.StringIO()
    cs.register_campaign("c-1")
    cs.pause_campaign("c-1")

    assert run_cli(["kill-switch", "--reason", "drill"], cs, out=out) == 0
    out_json = json.loads(out.getvalue().strip().splitlines()[0])
    assert out_json == {"status": "engaged", "tasks_cancelled": 0}

    # Resume is blocked while the switch is engaged -> exit code 2 with error JSON.
    rc = run_cli(["campaign-resume", "c-1"], cs, out=out)
    assert rc == 2
    err = json.loads(out.getvalue().strip().splitlines()[-1])
    assert "kill switch" in err["error"]


def test_cli_cancel_and_retry_flow(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    cs = Controls(audit_log=log, kill_switch=KillSwitch())
    out = io.StringIO()
    cs.register_campaign("c-1")
    cs.register_agent("c-1", "a1")

    assert run_cli(["agent-cancel", "c-1", "a1"], cs, out=out) == 0
    assert run_cli(["agent-retry", "c-1", "a1"], cs, out=out) == 0
    retry_out = json.loads(out.getvalue().strip().splitlines()[-1])
    assert retry_out["status"] == "queued" and retry_out["task"]

    assert run_cli(["finding-quarantine", "c-1", "missing"], cs, out=out) == 2
    assert run_cli(["audit-verify"], cs, out=out) == 0
