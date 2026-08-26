"""Human-control operations (PLAN.md §2.5, §15).

Covers: global kill switch, per-campaign pause/resume/stop, per-agent
cancel/retry, finding quarantine, and approval gates for the actions that
require explicit human confirmation. Every control action emits an auditable
record via the hash-chained AuditLog.

This module is deliberately storage-agnostic: it coordinates state via small
pluggable callbacks so the orchestrator (#7 storage, #12 runtime) can wire in
its own persistence without this layer depending on it.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field


class ControlError(RuntimeError):
    """Raised when a control action is invalid in the current state."""


class ControlAction(enum.StrEnum):
    KILL_SWITCH_ACTIVATE = "kill_switch_activate"
    KILL_SWITCH_REARM = "kill_switch_rearm"
    CAMPAIGN_PAUSE = "campaign_pause"
    CAMPAIGN_RESUME = "campaign_resume"
    CAMPAIGN_STOP = "campaign_stop"
    AGENT_CANCEL = "agent_cancel"
    AGENT_RETRY = "agent_retry"
    FINDING_QUARANTINE = "finding_quarantine"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_GRANT = "approval_grant"
    APPROVAL_DENY = "approval_deny"


# Actions that PLAN.md §2.5 requires human approval before execution.
APPROVAL_REQUIRED_ACTIONS = frozenset(
    {
        "active_testing",
        "poc_execution_live_target",
        "external_submission",
        "finding_deletion",
        "scope_change",
    }
)


@dataclass
class ApprovalRequest:
    id: str
    action: str  # one of APPROVAL_REQUIRED_ACTIONS
    subject: str  # campaign/finding/agent UUID the action applies to
    requested_by: str
    reason: str = ""
    status: str = "pending"  # pending | granted | denied
    decided_by: str = ""
    decision_reason: str = ""


@dataclass
class CampaignState:
    """Minimal control state for one campaign. The orchestrator owns richer
    state; this tracks only what the control surface needs."""

    campaign_uuid: str
    running: bool = True
    stopped: bool = False

    # Agents and findings registered by the runtime; keyed by UUID.
    agents: dict = field(default_factory=dict)  # uuid -> {"status": str, ...}
    findings: dict = field(default_factory=dict)  # uuid -> {"state": str, ...}


class Controls:
    """Human-control surface. All mutating methods write an audit record."""

    def __init__(self, audit_log, kill_switch):
        self.audit = audit_log
        self.kill_switch = kill_switch
        self._campaigns: dict[str, CampaignState] = {}
        self._approvals: dict[str, ApprovalRequest] = {}

    # -- registration -----------------------------------------------------

    def register_campaign(self, campaign_uuid: str) -> CampaignState:
        st = CampaignState(campaign_uuid=campaign_uuid)
        self._campaigns[campaign_uuid] = st
        return st

    def register_agent(self, campaign_uuid: str, agent_uuid: str) -> None:
        st = self._require_campaign(campaign_uuid)
        if agent_uuid not in st.agents:
            st.agents[agent_uuid] = {"status": "created"}

    def register_finding(self, campaign_uuid: str, finding_uuid: str) -> None:
        st = self._require_campaign(campaign_uuid)
        if finding_uuid not in st.findings:
            st.findings[finding_uuid] = {"state": "initial_findings"}

    def _require_campaign(self, campaign_uuid: str) -> CampaignState:
        try:
            return self._campaigns[campaign_uuid]
        except KeyError:
            raise ControlError(f"unknown campaign {campaign_uuid}") from None

    # -- kill switch ------------------------------------------------------

    def activate_kill_switch(self, actor: str = "", reason: str = "") -> int:
        """Engage the switch AND cancel all active tasks. Returns cancelled count."""
        flipped = self.kill_switch.activate(reason=reason or f"by {actor}")
        n = self.kill_switch.cancel_active_tasks()
        self.audit.append(
            ControlAction.KILL_SWITCH_ACTIVATE.value,
            {"reason": reason, "tasks_cancelled": n, "newly_flipped": flipped},
            actor=actor,
        )
        return n

    def rearm_kill_switch(self, actor: str = "") -> bool:
        """Operator-explicit re-arm after a kill. Audited with actor identity
        (#65 item 5). Returns True if an engagement was actually cleared."""
        cleared = self.kill_switch.rearm(actor=actor)
        self.audit.append(ControlAction.KILL_SWITCH_REARM.value, {"cleared": cleared}, actor=actor)
        return cleared

    # -- campaign controls -------------------------------------------------

    def pause_campaign(self, campaign_uuid: str, actor: str = "") -> None:
        st = self._require_campaign(campaign_uuid)
        if st.stopped:
            raise ControlError("cannot pause a stopped campaign")
        st.running = False
        self.audit.append(
            ControlAction.CAMPAIGN_PAUSE.value, {"campaign": campaign_uuid}, actor=actor
        )

    def resume_campaign(self, campaign_uuid: str, actor: str = "") -> None:
        st = self._require_campaign(campaign_uuid)
        if st.stopped:
            raise ControlError("cannot resume a stopped campaign")
        if self.kill_switch.active:
            raise ControlError("cannot resume while kill switch is engaged")
        st.running = True
        self.audit.append(
            ControlAction.CAMPAIGN_RESUME.value, {"campaign": campaign_uuid}, actor=actor
        )

    def stop_campaign(self, campaign_uuid: str, actor: str = "") -> None:
        st = self._require_campaign(campaign_uuid)
        st.running = False
        st.stopped = True
        self.audit.append(
            ControlAction.CAMPAIGN_STOP.value, {"campaign": campaign_uuid}, actor=actor
        )

    # -- agent controls ----------------------------------------------------

    def cancel_agent(self, campaign_uuid: str, agent_uuid: str, actor: str = "") -> None:
        st = self._require_campaign(campaign_uuid)
        agent = st.agents.get(agent_uuid)
        if agent is None:
            raise ControlError(f"unknown agent {agent_uuid}")
        if agent["status"] in ("completed", "cancelled"):
            raise ControlError(f"agent {agent_uuid} already terminal ({agent['status']})")
        agent["status"] = "cancelled"
        self.audit.append(
            ControlAction.AGENT_CANCEL.value,
            {"campaign": campaign_uuid, "agent": agent_uuid},
            actor=actor,
        )
        # Cancellation propagates to subagents (§6): any agent whose parent is
        # this agent is cancelled transitively.
        self._cancel_descendants(st, agent_uuid, actor)

    def _cancel_descendants(self, st: CampaignState, parent_uuid: str, actor: str) -> int:
        cancelled = 0
        frontier = [parent_uuid]
        while frontier:
            current = frontier.pop()
            for uid, info in st.agents.items():
                if info.get("parent") == current and info["status"] not in (
                    "completed",
                    "cancelled",
                ):
                    info["status"] = "cancelled"
                    cancelled += 1
                    self.audit.append(
                        ControlAction.AGENT_CANCEL.value,
                        {
                            "campaign": st.campaign_uuid,
                            "agent": uid,
                            "propagated_from": parent_uuid,
                        },
                        actor=actor,
                    )
                    frontier.append(uid)
        return cancelled

    def retry_agent(self, campaign_uuid: str, agent_uuid: str, actor: str = "") -> str:
        """Retry a failed/cancelled agent as a NEW task attempt; returns new task id."""
        st = self._require_campaign(campaign_uuid)
        agent = st.agents.get(agent_uuid)
        if agent is None:
            raise ControlError(f"unknown agent {agent_uuid}")
        if agent["status"] == "running":
            raise ControlError("cannot retry a running agent")
        if self.kill_switch.active:
            self.kill_switch.check("agent_retry")
        new_task = str(uuid.uuid4())
        agent["status"] = "queued"
        agent["retry_of"] = new_task
        self.audit.append(
            ControlAction.AGENT_RETRY.value,
            {"campaign": campaign_uuid, "agent": agent_uuid, "task": new_task},
            actor=actor,
        )
        return new_task

    # -- finding quarantine -------------------------------------------------

    def quarantine_finding(
        self, campaign_uuid: str, finding_uuid: str, actor: str = "", reason: str = ""
    ) -> None:
        """Quarantine path used by four-agent review all-reject (PLAN §10.5).

        Quarantine is NOT deletion — history is preserved with a tombstone flag.
        """
        st = self._require_campaign(campaign_uuid)
        finding = st.findings.get(finding_uuid)
        if finding is None:
            raise ControlError(f"unknown finding {finding_uuid}")
        finding["state"] = "quarantined"
        finding["tombstone"] = False
        self.audit.append(
            ControlAction.FINDING_QUARANTINE.value,
            {"campaign": campaign_uuid, "finding": finding_uuid, "reason": reason},
            actor=actor,
        )

    # -- approval gates -----------------------------------------------------

    def request_approval(
        self, action: str, subject: str, requested_by: str, reason: str = ""
    ) -> ApprovalRequest:
        if action not in APPROVAL_REQUIRED_ACTIONS:
            raise ControlError(f"action '{action}' does not require an approval gate")
        req = ApprovalRequest(
            id=str(uuid.uuid4()),
            action=action,
            subject=subject,
            requested_by=requested_by,
            reason=reason,
        )
        self._approvals[req.id] = req
        self.audit.append(
            ControlAction.APPROVAL_REQUEST.value,
            {"action": action, "subject": subject, "approval_id": req.id},
            actor=requested_by,
        )
        return req

    def decide_approval(
        self, approval_id: str, granted: bool, decided_by: str, decision_reason: str = ""
    ) -> ApprovalRequest:
        req = self._approvals.get(approval_id)
        if req is None:
            raise ControlError(f"unknown approval {approval_id}")
        if req.status != "pending":
            raise ControlError(f"approval {approval_id} already decided ({req.status})")
        req.status = "granted" if granted else "denied"
        req.decided_by = decided_by
        req.decision_reason = decision_reason
        self.audit.append(
            (ControlAction.APPROVAL_GRANT if granted else ControlAction.APPROVAL_DENY).value,
            {
                "approval_id": approval_id,
                "action": req.action,
                "subject": req.subject,
                "decision_reason": decision_reason,
            },
            actor=decided_by,
        )
        return req

    def assert_approved(self, approval_id: str) -> ApprovalRequest:
        """Gate check: the guarded action may proceed only if granted."""
        req = self._approvals.get(approval_id)
        if req is None:
            raise ControlError(f"unknown approval {approval_id}")
        if self.kill_switch.active:
            self.kill_switch.check(req.action)
        if req.status != "granted":
            raise ControlError(
                f"action '{req.action}' blocked: approval is '{req.status}', "
                "explicit human grant required"
            )
        return req

    # CLI/API read surface --------------------------------------------------

    def pending_approvals(self) -> list[ApprovalRequest]:
        return [r for r in self._approvals.values() if r.status == "pending"]

    def campaign_state(self, campaign_uuid: str) -> CampaignState:
        return self._require_campaign(campaign_uuid)
