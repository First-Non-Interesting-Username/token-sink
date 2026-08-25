"""Approval-request lifecycle backend (PLAN.md §2.5, §13 view 6, §15, §17).

Implements issue #85: the state machinery behind approval gates. The UI
(#22) and CLI (`policy/cli.py`) are thin surfaces over this backend.

Lifecycle::

    pending ──grant()──▶ granted (single-use grants consumed on use())
             pending ──deny()──▶ denied
             pending ──expire()/sweep_expired()──▶ expired
             pending ──superseded_by()──▶ superseded

Guarantees:
- Grants are scoped to one (action, subject) pair — never blanket.
- A grant may be single-use; executing the gated action consumes it.
- Expired/denied/superseded requests can never be applied retroactively;
  the action must re-request approval.
- Every transition AND every gated-action execution is written to the
  hash-chained AuditLog, so the audit trail proves no gated action ran
  without a live grant.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


class ApprovalError(RuntimeError):
    """Raised when an approval action is invalid in the current state."""


class RequestState(enum.StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"


class AuditEventType(enum.StrEnum):
    REQUESTED = "approval_requested"
    GRANTED = "approval_granted"
    DENIED = "approval_denied"
    EXPIRED = "approval_expired"
    SUPERSEDED = "approval_superseded"
    ACTION_EXECUTED = "gated_action_executed"
    BLOCKED = "gated_action_blocked"


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class ApprovalRequest:
    """One human-approval request, per issue #85 requirements."""

    id: str
    action: str  # one of policy.controls.APPROVAL_REQUIRED_ACTIONS
    subject: str  # campaign/finding/agent UUID the action applies to
    requested_by: str  # requesting agent UUID
    campaign_id: str = ""  # campaign UUID for attribution/filtering
    policy_rule: str = ""  # which gate/policy rule triggered the request
    payload_snapshot: dict = field(default_factory=dict)
    reason: str = ""
    created_at: datetime = field(default_factory=_now)
    expires_at: datetime | None = None
    single_use: bool = True  # default: one execution consumes the grant
    state: RequestState = RequestState.PENDING
    decided_by: str = ""
    decision_reason: str = ""
    superseded_by: str = ""

    def is_expired(self, at: datetime | None = None) -> bool:
        return self.expires_at is not None and (at or _now()) >= self.expires_at


class ApprovalBackend:
    """Owns approval requests end-to-end; all transitions audited."""

    def __init__(self, audit_log, clock=None):
        # audit_log: policy.audit.AuditLog (hash-chained). Injected rather
        # than constructed so tests can share one log with Controls.
        self.audit = audit_log
        self._clock = clock or _now
        self._requests: dict[str, ApprovalRequest] = {}

    # -- helpers -------------------------------------------------------------

    def _audit(self, event: AuditEventType, req: ApprovalRequest, extra: dict, actor: str) -> None:
        self.audit.append(
            event.value,
            {
                "approval_id": req.id,
                "action": req.action,
                "subject": req.subject,
                "state": req.state.value,
                **extra,
            },
            actor=actor,
        )

    def _live(self, req: ApprovalRequest) -> ApprovalRequest:
        """Lazily expire a past-due pending/granted request before any check."""
        if req.state in (RequestState.PENDING, RequestState.GRANTED) and req.is_expired(
            self._clock()
        ):
            prev = req.state
            req.state = RequestState.EXPIRED
            self._audit(
                AuditEventType.EXPIRED,
                req,
                {"reason": "ttl_elapsed", "previous_state": prev.value},
                actor="system",
            )
        return req

    # -- lifecycle -----------------------------------------------------------

    def create_request(
        self,
        action: str,
        subject: str,
        requested_by: str,
        campaign_id: str = "",
        policy_rule: str = "",
        payload_snapshot: dict | None = None,
        reason: str = "",
        ttl_seconds: int = 24 * 3600,
        single_use: bool = True,
    ) -> ApprovalRequest:
        """Create a pending request. A prior pending request for the same
        (action, subject) is superseded so exactly one live decision exists."""
        req = ApprovalRequest(
            id=str(uuid.uuid4()),
            action=action,
            subject=subject,
            requested_by=requested_by,
            campaign_id=campaign_id,
            policy_rule=policy_rule,
            payload_snapshot=dict(payload_snapshot or {}),
            reason=reason,
            created_at=self._clock(),
            expires_at=self._clock() + timedelta(seconds=ttl_seconds),
            single_use=single_use,
        )
        for other in self._requests.values():
            if (
                other.state is RequestState.PENDING
                and other.action == action
                and other.subject == subject
            ):
                other.state = RequestState.SUPERSEDED
                other.superseded_by = req.id
                self._audit(AuditEventType.SUPERSEDED, other, {"by": req.id}, actor=requested_by)
        self._requests[req.id] = req
        self._audit(
            AuditEventType.REQUESTED, req, {"requested_by": requested_by}, actor=requested_by
        )
        return req

    def grant(
        self, approval_id: str, decided_by: str, decision_reason: str = ""
    ) -> ApprovalRequest:
        req = self._require(approval_id)
        if req.state is not RequestState.PENDING:
            raise ApprovalError(
                f"approval {approval_id} is '{req.state.value}', only pending can be granted"
            )
        req.state = RequestState.GRANTED
        req.decided_by = decided_by
        req.decision_reason = decision_reason
        self._audit(
            AuditEventType.GRANTED, req, {"decision_reason": decision_reason}, actor=decided_by
        )
        return req

    def deny(self, approval_id: str, decided_by: str, decision_reason: str = "") -> ApprovalRequest:
        req = self._require(approval_id)
        if req.state is not RequestState.PENDING:
            raise ApprovalError(
                f"approval {approval_id} is '{req.state.value}', only pending can be denied"
            )
        req.state = RequestState.DENIED
        req.decided_by = decided_by
        req.decision_reason = decision_reason
        self._audit(
            AuditEventType.DENIED, req, {"decision_reason": decision_reason}, actor=decided_by
        )
        return req

    def supersede(self, approval_id: str, by_request_id: str, actor: str) -> ApprovalRequest:
        req = self._require(approval_id)
        if req.state is not RequestState.PENDING:
            raise ApprovalError(f"approval {approval_id} is '{req.state.value}'")
        req.state = RequestState.SUPERSEDED
        req.superseded_by = by_request_id
        self._audit(AuditEventType.SUPERSEDED, req, {"by": by_request_id}, actor=actor)
        return req

    def sweep_expired(self) -> list[ApprovalRequest]:
        """Expire all past-due requests (e.g. from a periodic task)."""
        return [self._live(r) for r in list(self._requests.values())]

    # -- gating ----------------------------------------------------------------

    def check(self, approval_id: str) -> ApprovalRequest:
        """Gate check: raises unless a live grant covers this request.

        Does NOT consume a single-use grant — call :meth:`use` when the
        action actually executes.
        """
        req = self._require(approval_id)
        self._live(req)
        if req.state is not RequestState.GRANTED:
            raise ApprovalError(
                f"action '{req.action}' blocked: approval is "
                f"'{req.state.value}' — explicit human grant required"
                + (", re-request approval" if req.state is RequestState.EXPIRED else "")
            )
        return req

    def use(self, approval_id: str) -> ApprovalRequest:
        """Record that the gated action executed under this grant.

        Consumes single-use grants. The execution itself is audited so the
        chain shows request → decision → execution (or block) for every
        gated action.
        """
        req = self.check(approval_id)
        self._audit(AuditEventType.ACTION_EXECUTED, req, {}, actor=req.requested_by)
        if req.single_use:
            req.state = RequestState.SUPERSEDED
            req.superseded_by = "consumed"
            req.decision_reason = (req.decision_reason + " ").strip() + "[grant consumed]"
        return req

    def blocked_event(self, action: str, subject: str, why: str) -> dict:
        """Emit an actionable blocked event when a gated attempt has no grant."""
        record = self.audit.append(
            AuditEventType.BLOCKED.value,
            {"action": action, "subject": subject, "why": why},
            actor="system",
        )
        return record

    # -- read surface (UI/CLI) ---------------------------------------------

    def get(self, approval_id: str) -> ApprovalRequest:
        return self._require(approval_id)

    def pending(self) -> list[ApprovalRequest]:
        out = []
        for r in list(self._requests.values()):
            if self._live(r).state is RequestState.PENDING:
                out.append(r)
        return out

    def by_subject(self, action: str, subject: str) -> list[ApprovalRequest]:
        return [r for r in self._requests.values() if r.action == action and r.subject == subject]

    def _require(self, approval_id: str) -> ApprovalRequest:
        try:
            return self._requests[approval_id]
        except KeyError:
            raise ApprovalError(f"unknown approval {approval_id}") from None
