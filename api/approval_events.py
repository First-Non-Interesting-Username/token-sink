"""Real-time approval event bridge (issue #237, PLAN §13.6 view 6).

Surfaces approval lifecycle changes in the campaign event stream so the
UI's approval center renders pending/blocked approvals live — no polling.

Design:

- **Audited path stays the only write path.** The UI approve/deny buttons
  call the same ``ApprovalBackend.grant()/deny()`` the CLI uses (shared
  helper :func:`decide_approval`), so every decision lands in the
  hash-chained AuditLog exactly once. The bridge never mutates request
  state itself; it only *observes* the backend and mirrors transitions
  into the EventStore.
- **Push via subscription.** ``ApprovalEventBridge`` registers a callback
  with the backend; every audited transition appends a corresponding
  event to the EventStore (campaign-scoped when the request carries a
  campaign_id). SSE/WebSocket transport (#31) fans those events out;
  this module stops at the durable stream.
- **Stale/expired visibility.** Expired requests emit an event with the
  previous state so the UI can render them as stale rather than silently
  dropping them from the queue. ``sweep_expired()`` is exposed for the
  periodic auto-expiry tick required by policy.
- **Reconnect safety.** Because events go through the append-only
  EventStore, a reconnecting UI replays missed approvals via
  ``replay_after(last_event_id)`` — no gap between poll fallbacks.
"""

from __future__ import annotations

from typing import Any

from observability.event_store import EventStore
from policy.approvals import ApprovalBackend, ApprovalError, RequestState

# Map each lifecycle transition to a stream event type. Kept explicit so
# the UI contract is stable and greppable.
STREAM_EVENT_TYPES = {
    "approval_requested": "approval.requested",
    "approval_granted": "approval.granted",
    "approval_denied": "approval.denied",
    "approval_expired": "approval.expired",
    "approval_superseded": "approval.superseded",
}


class ApprovalEventBridge:
    """Mirror ApprovalBackend transitions into an EventStore stream."""

    def __init__(self, backend: ApprovalBackend, events: EventStore):
        self.backend = backend
        self.events = events
        # The backend exposes transitions via its audit log appends; we hook
        # the same choke point (_audit) by wrapping it once, here.
        self._original_audit = backend._audit
        backend._audit = self._intercept_audit  # type: ignore[method-assign]

    # -- interception -------------------------------------------------------

    def _intercept_audit(self, event_type: Any, req, extra: dict, actor: str) -> None:
        # First keep the real audit behavior — the hash-chained trail must
        # stay byte-identical to the non-bridged path.
        self._original_audit(event_type, req, extra, actor)
        stream_type = STREAM_EVENT_TYPES.get(str(getattr(event_type, "value", event_type)))
        if stream_type is None:
            return  # gated_action_* events are not approval-center concerns
        payload = {
            "approval_id": req.id,
            "action": req.action,
            "subject": req.subject,
            "requested_by": req.requested_by,
            "state": req.state.value,
            "previous_state": extra.get("previous_state"),
            "decided_by": req.decided_by,
            "decision_reason": req.decision_reason,
            "expires_at": req.expires_at.isoformat() if req.expires_at else None,
            "actor": actor,
        }
        self.events.append(
            stream_type,
            payload,
            campaign_id=req.campaign_id or None,
        )

    # -- convenience passthroughs ---------------------------------------------

    def sweep_expired(self) -> int:
        """Auto-expiry tick: lazily expire past-due requests.

        Returns how many requests transitioned to expired (each of those
        emits an approval.expired stream event via the intercepted audit).
        States are snapshotted first because backend.pending() itself
        lazily expires, which would make a before/after count wrong.
        """
        were_pending = [
            r.id for r in self.backend._requests.values() if r.state is RequestState.PENDING
        ]
        self.backend.sweep_expired()
        return sum(1 for rid in were_pending if self.backend.get(rid).state is RequestState.EXPIRED)


def decide_approval(
    backend: ApprovalBackend,
    events: EventStore,
    approval_id: str,
    decision: str,
    decided_by: str,
    reason: str = "",
) -> dict:
    """Single audited decision path shared by CLI and UI.

    Refuses unknown decisions up front; delegates to grant()/deny() so the
    AuditLog entry is written by the same code path regardless of surface.
    Returns a serializable snapshot for the HTTP/CLI response.
    """
    if decision not in ("approve", "reject"):
        raise ApprovalError(f"unknown decision {decision!r}; use 'approve' or 'reject'")
    if decision == "approve":
        req = backend.grant(approval_id, decided_by=decided_by, decision_reason=reason)
    else:
        req = backend.deny(approval_id, decided_by=decided_by, decision_reason=reason)
    return {
        "id": req.id,
        "state": req.state.value,
        "decided_by": req.decided_by,
        "decision_reason": req.decision_reason,
    }


def waiting_agent_count(backend: ApprovalBackend, action: str, subject: str) -> int:
    """How many pending requests exist for one (action, subject).

    Used by the integration test and by the UI badge: an agent blocked on a
    gated action shows here until its request is granted or denied.
    """
    return len([r for r in backend.pending() if r.action == action and r.subject == subject])


__all__ = [
    "STREAM_EVENT_TYPES",
    "ApprovalEventBridge",
    "ApprovalError",
    "RequestState",
    "decide_approval",
    "waiting_agent_count",
]
