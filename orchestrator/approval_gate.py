"""Agent-side approval & intervention gate (PLAN §3.1, issue #249).

Ties the human-control surface (``policy.controls.Controls`` approval
lifecycle) into the agent execution path, so an agent that needs a gated
action (active testing, live-target PoC, external submission, finding
deletion, scope change) *blocks* — rather than proceeding or crashing —
until a human grants/denies the request, the request expires, or the
operator intervenes via pause/stop/kill-switch.

Two primitives:

- ``ApprovalGate`` — blocking wait on one approval request. The gate is
  woken by ``notify()`` from any thread (the API/CLI decision surface);
  expiry and kill-switch activation are re-checked after every wake-up so
  intervention always wins over a stale grant.
- ``InterventionPoint`` — cooperative checkpoint agents call between work
  units. It raises immediately when the campaign was paused/stopped or
  the global kill switch activated, giving operators bounded-latency
  intervention without the agent polling.

Every state observation is derived from the audited Controls/KillSwitch
state — this module never mutates approval state directly.
"""

from __future__ import annotations

import threading

from policy.controls import ControlError, Controls
from policy.kill_switch import KillSwitchActive


class GateDenied(RuntimeError):
    """The operator denied the request or intervened; do not proceed."""


class ApprovalGate:
    """Blocking wait for one approval request, with intervention checks."""

    def __init__(self, controls: Controls, poll_seconds: float = 0.05):
        self.controls = controls
        self.poll_seconds = poll_seconds

    def request(self, action: str, subject: str, requested_by: str, reason: str = ""):
        req = self.controls.request_approval(action, subject, requested_by, reason)
        self._event_for(req.id).set()
        return req

    def notify(self, approval_id: str) -> None:
        """Called by the decision surface after grant/deny to wake waiters."""
        self._event_for(approval_id).set()

    # internal: per-request wake events -------------------------------------
    _events: dict = {}

    def _event_for(self, approval_id: str) -> threading.Event:
        ev = self._events.get(approval_id)
        if ev is None:
            ev = threading.Event()
            self._events[approval_id] = ev
        return ev

    def wait(
        self,
        approval_id: str,
        timeout_seconds: float,
        on_denied=None,
        on_expired=None,
    ):
        """Block until decided/expired/intervened.

        Returns the granted ApprovalRequest, or raises:

        - ``GateDenied``   — explicit deny, or operator intervention
          (kill switch active) while waiting.
        - ``TimeoutError`` — not decided within timeout_seconds.

        ``on_denied`` / ``on_expired`` hooks let callers record structured
        outcomes before the exception propagates.
        """
        import time

        deadline = time.monotonic() + timeout_seconds
        event = self._event_for(approval_id)
        while True:
            # Intervention check FIRST: a kill switch engaged mid-wait wins
            # over a previously observed grant (stale-grant protection).
            if self.controls.kill_switch.active:
                raise GateDenied("kill switch active while waiting for approval")
            try:
                # Re-checks current status each iteration so mid-wait
                # decisions are honored even if we were woken by an
                # unrelated event.
                return self.controls.assert_approved(approval_id)
            except KillSwitchActive as exc:
                raise GateDenied(str(exc)) from exc
            except ControlError as exc:
                msg = str(exc)
                if "kill switch" in msg.lower():
                    raise GateDenied(msg) from exc
                if "'denied'" in msg:
                    if on_denied:
                        on_denied()
                    raise GateDenied(msg) from exc
                if "expired" in msg.lower():
                    if on_expired:
                        on_expired()
                    raise GateDenied(msg) from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"approval {approval_id} not granted within {timeout_seconds}s")
            # Wake on notify() or poll at worst every poll_seconds.
            event.wait(timeout=min(remaining, self.poll_seconds))
            event.clear()


class InterventionPoint:
    """Cooperative checkpoint honoring operator pause/stop/kill-switch."""

    def __init__(self, controls: Controls):
        self.controls = controls

    def check(self, campaign_uuid: str) -> None:
        st = self.controls.campaign_state(campaign_uuid)
        if getattr(self.controls.kill_switch, "active", False):
            raise GateDenied("kill switch active")
        if st.stopped:
            raise GateDenied(f"campaign {campaign_uuid} stopped by operator")
        if not st.running:
            raise GateDenied(f"campaign {campaign_uuid} paused by operator")
