"""Real-time approval-center push (issue #237, PLAN §13 view 6).

The approval lifecycle (#85) and its HTTP surface (#206) exist; this module
adds the *streaming* slice the UI needs: subscribers get a full queue
snapshot pushed whenever it changes — no polling.

Design:

- ``ApprovalStream`` wraps an :class:`ApprovalBackend`. Every mutation the UI
  can observe (create/grant/deny/supersede/expire) goes through the SAME
  audited backend methods, so the wire view can never diverge from the audit
  trail. A background ticker calls ``sweep_expired()`` so TTL expiry surfaces
  as a push within one tick instead of waiting for a read.
- Subscribers are versioned: each snapshot carries a monotonically increasing
  revision; clients that fall behind re-sync from the latest snapshot rather
  than replaying deltas — approvals are few, snapshots are small.
- ``wait_for_decision()`` is the agent-side primitive: it blocks until the
  request reaches a terminal state (granted/denied/expired/superseded), so an
  approval granted mid-campaign unblocks exactly the waiting agent(s) and
  nobody else.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from policy.approvals import ApprovalBackend, RequestState

TERMINAL_STATES = frozenset(
    {RequestState.GRANTED, RequestState.DENIED, RequestState.EXPIRED, RequestState.SUPERSEDED}
)


class ApprovalStream:
    """Pushes approval-queue snapshots to subscribers on every change."""

    def __init__(
        self,
        backend: ApprovalBackend,
        *,
        expiry_tick_s: float = 1.0,
        clock=time.monotonic,
    ) -> None:
        self.backend = backend
        self._expiry_tick_s = expiry_tick_s
        self._clock = clock
        self._cv = threading.Condition()
        self._revision = 0
        # waiter callbacks keyed by approval_id: called with the request when
        # it reaches ANY terminal state. Exactly-one-wakeup semantics.
        self._waiters: dict[str, list[Any]] = {}
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None
        self._last_sig = self._queue_signature()

    # -- change detection ------------------------------------------------------

    def _queue_signature(self) -> tuple:
        """Cheap comparable fingerprint of everything the UI displays."""
        sig = []
        for r in sorted(self.backend.pending(), key=lambda x: x.id):
            sig.append(
                (
                    r.id,
                    r.state.value,
                    r.action,
                    r.subject,
                    r.expires_at.isoformat() if r.expires_at else None,
                )
            )
        return tuple(sig)

    def _maybe_push(self) -> bool:
        """Expire stale requests; if anything changed, bump + wake. Returns
        True when a new revision was published."""
        changed = False
        for r in self.backend.sweep_expired():
            if r.state == RequestState.EXPIRED:
                changed = True
        if changed or self._queue_signature() != self._last_sig:
            self._last_sig = self._queue_signature()
            self._publish()
            return True
        return False

    def _publish(self) -> None:
        self._revision += 1
        with self._cv:
            self._cv.notify_all()

    # -- public API ------------------------------------------------------------

    def start_ticker(self) -> None:
        """Background thread so TTL expiry pushes without any read traffic."""

        def tick():
            while not self._stop.wait(self._expiry_tick_s):
                try:
                    self.refresh()
                except Exception:
                    pass  # a failed tick must not kill the push loop

        self._ticker = threading.Thread(target=tick, daemon=True)
        self._ticker.start()

    def stop_ticker(self) -> None:
        self._stop.set()

    def refresh(self) -> int:
        """Re-check the backend now (also used after local mutations)."""
        if self._maybe_push():
            return self._revision
        return self._revision

    def snapshot(self) -> dict[str, Any]:
        """Current full queue state + revision (initial sync payload)."""
        self.refresh()
        return {
            "revision": self._revision,
            "requests": [
                {
                    "id": r.id,
                    "action": r.action,
                    "subject": r.subject,
                    "requested_by": r.requested_by,
                    "campaign_id": r.campaign_id,
                    "state": r.state.value,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                }
                for r in sorted(self.backend.pending(), key=lambda x: x.id)
            ],
        }

    def subscribe(self) -> Subscription:
        """A pull-style subscription: poll next_revision() then snapshot()."""
        return Subscription(self)

    def wait_for_decision(
        self,
        approval_id: str,
        *,
        timeout_s: float | None = None,
        poll_s: float = 0.05,
    ) -> dict[str, Any]:
        """Block until the request reaches a terminal state.

        Returns ``{"state": <str>, "request": <ApprovalRequest>}``. Raises
        TimeoutError on timeout. The ticker/refresh drives transitions; this
        only waits, never mutates.
        """
        deadline = None if timeout_s is None else self._clock() + timeout_s
        while True:
            self.refresh()
            req = self.backend.get(approval_id)  # raises ApprovalError if unknown
            if req.state in TERMINAL_STATES:
                return {"state": req.state.value, "request": req}
            if deadline is not None and self._clock() >= deadline:
                raise TimeoutError(f"approval {approval_id} still {req.state.value}")
            time.sleep(poll_s)

    def notify_changed(self) -> None:
        """Hook for callers that just mutated via the audited backend."""
        self._last_sig = self._queue_signature()
        self._publish()


class Subscription:
    """Tracks the client's seen revision; snapshot() returns only on change."""

    def __init__(self, stream: ApprovalStream) -> None:
        self._stream = stream
        self._seen = -1

    def next_snapshot(self) -> dict[str, Any] | None:
        cur = self._stream.snapshot()
        if cur["revision"] == self._seen:
            return None
        self._seen = cur["revision"]
        return cur
