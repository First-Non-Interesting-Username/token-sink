"""Campaign lifecycle semantics (PLAN §5, §17, §19.6 — issue #205).

A campaign is the top-level unit of work, and its lifecycle must be
explicit: which states exist, which transitions are legal, and what
happens to in-flight tasks when an operator pauses or stops a campaign.
This module is the single authority for those rules:

- :class:`CampaignState` — the lifecycle states
  (``draft → running ⇄ paused``, ``running/paused → stopped``,
  ``running → completed``).
- :class:`CampaignLifecycle` — a state machine with guarded transitions:
  every transition validates the from-state, records who/why, appends an
  audit entry (append-only history), and returns a :class:`TransitionResult`.
  Illegal transitions are rejected with an explanation, never silently
  coerced.
- In-flight task handling: on pause/stop the machine asks the registered
  drain callback to quiesce in-flight tasks within a bounded deadline and
  records the drain outcome. Pause/stop never abandons work silently —
  if the drain fails or times out the transition still completes but is
  marked ``drain_ok=False`` so operators can see it.

Resumability lives at the storage layer; this module only guarantees that
a paused/stopped campaign's recorded snapshot (state + history + drain
outcomes) is sufficient to decide whether resume is safe. Resuming a
paused campaign re-enters ``running`` via the same guarded path as any
other transition.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CampaignLifecycle",
    "CampaignState",
    "DrainOutcome",
    "IllegalTransitionError",
    "TransitionResult",
]


class CampaignState(enum.StrEnum):
    """Explicit campaign lifecycle states."""

    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"


# Legal transitions: from-state -> set of to-states.
LEGAL_TRANSITIONS: dict[CampaignState, frozenset[CampaignState]] = {
    CampaignState.DRAFT: frozenset({CampaignState.RUNNING}),
    CampaignState.RUNNING: frozenset(
        {CampaignState.PAUSED, CampaignState.STOPPED, CampaignState.COMPLETED}
    ),
    CampaignState.PAUSED: frozenset({CampaignState.RUNNING, CampaignState.STOPPED}),
    CampaignState.STOPPED: frozenset(),
    CampaignState.COMPLETED: frozenset(),
}


class IllegalTransitionError(ValueError):
    """Raised when a transition is not legal from the current state."""

    def __init__(self, current: CampaignState, target: CampaignState) -> None:
        self.current = current
        self.target = target
        allowed = sorted(s.value for s in LEGAL_TRANSITIONS[current])
        super().__init__(
            f"illegal campaign transition {current.value} -> {target.value}; "
            f"allowed from {current.value}: {', '.join(allowed) or 'none'}"
        )


@dataclass(frozen=True)
class DrainOutcome:
    """Result of draining in-flight tasks during pause/stop/resume."""

    ok: bool
    drained: int = 0
    abandoned: int = 0
    detail: str = ""


@dataclass(frozen=True)
class TransitionResult:
    """Record of one successful transition (append-only history entry)."""

    campaign_uuid: str
    from_state: CampaignState
    to_state: CampaignState
    actor: str
    reason: str
    at_unix_ns: int
    drain: DrainOutcome | None = None


@dataclass
class _InFlightTask:
    task_id: str
    started_at_unix_ns: int = field(default_factory=lambda: time.time_ns())


def _default_now_ns() -> int:
    return time.time_ns()


class CampaignLifecycle:
    """Guarded state machine for one campaign.

    Parameters
    ----------
    campaign_uuid:
        Stable identity of the campaign.
    now_ns:
        Injectable clock (ns since epoch) for tests.
    drain_callback:
        Optional callable invoked on pause/stop/(resume) transitions with
        ``(deadline_seconds)`` and returning a :class:`DrainOutcome`. It is
        responsible for quiescing in-flight tasks; the machine only records
        the outcome. If absent, drains are treated as trivially complete.
    """

    def __init__(
        self,
        campaign_uuid: str | None = None,
        *,
        initial_state: CampaignState = CampaignState.DRAFT,
        now_ns: Callable[[], int] | None = None,
        drain_callback: Callable[[float], DrainOutcome] | None = None,
    ) -> None:
        if not campaign_uuid:
            campaign_uuid = str(uuid.uuid4())
        try:
            uuid.UUID(campaign_uuid)
        except ValueError as exc:
            raise ValueError("campaign_uuid must be a valid UUID") from exc
        self.campaign_uuid = campaign_uuid
        self.state = initial_state
        self._now_ns = now_ns or _default_now_ns
        self._drain_callback = drain_callback
        self.history: list[TransitionResult] = []
        self.in_flight: dict[str, _InFlightTask] = {}

    # -- in-flight bookkeeping ------------------------------------------------

    def mark_started(self, task_id: str) -> None:
        """Record an in-flight task (only meaningful while running)."""
        if self.state is not CampaignState.RUNNING:
            raise IllegalTransitionError(self.state, self.state)
        self.in_flight[task_id] = _InFlightTask(task_id=task_id)

    def mark_finished(self, task_id: str) -> None:
        self.in_flight.pop(task_id, None)

    @property
    def in_flight_count(self) -> int:
        return len(self.in_flight)

    # -- transitions -----------------------------------------------------------

    def can_transition(self, target: CampaignState) -> bool:
        return target in LEGAL_TRANSITIONS[self.state]

    def require_transition(self, target: CampaignState) -> bool:
        """Validate without mutating; raises :class:`IllegalTransitionError`."""
        if not isinstance(target, CampaignState):
            raise TypeError("target must be a CampaignState")
        if not self.can_transition(target):
            raise IllegalTransitionError(self.state, target)
        return True

    def transition(
        self,
        target: CampaignState,
        *,
        actor: str,
        reason: str = "",
        drain_deadline_seconds: float = 30.0,
    ) -> TransitionResult:
        """Perform a guarded transition, draining in-flight work when required.

        Pause, stop, and stop-from-pause all drain in-flight tasks first;
        start and resume do not (nothing is in flight yet / already drained).
        """
        self.require_transition(target)

        drain: DrainOutcome | None = None
        if target in (CampaignState.PAUSED, CampaignState.STOPPED):
            drain = self._run_drain(drain_deadline_seconds)

        previous = self.state
        self.state = target
        result = TransitionResult(
            campaign_uuid=self.campaign_uuid,
            from_state=previous,
            to_state=target,
            actor=actor,
            reason=reason,
            at_unix_ns=self._now_ns(),
            drain=drain,
        )
        self.history.append(result)
        return result

    def start(self, *, actor: str, reason: str = "") -> TransitionResult:
        return self.transition(CampaignState.RUNNING, actor=actor, reason=reason)

    def pause(
        self, *, actor: str, reason: str = "", drain_deadline_seconds: float = 30.0
    ) -> TransitionResult:
        return self.transition(
            CampaignState.PAUSED,
            actor=actor,
            reason=reason,
            drain_deadline_seconds=drain_deadline_seconds,
        )

    def resume(self, *, actor: str, reason: str = "") -> TransitionResult:
        """Resume a paused campaign. Only legal from ``paused``."""
        return self.transition(CampaignState.RUNNING, actor=actor, reason=reason)

    def stop(
        self, *, actor: str, reason: str = "", drain_deadline_seconds: float = 30.0
    ) -> TransitionResult:
        return self.transition(
            CampaignState.STOPPED,
            actor=actor,
            reason=reason,
            drain_deadline_seconds=drain_deadline_seconds,
        )

    def complete(self, *, actor: str, reason: str = "") -> TransitionResult:
        return self.transition(CampaignState.COMPLETED, actor=actor, reason=reason)

    # -- internals -------------------------------------------------------------

    def _run_drain(self, deadline_seconds: float) -> DrainOutcome:
        if self._drain_callback is None:
            self.in_flight.clear()
            return DrainOutcome(ok=True, drained=0, abandoned=0, detail="no callback")
        try:
            outcome = self._drain_callback(deadline_seconds)
        except Exception as exc:  # noqa: BLE001 - drain failure is data, not a crash
            return DrainOutcome(
                ok=False, drained=0, abandoned=len(self.in_flight), detail=f"drain raised: {exc}"
            )
        if not isinstance(outcome, DrainOutcome):  # defensive
            return DrainOutcome(ok=False, abandoned=len(self.in_flight), detail="bad drain result")
        if outcome.ok:
            self.in_flight.clear()
        return outcome

    # -- snapshot / resumability ------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Serializable state snapshot sufficient to resume after restart."""
        return {
            "campaign_uuid": self.campaign_uuid,
            "state": self.state.value,
            "history": [
                {
                    "from": r.from_state.value,
                    "to": r.to_state.value,
                    "actor": r.actor,
                    "reason": r.reason,
                    "at_unix_ns": r.at_unix_ns,
                    "drain": (
                        {
                            "ok": r.drain.ok,
                            "drained": r.drain.drained,
                            "abandoned": r.drain.abandoned,
                            "detail": r.drain.detail,
                        }
                        if r.drain
                        else None
                    ),
                }
                for r in self.history
            ],
        }

    @classmethod
    def from_snapshot(cls, snap: dict[str, Any], **kwargs: Any) -> CampaignLifecycle:
        """Rebuild a machine from a snapshot (crash-recovery path)."""
        machine = cls(snap["campaign_uuid"], initial_state=CampaignState(snap["state"]), **kwargs)
        for h in snap.get("history", []):
            drain = None
            if h.get("drain"):
                d = h["drain"]
                drain = DrainOutcome(
                    ok=d["ok"],
                    drained=d.get("drained", 0),
                    abandoned=d.get("abandoned", 0),
                    detail=d.get("detail", ""),
                )
            machine.history.append(
                TransitionResult(
                    campaign_uuid=snap["campaign_uuid"],
                    from_state=CampaignState(h["from"]),
                    to_state=CampaignState(h["to"]),
                    actor=h["actor"],
                    reason=h.get("reason", ""),
                    at_unix_ns=h["at_unix_ns"],
                    drain=drain,
                )
            )
        return machine
