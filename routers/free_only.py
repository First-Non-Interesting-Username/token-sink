"""Free-only routing guarantee (PLAN §7.3, §21; issue #66).

When a campaign (or the global config) is in free-only mode, routing must be
UNABLE to select a paid model or one with unknown free/paid status — enforced
here in code, never by prompt. This module is the single choke point every
candidate plan must pass through before it can become a selection:

- ``FreeOnlyGate.filter`` drops any candidate whose model's confirmed status
  is not FREE — including every entry in its ``fallbacks`` chain. Unknown
  status ⇒ excluded until free-status metadata confirms otherwise
  (§8.2 / providers.free_status).
- Each block emits a :class:`PolicyEvent` so blocked attempts are visible in
  the UI (#22) and metrics (#23); callers can also append them to the
  tamper-evident event store (#42).
- ``enforce_selection`` is a second, independent check applied at selection
  time: even if a caller forgets to filter first, a paid/unknown selection
  raises instead of slipping through (defense in depth, per §2 "blocked by
  policy, not merely discouraged").

Status resolution is injected via a callable so this layer stays decoupled
from the catalog implementation (issue #98): given ``(provider, model)``
return the confirmed :class:`FreeStatus`. Models missing from the catalog
resolve to UNKNOWN and are therefore blocked — fail closed.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from providers.free_status import FREE_ROUTABLE, FreeStatus

# A status resolver maps (provider, model) -> FreeStatus. Resolvers SHOULD
# return FreeStatus.UNKNOWN for anything they cannot confirm.
StatusResolver = Callable[[str, str], FreeStatus]


def unknown_status_resolver(provider: str, model: str) -> FreeStatus:
    """A resolver that knows nothing: everything resolves UNKNOWN (blocked)."""
    return FreeStatus.UNKNOWN


@dataclass(frozen=True)
class PolicyEvent:
    """One free-only enforcement outcome, for UI/metrics/event-store use."""

    event_id: str
    ts: float
    kind: str  # "blocked" | "allowed"
    provider: str
    model: str
    status: str
    reason: str
    campaign_id: str | None = None
    origin: str = ""  # e.g. "primary" | "fallback" | "selection" | "retry"


@dataclass(frozen=True)
class BlockedCandidate:
    """A candidate plan rejected by the gate, with an actionable reason."""

    provider: str
    model: str
    status: str
    reason: str
    origin: str


class FreeOnlyViolation(RuntimeError):
    """Raised when a paid/unknown model reaches selection despite the gate."""


def _candidate_fields(candidate: object, origin: str) -> tuple[str, str, list[dict]]:
    """Extract (provider, model, fallbacks) from a CandidatePlan-shaped object."""
    provider = getattr(candidate, "provider", "")
    model = getattr(candidate, "model", "")
    fallbacks = list(getattr(candidate, "fallbacks", []) or [])
    return str(provider), str(model), fallbacks


class FreeOnlyGate:
    """Hard free-only enforcement for routing candidates.

    ``resolver`` must return the *confirmed* free status of a model; the
    gate treats UNKNOWN as not-routable (fail closed).
    """

    def __init__(
        self,
        resolver: StatusResolver = unknown_status_resolver,
        enabled: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._resolver = resolver
        self.enabled = enabled
        self._clock = clock
        self.events: list[PolicyEvent] = []

    # -- internals ---------------------------------------------------------

    def _record(
        self,
        kind: str,
        provider: str,
        model: str,
        status: str,
        reason: str,
        campaign_id: str | None,
        origin: str,
    ) -> PolicyEvent:
        ev = PolicyEvent(
            event_id=uuid.uuid4().hex,
            ts=self._clock(),
            kind=kind,
            provider=provider,
            model=model,
            status=status,
            reason=reason,
            campaign_id=campaign_id,
            origin=origin,
        )
        self.events.append(ev)
        return ev

    def _check_model(
        self,
        provider: str,
        model: str,
        campaign_id: str | None,
        origin: str,
    ) -> BlockedCandidate | None:
        """Return a BlockedCandidate if (provider, model) may not be routed."""
        if not self.enabled:
            return None
        status = self._resolver(provider, model)
        if status in FREE_ROUTABLE:
            self._record(
                "allowed", provider, model, status.value, "confirmed free", campaign_id, origin
            )
            return None
        reason = (
            f"free-only mode: model {provider}/{model} has status "
            f"'{status.value}' — only confirmed-free models are routable"
            + (
                " (unknown status is excluded until confirmed, §8.2)"
                if status is FreeStatus.UNKNOWN
                else ""
            )
        )
        self._record("blocked", provider, model, status.value, reason, campaign_id, origin)
        return BlockedCandidate(provider, model, status.value, reason, origin)

    # -- public API --------------------------------------------------------

    def filter(
        self,
        candidates: list,
        campaign_id: str | None = None,
    ) -> tuple[list, list[BlockedCandidate]]:
        """Filter candidate plans for free-only routing.

        Returns ``(routable, blocked)``. Every primary candidate AND every
        entry in its fallbacks chain is checked; a candidate with any
        non-free fallback is itself dropped — a fallback chain must not be
        able to escape free-only mode after the primary is accepted.
        """
        routable: list = []
        blocked: list[BlockedCandidate] = []
        for cand in candidates or []:
            provider, model, fallbacks = _candidate_fields(cand, "primary")
            b = self._check_model(provider, model, campaign_id, "primary")
            if b:
                blocked.append(b)
                continue
            fb_blocked: list[BlockedCandidate] = []
            for i, fb in enumerate(fallbacks):
                fb = dict(fb)
                fp, fm = str(fb.get("provider", "")), str(fb.get("model", ""))
                bb = self._check_model(fp, fm, campaign_id, f"fallback[{i}]")
                if bb:
                    fb_blocked.append(bb)
            if fb_blocked:
                # Drop the whole candidate: its own chain violates the mode.
                blocked.extend(fb_blocked)
                reason = f"{fb_blocked[0].reason} (in fallback chain of {provider}/{model})"
                blocked.append(
                    BlockedCandidate(
                        provider,
                        model,
                        self._resolver(provider, model).value,
                        reason,
                        "primary",
                    )
                )
                self._record(
                    "blocked",
                    provider,
                    model,
                    self._resolver(provider, model).value,
                    reason,
                    campaign_id,
                    "primary",
                )
                continue
            routable.append(cand)
        return routable, blocked

    def enforce_selection(
        self,
        provider: str,
        model: str,
        campaign_id: str | None = None,
        origin: str = "selection",
    ) -> None:
        """Final backstop: raise unless the selected model is confirmed free.

        Called at selection time (including on retry/failover paths) so no
        code path — filtered or not — can commit to a non-free model.
        """
        b = self._check_model(provider, model, campaign_id, origin)
        if b:
            raise FreeOnlyViolation(b.reason)

    def drain_events(self) -> list[PolicyEvent]:
        """Hand events to the UI/metrics/event-store pipeline."""
        out, self.events = self.events, []
        return out
