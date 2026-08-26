"""Per-target health and politeness tracking (issue #116, PLAN §2.2/§5/§13).

The policy engine answers "is this action allowed by campaign scope?"; this
module answers "is the target itself healthy enough to keep probing?" —
ethical scanning requires backing off when a target shows distress (error
spikes, 429s, connection resets), regardless of formal rate-limit headroom.

Design:
- Rolling per-target counters (requests / errors / latency samples) over a
  sliding window.
- Distress detection from error rate + recent 429/reset signals triggers an
  automatic transition to DEGRADED (backoff) or SUSPENDED (hard stop).
- State machine per target: HEALTHY -> DEGRADED -> SUSPENDED, with explicit
  resume (auto after cooldown for degraded; human-approved only for
  suspended).
- Safety invariant enforced in PolicyEngine: a SUSPENDED target rejects all
  active tool calls even if the scope allowlist still matches.

State transitions are recorded to the observability EventStore (#23) so they
are queryable by campaign + time range and visible on dashboards.
"""

from __future__ import annotations

import enum
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Window length for rolling counters (seconds). Kept short: distress is about
# what is happening NOW, not campaign averages.
WINDOW_SECONDS = 60.0
# Minimum requests inside the window before error-rate distress can fire —
# avoids one unlucky 404 suspending a target.
MIN_REQUESTS_FOR_RATE = 5
# Error fraction inside the window that counts as distress.
ERROR_RATE_THRESHOLD = 0.8
# Consecutive hard-distress signals (429 / connection reset) that suspend a
# target outright, bypassing the degraded stage.
SUSPEND_AFTER_CONSECUTIVE = 3
# Auto-resume delay after entering DEGRADED (seconds). SUSPENDED never
# auto-resumes — that requires human approval via `resume()`.
DEGRADED_COOLDOWN_SECONDS = 300.0


class TargetHealthState(enum.Enum):
    """Lifecycle of one target's politeness state (§13 view 1 alerts)."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"  # automatic backoff window
    SUSPENDED = "suspended"  # hard stop until human-approved resume


@dataclass
class TargetStats:
    """Rolling counters and health state for a single target."""

    state: TargetHealthState = TargetHealthState.HEALTHY
    total_requests: int = 0
    total_errors: int = 0
    # (timestamp, ok, latency_seconds, hard_signal) tuples inside the window
    _samples: deque[tuple[float, bool, float, bool]] = field(default_factory=deque, repr=False)
    consecutive_hard_signals: int = 0
    last_transition_ts: float = 0.0
    # Set once robots.txt / published testing policies were fetched for this
    # target when the campaign opted into politeness compliance (#116).
    robots_checked: bool = False
    robots_disallowed_paths: tuple[str, ...] = ()

    def prune_window(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def window_error_rate(self, now: float) -> float:
        self.prune_window(now)
        if len(self._samples) < MIN_REQUESTS_FOR_RATE:
            return 0.0
        errors = sum(1 for s in self._samples if not s[1])
        return errors / len(self._samples)

    def window_count(self, now: float) -> int:
        self.prune_window(now)
        return len(self._samples)


class TargetHealthTracker:
    """Tracks per-target request outcomes and drives the health state machine.

    ``event_sink`` receives ``(campaign_id, event_type, payload)`` dicts for
    every state transition so observability (#23) has the full history; it is
    optional so unit tests and offline callers stay dependency-free.
    """

    def __init__(
        self,
        event_sink: Callable[[str | None, str, dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._targets: dict[str, TargetStats] = {}
        self._event_sink = event_sink
        self._clock = clock
        self._suspended_total = 0

    def stats(self, target_key: str) -> TargetStats:
        return self._targets.setdefault(target_key, TargetStats())

    def record_result(
        self,
        target_key: str,
        *,
        ok: bool,
        status_code: int | None = None,
        latency_seconds: float = 0.0,
        connection_reset: bool = False,
        campaign_id: str | None = None,
    ) -> TargetHealthState:
        """Record one request outcome; may trigger a state transition.

        Hard distress signals are HTTP 429 (rate limited by the target) and
        connection resets — the target telling us to back off NOW.
        """
        now = self._clock()
        st = self.stats(target_key)
        hard = connection_reset or (status_code == 429)
        st.total_requests += 1
        if not ok:
            st.total_errors += 1
        st._samples.append((now, ok, latency_seconds, hard))
        st.prune_window(now)

        if hard and ok is False:
            st.consecutive_hard_signals += 1
        elif ok:
            st.consecutive_hard_signals = 0

        prev = st.state
        if (
            st.state is TargetHealthState.HEALTHY
            and st.consecutive_hard_signals >= SUSPEND_AFTER_CONSECUTIVE
        ):
            self._transition(target_key, st, TargetHealthState.SUSPENDED, now, campaign_id)
        elif (
            st.state is TargetHealthState.HEALTHY
            and st.window_error_rate(now) >= ERROR_RATE_THRESHOLD
        ):
            self._transition(target_key, st, TargetHealthState.DEGRADED, now, campaign_id)

        if prev is st.state:
            pass
        return st.state

    def check_active_allowed(self, target_key: str) -> tuple[bool, str]:
        """Gate for ACTIVE tool calls against one target.

        Returns (allowed, reason). Suspended targets reject everything;
        degraded targets also reject until their cooldown elapses (automatic
        backoff), then auto-recover to HEALTHY on the next check.
        """
        now = self._clock()
        # The engine passes full request URLs while counters are often keyed
        # by bare origin — check the exact key AND its origin prefix so a
        # suspended host is blocked no matter how callers key their results.
        candidates = [target_key]
        if "://" in target_key:
            origin = (
                target_key.split("://", 1)[0]
                + "://"
                + (target_key.split("://", 1)[1].split("/", 1)[0])
            )
            candidates.append(origin)
        states = []
        for cand in candidates:
            st = self._targets.get(cand)
            if st is not None and st.state is not TargetHealthState.HEALTHY:
                states.append(st)
                target_key = cand
        if not states:
            return True, "healthy"
        # Most restrictive state wins (SUSPENDED > DEGRADED).
        st = max(states, key=lambda s: s.state.value == "suspended")
        if st.state is TargetHealthState.SUSPENDED:
            return False, (
                f"target {target_key!r} is SUSPENDED due to repeated distress "
                "(429/connection resets); human-approved resume required"
            )
        if st.state is TargetHealthState.DEGRADED:
            if now - st.last_transition_ts >= DEGRADED_COOLDOWN_SECONDS:
                self._transition(target_key, st, TargetHealthState.HEALTHY, now, None)
                return True, "degraded cooldown elapsed; target recovered"
            return False, (
                f"target {target_key!r} is DEGRADED (distress backoff); "
                f"retrying automatically after cooldown"
            )
        return True, "healthy"

    def suspend(self, target_key: str, campaign_id: str | None = None) -> None:
        """Human/operator-initiated suspension."""
        now = self._clock()
        st = self.stats(target_key)
        self._transition(target_key, st, TargetHealthState.SUSPENDED, now, campaign_id)

    def resume(self, target_key: str, *, approved_by: str = "") -> TargetHealthState:
        """Human-approved resume from SUSPENDED (or force-clear DEGRADED)."""
        now = self._clock()
        st = self.stats(target_key)
        st.consecutive_hard_signals = 0
        st._samples.clear()
        self._transition(
            target_key,
            st,
            TargetHealthState.HEALTHY,
            now,
            None,
            extra={"approved_by": approved_by},
        )
        return st.state

    def set_robots_policy(
        self, target_key: str, disallow: list[str], *, checked: bool = True
    ) -> None:
        """Record robots.txt / published-policy results for provenance.

        Callers fetch robots.txt themselves (respecting the same rate limits);
        the tracker stores the parsed result so provenance evidence exists for
        every politeness decision (#116).
        """
        st = self.stats(target_key)
        st.robots_checked = checked
        st.robots_disallowed_paths = tuple(disallow)

    def robots_disallows(self, url_path: str, target_key: str) -> bool:
        """Boundary-aware robots check: '/admin' blocks '/admin/panel' but
        NOT '/adminX' (path-segment honesty), and '/' blocks everything."""
        st = self.stats(target_key)
        if not st.robots_checked:
            return False
        for p in st.robots_disallowed_paths:
            if p == "/":
                return True
            base = p.rstrip("/")
            if url_path == base or url_path.startswith(base + "/"):
                return True
        return False

    def summary(self) -> dict[str, dict[str, Any]]:
        """Snapshot for UI dashboard alerts / CLI display (§13 view 1)."""
        now = self._clock()
        out: dict[str, dict[str, Any]] = {}
        for key, st in self._targets.items():
            out[key] = {
                "state": st.state.value,
                "window_requests": st.window_count(now),
                "window_error_rate": round(st.window_error_rate(now), 3),
                "total_requests": st.total_requests,
                "total_errors": st.total_errors,
                "consecutive_hard_signals": st.consecutive_hard_signals,
                "robots_checked": st.robots_checked,
            }
        return out

    def _transition(
        self,
        target_key: str,
        st: TargetStats,
        new_state: TargetHealthState,
        now: float,
        campaign_id: str | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if st.state is new_state:
            return
        old = st.state
        st.state = new_state
        st.last_transition_ts = now
        if new_state is TargetHealthState.SUSPENDED:
            self._suspended_total += 1
        if self._event_sink:
            payload: dict[str, Any] = {
                "target": target_key,
                "from": old.value,
                "to": new_state.value,
            }
            if extra:
                payload.update(extra)
            self._event_sink(campaign_id, "target_health.transition", payload)
