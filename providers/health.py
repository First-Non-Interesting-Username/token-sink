"""Provider health checks (PLAN §8.1 health check; issue #102).

Health-check slice of the provider interface with its own lifecycle:

- ``ProviderHealthMonitor`` runs lightweight probes per adapter: auth status
  (never displaying secrets), endpoint reachability, and a latency sample.
- Each probe produces a ``QuotaSnapshot`` (window usage / remaining / reset)
  that the rate limiter (#75/#80/#82) and usage accounting (#28) can consume.
- Per-provider state machine: healthy → degraded → cooling_down → excluded,
  with every transition emitted as an event (#23) so the UI status page
  (#13.4) is just an event/monitor reader.
- A failed probe excludes a provider from routing until it recovers; recovery
  emits its own event.
- Probes are disabled entirely while the kill switch is active (#65) — no
  network egress after activation, including probe traffic.

Probing strategy: adapters implement the tiny ``HealthProbe`` protocol so the
monitor never depends on concrete SDKs; tests inject fake probes. Probes count
against the provider's rate limit like any other request, so failures back off
geometrically rather than hammering a struggling endpoint.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from observability.event_store import EventStore

# Health states per issue #102. Ordered by severity; recovery walks backwards.
STATE_HEALTHY = "healthy"
STATE_DEGRADED = "degraded"
STATE_COOLING_DOWN = "cooling_down"
STATE_EXCLUDED = "excluded"
VALID_STATES = (STATE_HEALTHY, STATE_DEGRADED, STATE_COOLING_DOWN, STATE_EXCLUDED)

EVENT_TYPE = "provider.health.changed"


class KillSwitchActive(Exception):
    """Raised when a probe is attempted while the kill switch is engaged."""


@dataclass(frozen=True)
class QuotaSnapshot:
    """Point-in-time quota/rate-limit reading for one provider.

    Shared shape consumed by the rate limiter and usage accounting; values are
    None when the provider API does not expose them.
    """

    provider: str
    requests_used: int | None = None
    requests_limit: int | None = None
    tokens_used: int | None = None
    tokens_limit: int | None = None
    reset_at: float | None = None  # unix ts when the current window resets
    observed_at: float = 0.0

    @property
    def remaining_requests(self) -> int | None:
        if self.requests_limit is None:
            return None
        used = self.requests_used or 0
        return max(0, self.requests_limit - used)


class HealthProbe(ABC):
    """Minimal probe interface each provider adapter must satisfy."""

    @abstractmethod
    def check(self) -> tuple[bool, float, QuotaSnapshot | None]:
        """Run one lightweight probe.

        Returns (ok, latency_seconds, quota_snapshot). Implementations must
        never raise on provider failure — return ok=False instead — but MAY
        raise on local misconfiguration, which the monitor treats as fatal for
        the probe loop.
        """


class HealthCheckResult:
    """One recorded probe outcome plus the monitor's resulting state."""

    __slots__ = ("provider", "ok", "latency", "quota", "error", "ts")

    def __init__(
        self,
        provider: str,
        ok: bool,
        latency: float,
        quota: QuotaSnapshot | None = None,
        error: str | None = None,
        ts: float = 0.0,
    ) -> None:
        self.provider = provider
        self.ok = ok
        self.latency = latency
        self.quota = quota
        self.error = error
        self.ts = ts

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ok": self.ok,
            "latency": self.latency,
            "error": self.error,
            "ts": self.ts,
            "quota": self.quota.__dict__ if self.quota else None,
        }


@dataclass
class ProviderHealth:
    """Mutable per-provider health record owned by the monitor."""

    provider: str
    state: str = STATE_HEALTHY
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_latency: float | None = None
    last_probe_ts: float = 0.0
    last_error: str | None = None
    quota: QuotaSnapshot | None = None
    history: list[HealthCheckResult] = field(default_factory=list)


class ProviderHealthMonitor:
    """Tracks provider health via injected probes; emits state-change events.

    The monitor does no scheduling itself — the runtime calls
    ``run_probe(provider)`` on its cadence (config `providers.health.*`,
    §16). This keeps timing policy out of the tested core and lets the kill
    switch gate entry points in one place.
    """

    def __init__(
        self,
        probes: dict[str, HealthProbe],
        events: EventStore,
        *,
        degraded_after_failures: int = 1,
        exclude_after_failures: int = 3,
        cooldown_successes_to_recover: int = 2,
        latency_degrade_ms: float = 5000.0,
        now=None,
    ) -> None:
        if exclude_after_failures < degraded_after_failures:
            raise ValueError("exclude threshold must be >= degraded threshold")
        self.probes = probes
        self.events = events
        self.degraded_after_failures = degraded_after_failures
        self.exclude_after_failures = exclude_after_failures
        self.cooldown_successes_to_recover = cooldown_successes_to_recover
        # Latency above this marks a successful probe as degraded-quality:
        # reachable but too slow to route latency-sensitive tasks to.
        self.latency_degrade_ms = latency_degrade_ms
        self._now = now or time.time
        self.health: dict[str, ProviderHealth] = {}

    # -- public read API ---------------------------------------------------

    def snapshot(self, provider: str) -> ProviderHealth:
        """Current health record (creating a default-healthy one if unseen)."""
        return self._ensure(provider)

    def routable(self, provider: str) -> bool:
        """Whether the router may send work to this provider right now."""
        h = self._ensure(provider)
        # healthy and degraded stay routable; cooling_down/excluded do not.
        return h.state in (STATE_HEALTHY, STATE_DEGRADED)

    def status_page(self) -> list[dict[str, Any]]:
        """Data backing the provider page (PLAN §13.4): all providers, latest
        latency/quota/state, newest first by state severity."""
        rows = []
        for name in sorted(self.health):
            h = self.health[name]
            rows.append(
                {
                    "provider": name,
                    "state": h.state,
                    "latency": h.last_latency,
                    "last_probe_ts": h.last_probe_ts,
                    "last_error": h.last_error,
                    "consecutive_failures": h.consecutive_failures,
                    "quota": h.quota.__dict__ if h.quota else None,
                }
            )
        return rows

    # -- probing ------------------------------------------------------------

    def run_probe(self, provider: str, *, kill_switch_active: bool = False) -> HealthCheckResult:
        """Probe one provider and update its state machine.

        Raises KillSwitchActive if the kill switch is engaged — probing makes
        network requests, which must stop completely after activation (#65).
        """
        if kill_switch_active:
            raise KillSwitchActive(provider)
        probe = self.probes.get(provider)
        if probe is None:
            raise KeyError(f"no probe registered for provider {provider!r}")

        started = self._now()
        try:
            ok, latency, quota = probe.check()
            error = None
        except Exception as exc:  # local misconfiguration counts as failure
            ok, latency, quota = False, self._now() - started, None
            error = f"{type(exc).__name__}: {exc}"
        result = HealthCheckResult(
            provider=provider,
            ok=ok,
            latency=latency,
            quota=quota,
            error=error,
            ts=self._now(),
        )
        self._record(result)
        return result

    # -- internals -----------------------------------------------------------

    def _ensure(self, provider: str) -> ProviderHealth:
        if provider not in self.health:
            self.health[provider] = ProviderHealth(provider=provider)
        return self.health[provider]

    def _record(self, result: HealthCheckResult) -> None:
        h = self._ensure(result.provider)
        h.last_probe_ts = result.ts
        h.last_error = result.error
        if result.quota:
            h.quota = result.quota
        # Keep bounded history so the UI can draw a small sparkline without
        # the store growing unbounded.
        h.history.append(result)
        del h.history[:-20]

        prev_state = h.state
        if result.ok:
            h.consecutive_failures = 0
            h.consecutive_successes += 1
            h.last_latency = result.latency
            # Slow-but-working responses degrade the state instead of failing
            # outright — routing wants to avoid them, not ban the provider.
            slow = result.latency * 1000 > self.latency_degrade_ms
            if h.state == STATE_EXCLUDED or h.state == STATE_COOLING_DOWN:
                if h.consecutive_successes >= self.cooldown_successes_to_recover:
                    new_state = STATE_DEGRADED if slow else STATE_HEALTHY
                else:
                    new_state = h.state  # still cooling down
            elif h.state == STATE_HEALTHY and slow:
                new_state = STATE_DEGRADED
            elif h.state == STATE_DEGRADED and not slow:
                new_state = STATE_HEALTHY
            else:
                new_state = h.state
        else:
            h.consecutive_successes = 0
            h.consecutive_failures += 1
            if h.consecutive_failures >= self.exclude_after_failures:
                new_state = STATE_EXCLUDED
            elif h.consecutive_failures >= self.degraded_after_failures:
                # First failure drops straight to cooling_down: the provider
                # just errored, so treat it as worse than merely degraded.
                new_state = STATE_COOLING_DOWN
            else:
                new_state = h.state

        if new_state != prev_state:
            h.state = new_state
            # Every transition becomes a durable event so the audit log and
            # the live stream see provider exclusions/recoveries (#23).
            self.events.append(
                EVENT_TYPE,
                {
                    "provider": result.provider,
                    "from": prev_state,
                    "to": new_state,
                    "reason": result.error or ("slow" if result.ok else "probe_failed"),
                    "latency": result.latency,
                    "ts": result.ts,
                },
            )
