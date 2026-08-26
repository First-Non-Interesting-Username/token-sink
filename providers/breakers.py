"""Provider circuit breakers, cooldowns, and health-driven exclusion (issue #83).

PLAN §7.3: "Apply circuit breakers, backoff, and cooldowns" and "Do not route
to a provider that is over quota or failing health checks."

This module is the live protection mechanism behind those rules:

- One :class:`CircuitBreaker` per ``(provider, model)`` pair, owned by a
  :class:`BreakerRegistry`. A breaker opens after ``failure_threshold``
  consecutive failures OR an error rate over ``error_rate_threshold`` across
  at least ``min_samples`` recent outcomes.
- An open breaker serves a **cooldown** window; after it expires the breaker
  goes half-open and admits up to ``half_open_max_probes`` probe calls. Probe
  successes close it; any probe failure re-opens it with a fresh cooldown.
- Quota exhaustion (429 / rate-limit responses) sets a cooldown derived from
  provider ``Retry-After`` headers when present, falling back to the
  configured default quota cooldown.
- Health-check status (PLAN §8.1) feeds an eligibility flag consulted on every
  candidate evaluation: unhealthy ⇒ excluded regardless of breaker state.

State is plain JSON-serializable data and can be persisted through the storage
layer (``kind="provider_breaker"``, one record per provider/model) so a
restart does not slam a failing provider with a fresh breaker. Persistence is
best-effort: routing never depends on the store being reachable.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

# Record kind used for persisted breaker state (storage layer #7).
RECORD_KIND = "provider_breaker"


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True)
class BreakerConfig:
    """Tunables for one breaker. All windows are seconds."""

    failure_threshold: int = 5  # consecutive failures to trip
    min_samples: int = 10  # samples before error-rate trips can fire
    error_rate_threshold: float = 0.5  # fraction of recent failures
    window_size: int = 20  # rolling outcomes kept for the error rate
    open_cooldown: float = 30.0  # default cooldown once opened
    quota_cooldown: float = 60.0  # fallback when no Retry-After available
    half_open_max_probes: int = 1


@dataclass
class BreakerStateData:
    """Mutable runtime state of one breaker (JSON-serializable)."""

    state: BreakerState = BreakerState.CLOSED
    consecutive_failures: int = 0
    recent: list[int] = field(default_factory=list)  # 1=success 0=failure
    opened_at: float = 0.0
    cooldown_until: float = 0.0
    half_open_probes_in_flight: int = 0

    def to_json(self) -> dict:
        return {
            "state": self.state.value,
            "consecutive_failures": self.consecutive_failures,
            "recent": list(self.recent),
            "opened_at": self.opened_at,
            "cooldown_until": self.cooldown_until,
        }

    @classmethod
    def from_json(cls, data: dict) -> BreakerStateData:
        return cls(
            state=BreakerState(data.get("state", "closed")),
            consecutive_failures=int(data.get("consecutive_failures", 0)),
            recent=[int(x) for x in data.get("recent", [])],
            opened_at=float(data.get("opened_at", 0.0)),
            cooldown_until=float(data.get("cooldown_until", 0.0)),
        )


@dataclass(frozen=True)
class ExclusionEvent:
    """One exclusion of a candidate by a breaker — recorded, not silent."""

    event_id: str
    ts: float
    provider: str
    model: str
    reason: str
    breaker_state: str


def _key(provider: str, model: str) -> str:
    return f"{provider}/{model}"


def cooldown_from_retry_after(retry_after: float | None, cfg: BreakerConfig) -> float:
    """Derive a quota cooldown from a Retry-After value, if usable."""
    if retry_after is None or retry_after <= 0:
        return cfg.quota_cooldown
    return max(float(retry_after), 1.0)


class CircuitBreaker:
    """State machine for one provider/model pair."""

    def __init__(
        self,
        provider: str,
        model: str,
        config: BreakerConfig | None = None,
        clock: Callable[[], float] = time.time,
        state: BreakerStateData | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.config = config or BreakerConfig()
        self._clock = clock
        self.data = state or BreakerStateData()
        self._half_open_successes = 0

    # -- queries ------------------------------------------------------------

    @property
    def key(self) -> str:
        return _key(self.provider, self.model)

    def snapshot(self) -> BreakerStateData:
        return self.data

    def effective_state(self) -> BreakerState:
        """OPEN whose cooldown has expired reads as HALF_OPEN (probe time)."""
        if self.data.state is BreakerState.OPEN and self._clock() >= self.data.cooldown_until:
            return BreakerState.HALF_OPEN
        return self.data.state

    def availability(self) -> tuple[bool, str]:
        """(is_available, reason). Reasons are actionable strings."""
        st = self.effective_state()
        if st is BreakerState.OPEN:
            remaining = max(0.0, self.data.cooldown_until - self._clock())
            return False, f"breaker open, cooldown {remaining:.1f}s remaining"
        if st is BreakerState.HALF_OPEN:
            if self.data.half_open_probes_in_flight >= self.config.half_open_max_probes:
                return False, "breaker half-open, probe budget exhausted"
            return True, "probe allowed"
        return True, "closed"

    # -- mutations ----------------------------------------------------------

    def allow_probe(self) -> bool:
        """Reserve a call slot; False means excluded."""
        ok, _ = self.availability()
        if ok:
            if self.effective_state() is BreakerState.HALF_OPEN:
                self.data.half_open_probes_in_flight += 1
                self.data.state = BreakerState.HALF_OPEN
            return True
        return False

    def record_success(self) -> None:
        if self.effective_state() is BreakerState.HALF_OPEN:
            self._close()
            return
        self.data.consecutive_failures = 0
        self.data.recent.append(1)
        del self.data.recent[: -self.config.window_size]

    def record_failure(self, retry_after: float | None = None) -> float:
        """Record a failure; returns the applied cooldown (0 if still closed)."""
        now = self._clock()
        st = self.effective_state()
        if st is BreakerState.OPEN:
            # Already cooling down (caller skipped allow_probe or a probe
            # raced): acknowledge without extending the cooldown.
            return max(0.0, self.data.cooldown_until - now)
        if st is BreakerState.HALF_OPEN:
            # A failed probe re-opens the breaker. Without a Retry-After hint
            # we fall back to the plain open cooldown, same as a cold trip.
            cd = (
                cooldown_from_retry_after(retry_after, self.config)
                if retry_after is not None
                else self.config.open_cooldown
            )
            return self._trip(now, cd)
        self.data.consecutive_failures += 1
        self.data.recent.append(0)
        del self.data.recent[: -self.config.window_size]
        cfg = self.config
        # recent stores 1=success / 0=failure: the ERROR rate is the fraction
        # of zeros, not the mean.
        failures = len(self.data.recent) - sum(self.data.recent)
        trip = self.data.consecutive_failures >= cfg.failure_threshold or (
            len(self.data.recent) >= cfg.min_samples
            and (failures / len(self.data.recent)) > cfg.error_rate_threshold
        )
        if trip:
            cd = (
                cooldown_from_retry_after(retry_after, cfg)
                if retry_after is not None
                else cfg.open_cooldown
            )
            return self._trip(now, cd)
        return 0.0

    # -- internals ----------------------------------------------------------

    def _trip(self, now: float, cooldown: float) -> float:
        self.data.state = BreakerState.OPEN
        self.data.opened_at = now
        self.data.cooldown_until = now + cooldown
        self.data.consecutive_failures = 0
        self.data.recent = []
        self.data.half_open_probes_in_flight = 0
        return cooldown

    def _close(self) -> None:
        self.data.state = BreakerState.CLOSED
        self.data.consecutive_failures = 0
        self.data.recent = []
        self.data.cooldown_until = 0.0
        self.data.half_open_probes_in_flight = 0
        self._half_open_successes = 0


class Unhealthy(Exception):
    pass


class BreakerRegistry:
    """All breakers + health flags; filters candidate plans (§7.3)."""

    def __init__(
        self,
        config: BreakerConfig | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config or BreakerConfig()
        self._clock = clock
        self.breakers: dict[str, CircuitBreaker] = {}
        self.health_ok: set[str] = set()  # keys explicitly marked healthy
        self.health_bad: set[str] = set()  # keys explicitly marked unhealthy
        self.events: list[ExclusionEvent] = []

    # -- lookup / health ----------------------------------------------------

    def breaker(self, provider: str, model: str) -> CircuitBreaker:
        k = _key(provider, model)
        if k not in self.breakers:
            self.breakers[k] = CircuitBreaker(provider, model, self.config, self._clock)
        return self.breakers[k]

    def mark_healthy(self, provider: str, model: str) -> None:
        k = _key(provider, model)
        self.health_bad.discard(k)
        self.health_ok.add(k)

    def mark_unhealthy(self, provider: str, model: str) -> None:
        k = _key(provider, model)
        self.health_ok.discard(k)
        self.health_bad.add(k)

    def eligibility(self, provider: str, model: str) -> tuple[bool, str]:
        """Combined health + breaker eligibility flag (fail closed on bad health)."""
        k = _key(provider, model)
        if k in self.health_bad:
            return False, "failing health checks"
        ok, reason = self.breaker(provider, model).availability()
        return (True, reason) if ok else (False, reason)

    # -- outcome recording --------------------------------------------------

    def record_success(self, provider: str, model: str) -> None:
        b = self.breaker(provider, model)
        b.allow_probe()  # no-op if closed; reserves nothing extra when open
        b.record_success()

    def record_failure(self, provider: str, model: str, retry_after: float | None = None) -> float:
        b = self.breaker(provider, model)
        b.allow_probe()
        return b.record_failure(retry_after)

    # -- candidate filtering -------------------------------------------------

    def filter_plans(self, candidates: list) -> tuple[list, list]:
        """Split CandidatePlan-shaped objects into (routable, blocked).

        Mirrors routers.free_only.FreeOnlyGate.filter semantics: a candidate
        whose PRIMARY target is excluded is dropped entirely — failover into
        an open breaker is exactly what §7.3 forbids.
        """
        routable, blocked = [], []
        for cand in candidates:
            provider = str(getattr(cand, "provider", ""))
            model = str(getattr(cand, "model", ""))
            ok, reason = self.eligibility(provider, model)
            if not ok:
                blocked.append((provider, model, reason))
                self.events.append(
                    ExclusionEvent(
                        event_id=uuid.uuid4().hex,
                        ts=self._clock(),
                        provider=provider,
                        model=model,
                        reason=reason,
                        breaker_state=self.breaker(provider, model).effective_state().value,
                    )
                )
            else:
                routable.append(cand)
        return routable, blocked

    # -- persistence ---------------------------------------------------------

    def dump_state(self) -> dict[str, dict]:
        """Serializable {key: state} map for storage-backed persistence."""
        return {k: b.snapshot().to_json() for k, b in self.breakers.items()}

    def restore_state(self, saved: dict[str, dict]) -> int:
        """Load a previously dumped state map; returns count restored."""
        n = 0
        for k, js in (saved or {}).items():
            try:
                provider, model = k.split("/", 1)
                if not provider or not model:
                    continue
                self.breakers[k] = CircuitBreaker(
                    provider, model, self.config, self._clock, BreakerStateData.from_json(js)
                )
                n += 1
            except (ValueError, TypeError, KeyError):
                # Corrupt entry: skip it rather than poison the whole registry.
                continue
        return n

    # -- storage-layer persistence (#7); best-effort by design ---------------

    def save(self, storage) -> None:
        """Persist every breaker as a record (kind=provider_breaker)."""
        for k, b in self.breakers.items():
            rec_id = k.replace("/", ":")
            existing = storage.get_record(RECORD_KIND, rec_id)
            payload = {
                "provider": b.provider,
                "model": b.model,
                **b.snapshot().to_json(),
            }
            if existing is None:
                try:
                    storage.insert_record(RECORD_KIND, rec_id, payload)
                except Exception:
                    pass  # best-effort: idempotent re-save races are fine
            else:
                try:
                    storage.update_record(RECORD_KIND, rec_id, existing["version"], payload)
                except Exception:
                    pass

    def load(self, storage) -> int:
        """Restore breaker states previously saved; returns count restored."""
        saved: dict[str, dict] = {}
        for rec in storage.list_records(RECORD_KIND, limit=10000):
            data = rec["data"] if isinstance(rec.get("data"), dict) else rec
            key = f"{data.get('provider', '')}/{data.get('model', '')}"
            if key != "/":
                saved[key] = data
        return self.restore_state(saved)


__all__ = [
    "RECORD_KIND",
    "BreakerConfig",
    "BreakerRegistry",
    "BreakerState",
    "BreakerStateData",
    "CircuitBreaker",
    "ExclusionEvent",
    "Unhealthy",
    "cooldown_from_retry_after",
]
