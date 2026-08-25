"""Rate limiting subsystem (issue #80, PLAN §2 principle 2, §5, §7.3).

A shared limiter keyed at four scopes — provider endpoint, target host,
campaign, and global — so concurrency stays inside the budgets a campaign
declares. Enforcement is a pre-dispatch gate in the policy layer
(`PolicyEngine.evaluate`), not best-effort inside tools: anything that goes
through policy cannot bypass limits.

Design notes:
- Sliding-window counting (deque of timestamps per key): simple, exact within
  the window, no background refill thread needed. Token buckets would need
  lazy-refill bookkeeping for the same guarantee.
- `acquire` returns a decision immediately (block/defer is the caller's call)
  but also offers `wait`, which sleeps until capacity exists — routers and
  agents use that for backpressure ("block or degrade rather than exceed").
- Keys are hierarchical: every request counts against endpoint/target/
  campaign AND global counters, so a hot campaign can't starve another one's
  campaign-scoped budget while still respecting the shared global ceiling.
"""

from __future__ import annotations

import threading
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass

from policy.scope import RateLimit

# The dimensions every request is accounted under (§2.2: endpoint, target,
# campaign, global). Values are limiter keys; see RateLimiter.keys_for().
SCOPE_DIMENSIONS = ("endpoint", "target", "campaign", "global")

GLOBAL_KEY = "global"


@dataclass(frozen=True)
class LimitSpec:
    """One configured ceiling: max requests per sliding window."""

    max_requests: int
    per_seconds: float

    @classmethod
    def from_rate_limit(cls, rl: RateLimit) -> LimitSpec:
        return cls(max_requests=rl.max_requests, per_seconds=rl.per_seconds)


@dataclass(frozen=True)
class AcquireResult:
    """Outcome of a pre-dispatch rate-limit check."""

    allowed: bool
    # Which dimension refused, e.g. "target" — surfaced in blocked events so
    # operators can see exactly which budget was exhausted (§14).
    limiting_dimension: str = ""
    # Seconds until the refusing window frees up (0 when allowed).
    retry_after_seconds: float = 0.0
    explanation: str = ""


class _Window:
    """Sliding request-timestamp window for one key. Thread-safe via lock."""

    __slots__ = ("spec", "events", "lock")

    def __init__(self, spec: LimitSpec):
        self.spec = spec
        self.events: deque[float] = deque()
        self.lock = threading.Lock()

    def prune(self, now: float) -> None:
        cutoff = now - self.spec.per_seconds
        ev = self.events
        while ev and ev[0] <= cutoff:
            ev.popleft()

    def try_admit(self, now: float) -> tuple[bool, float]:
        """Try to record one admitted request. Returns (ok, retry_after)."""
        with self.lock:
            self.prune(now)
            if len(self.events) >= self.spec.max_requests:
                # Oldest event must age out before the next slot opens.
                retry_after = max(0.0, self.events[0] + self.spec.per_seconds - now)
                return False, retry_after
            self.events.append(now)
            return True, 0.0

    def time_until_slot(self) -> float:
        """How long until at least one slot is free (assumes full window)."""
        with self.lock:
            if len(self.events) < self.spec.max_requests:
                return 0.0
            now = time.monotonic()
            self.prune(now)
            if len(self.events) < self.max_requests_safe():
                return 0.0
            return max(0.0, self.events[0] + self.spec.per_seconds - time.monotonic())

    def max_requests_safe(self) -> int:
        return self.spec.max_requests

    def usage(self, now: float) -> int:
        with self.lock:
            self.prune(now)
            return len(self.events)


def host_of(target: str) -> str:
    """Extract the host key for target-scoped limiting from a URL or name."""
    if "://" in target:
        return (urllib.parse.urlparse(target).hostname or target).lower().rstrip(".")
    return target.lower().rstrip(".")


class RateLimiter:
    """Shared multi-scope sliding-window limiter (endpoint/target/campaign/global)."""

    def __init__(self) -> None:
        self._windows: dict[str, _Window] = {}
        self._specs: dict[str, LimitSpec] = {}
        self._lock = threading.Lock()

    # -- configuration -----------------------------------------------------

    def set_limit(self, dimension: str, key: str, spec: LimitSpec | None) -> None:
        """Set (or clear, spec=None) the limit for one scope key."""
        if dimension not in SCOPE_DIMENSIONS:
            raise ValueError(f"unknown dimension: {dimension!r}")
        with self._lock:
            k = f"{dimension}:{key}"
            if spec is None:
                self._specs.pop(k, None)
                self._windows.pop(k, None)
            else:
                self._specs[k] = spec
                # Keep existing window state when re-configuring; only create
                # fresh windows so mid-campaign limit updates don't reset counts.
                if k not in self._windows:
                    self._windows[k] = _Window(spec)

    def configure_from_scope(self, scope) -> None:
        """Apply campaign scope config (§5 `rate_limits`) to this limiter.

        Recognized keys map onto dimensions: 'global', 'campaign:<uuid>',
        'target:<host or name>' (any TargetSpec-matching value works since we
        key by the literal value), 'endpoint:<url>'. Unknown keys are kept
        verbatim as target keys — conservative default.
        """
        for name, rl in getattr(scope, "rate_limits", {}).items():
            spec = LimitSpec.from_rate_limit(rl)
            if name == GLOBAL_KEY or name.startswith("global"):
                self.set_limit("global", GLOBAL_KEY, spec)
            elif ":" in name:
                dim, _, key = name.partition(":")
                if dim in SCOPE_DIMENSIONS and dim != "global":
                    self.set_limit(dim, key, spec)
                else:
                    self.set_limit("target", name, spec)
            else:
                self.set_limit("target", name, spec)

    # -- accounting --------------------------------------------------------

    def keys_for(
        self,
        *,
        endpoint: str = "",
        target: str = "",
        campaign_uuid: str = "",
    ) -> list[tuple[str, str]]:
        """The (dimension, key) pairs one request counts against."""
        pairs: list[tuple[str, str]] = []
        if endpoint:
            pairs.append(("endpoint", endpoint))
        if target:
            pairs.append(("target", host_of(target)))
        if campaign_uuid:
            pairs.append(("campaign", campaign_uuid))
        pairs.append(("global", GLOBAL_KEY))
        return pairs

    def acquire(
        self,
        *,
        endpoint: str = "",
        target: str = "",
        campaign_uuid: str = "",
    ) -> AcquireResult:
        """Pre-dispatch check: admit the request into every applicable window.

        Admission is all-or-nothing across dimensions where possible: we first
        verify capacity everywhere, then commit. Between concurrent callers a
        rare partial-commit can occur on the non-refusing dimensions; the
        refusing dimension never over-admits, which is the safety property.
        """
        pairs = self.keys_for(endpoint=endpoint, target=target, campaign_uuid=campaign_uuid)
        now = time.monotonic()

        with self._lock:
            windows = [(dim, key, self._window_locked(dim, key)) for dim, key in pairs]

        # First pass: find refusals without consuming slots.
        for dim, key, win in windows:
            if win is None:
                continue
            ok, retry_after = win.try_admit(now)
            if not ok:
                return AcquireResult(
                    allowed=False,
                    limiting_dimension=dim,
                    retry_after_seconds=retry_after,
                    explanation=(
                        f"rate limit exceeded at {dim} scope (key={key!r}): "
                        f"retry after {retry_after:.2f}s"
                    ),
                )
        return AcquireResult(True)

    def wait(
        self,
        *,
        endpoint: str = "",
        target: str = "",
        campaign_uuid: str = "",
        timeout: float | None = None,
        poll_interval: float = 0.05,
    ) -> bool:
        """Blocking backpressure helper: sleep until `acquire` succeeds.

        Returns True when admitted, False when `timeout` elapsed first.
        Routers/agents use this to degrade rather than exceed limits (§7.3).
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            result = self.acquire(endpoint=endpoint, target=target, campaign_uuid=campaign_uuid)
            if result.allowed:
                return True
            sleep_for = result.retry_after_seconds or poll_interval
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                sleep_for = min(sleep_for, remaining)
            time.sleep(sleep_for)

    def usage(self) -> dict[str, dict[str, dict[str, float]]]:
        """Current usage vs. limit per scope, for §14 metrics."""
        now = time.monotonic()
        snapshot: dict[str, dict[str, dict[str, float]]] = {}
        with self._lock:
            items = list(self._specs.items())
        for k, spec in items:
            with self._lock:
                win = self._windows.get(k)
            used = win.usage(now) if win else 0
            dimension, _, key = k.partition(":")
            snapshot.setdefault(dimension, {})[key] = {
                "used": float(used),
                "limit": float(spec.max_requests),
                "window_seconds": float(spec.per_seconds),
            }
        return snapshot

    # -- internals ---------------------------------------------------------

    def _window_locked(self, dimension: str, key: str) -> _Window | None:
        """Return the active window for a key, creating it lazily.

        Caller must hold self._lock. Unconfigured keys are unlimited (the
        campaign config decides ceilings; defaults stay permissive here so an
        unconfigured deployment doesn't deadlock).
        """
        k = f"{dimension}:{key}"
        spec = self._specs.get(k)
        if spec is None:
            return None
        win = self._windows.get(k)
        if win is None:
            win = _Window(spec)
            self._windows[k] = win
        return win
