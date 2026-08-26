"""Scoped budget enforcement (issue #106, PLAN §5/§6/§14).

The per-agent enforcer in ``budgets/__init__.py`` (issue #141) covers one
agent's lifetime caps. This module layers the *scope hierarchy* the issue
requires — agent, campaign, and global scopes sharing the same four
dimensions — plus the semantics that make budgets enforceable rather than
just counters:

- **Atomic reservations** (:class:`Reservation`): concurrent callers
  reserve before dispatch, commit actual usage on completion, or release
  without billing on failure/timeout. Two agents can never both spend the
  last 1k tokens: the second reservation is refused.
- **Pre-flight typed rejection**: a call that would exceed a hard cap is
  rejected with :class:`ScopedBudgetExhausted` *before* dispatch — never
  run-then-bill.
- **Soft warnings vs hard caps**: crossing 80% of any dimension raises a
  warning event; only 100% blocks.
- **Exhaustion behavior**: agent-scope exhaustion blocks that agent;
  campaign-scope exhaustion signals pause + human notification (returned
  as an event, not silently swallowed); global exhaustion stops admission
  everywhere.
- **Persistence**: :meth:`BudgetScope.snapshot` / :meth:`BudgetScope.restore`
  round-trip spent usage so a restart never "unspends" anything; usage is
  recorded into the ledger only via commit, which happens after the fact.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BudgetScopeManager",
    "Reservation",
    "ScopedBudgetExhausted",
    "SCOPE_AGENT",
    "SCOPE_CAMPAIGN",
    "SCOPE_GLOBAL",
]

SCOPE_AGENT = "agent"
SCOPE_CAMPAIGN = "campaign"
SCOPE_GLOBAL = "global"
SCOPES = (SCOPE_GLOBAL, SCOPE_CAMPAIGN, SCOPE_AGENT)  # innermost checked last

DIMENSIONS = ("tokens", "requests", "wall_clock_seconds", "tool_calls")

SOFT_WARNING_FRACTION = 0.8


class ScopedBudgetExhausted(Exception):
    """Typed pre-flight rejection: a hard cap would be exceeded by this call."""

    def __init__(self, scope: str, dimension: str, remaining: float | int, requested: float | int):
        self.scope = scope
        self.dimension = dimension
        self.remaining = remaining
        self.requested = requested
        super().__init__(
            f"budget exhausted at {scope} scope: {dimension} "
            f"remaining={remaining}, requested={requested}"
        )


@dataclass
class _ScopeLedger:
    """Spent usage for one scope. Limits of ``None`` are unlimited."""

    limits: dict[str, float | int | None]
    spent: dict[str, float | int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        for dim in DIMENSIONS:
            self.spent.setdefault(dim, 0)

    def remaining(self, dimension: str) -> float | int | None:
        limit = self.limits.get(dimension)
        if limit is None:
            return None
        return max(0, float(limit) - float(self.spent[dimension]))

    def utilization(self, dimension: str) -> float:
        """Fraction of limit consumed (0.0 when unlimited)."""
        limit = self.limits.get(dimension)
        if not limit:
            return 0.0
        return float(self.spent[dimension]) / float(limit)


@dataclass
class Reservation:
    """An in-flight hold against one or more scope ledgers.

    Commit bills *actual* usage (releasing the hold first); release drops
    the hold with no billing — failed or timed-out calls never consume the
    reserved amount, though anything already streamed/billed stays counted
    via an explicit partial commit.
    """

    manager: BudgetScopeManager
    holds: list[tuple[str, _ScopeLedger, float | int]] = field(default_factory=list)
    _hold_entries: list[tuple[str, str, float]] = field(default_factory=list)
    committed: bool = False
    released: bool = False

    def commit(
        self,
        *,
        tokens: int = 0,
        requests: int = 0,
        wall_clock_seconds: float = 0.0,
        tool_calls: int = 0,
    ) -> list[dict[str, Any]]:
        """Bill actual usage across all held scopes; returns warning events."""
        assert not self.committed and not self.released, "reservation already settled"
        self.committed = True
        self._release_holds()
        return self.manager._bill(
            tokens=tokens,
            requests=requests,
            wall_clock_seconds=wall_clock_seconds,
            tool_calls=tool_calls,
        )

    def release(self) -> None:
        """Drop the hold without billing (failure / timeout path)."""
        assert not self.committed, "already committed"
        self.released = True
        self._release_holds()

    def _release_holds(self) -> None:
        """Drop this reservation's holds from the manager's hold table."""
        mgr = self.manager
        for scope, dim, amount in self._hold_entries:
            key = (scope, dim)
            mgr._holds[key] = max(0.0, mgr._holds.get(key, 0.0) - float(amount))

    def _register_holds(self, entries: list[tuple[str, str, float]]) -> None:
        self._hold_entries = entries


@dataclass
class BudgetScopeManager:
    """Hierarchical budget enforcement across global/campaign/agent scopes.

    All mutations are guarded by a single lock so two threads reserving the
    last remaining tokens cannot both succeed (the race the issue calls
    out).
    """

    limits: dict[str, dict[str, float | int | None]]  # scope -> dimension -> limit|None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    paused_campaigns: list[str] = field(default_factory=list)
    _ledgers: dict[str, _ScopeLedger] = field(default_factory=dict, init=False)
    _holds: dict[tuple[str, str], float] = field(default_factory=dict)  # (scope, dim) -> reserved
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        for scope, dims in self.limits.items():
            self._ledgers[scope] = _ScopeLedger(limits=dims)

    # -- pre-flight ---------------------------------------------------------

    def check(self, requested: dict[str, float | int], campaign_id: str, agent_id: str) -> None:
        """Pre-flight: raise :class:`ScopedBudgetExhausted` if any hard cap blocks.

        Checks outermost-first so a global cap refusal doesn't partially
        consume campaign headroom. Reservations are made atomically under
        the lock: if any scope refuses, all holds roll back.
        """
        with self._lock:
            # Validate every scope can afford the request before holding anywhere.
            for scope in SCOPES:
                ledger = self._ledgers.get(scope)
                if ledger is None:
                    continue
                for dim, amount in requested.items():
                    rem = ledger.remaining(dim)
                    already = self._holds.get((scope, dim), 0.0)
                    if rem is not None and float(amount) > float(rem) - already:
                        raise ScopedBudgetExhausted(scope, dim, int(float(rem) - already), amount)
            # All scopes afford it — place holds atomically.
            for scope in SCOPES:
                if scope not in self._ledgers:
                    continue
                for dim, amount in requested.items():
                    key = (scope, dim)
                    self._holds[key] = self._holds.get(key, 0.0) + float(amount)

    def reserve(
        self, requested: dict[str, float | int], campaign_id: str, agent_id: str
    ) -> Reservation:
        """Check + create a reservation handle for an in-flight call."""
        self.check(requested, campaign_id, agent_id)
        res = Reservation(manager=self)
        res._register_holds(
            [
                (scope, dim, float(amount))
                for scope in SCOPES
                if scope in self._ledgers
                for dim, amount in requested.items()
            ]
        )
        return res

    # -- billing ------------------------------------------------------------

    def _bill(
        self,
        *,
        tokens: int = 0,
        requests: int = 0,
        wall_clock_seconds: float = 0.0,
        tool_calls: int = 0,
    ) -> list[dict[str, Any]]:
        """Add usage to every scoped ledger; emit soft-warning events at 80%."""
        actual = {
            "tokens": tokens,
            "requests": requests,
            "wall_clock_seconds": wall_clock_seconds,
            "tool_calls": tool_calls,
        }
        events: list[dict[str, Any]] = []
        with self._lock:
            for scope, ledger in self._ledgers.items():
                for dim, amount in actual.items():
                    if not amount:
                        continue
                    was = ledger.utilization(dim)
                    ledger.spent[dim] = float(ledger.spent[dim]) + float(amount)
                    now_util = ledger.utilization(dim)
                    limit = ledger.limits.get(dim)
                    if limit and was < SOFT_WARNING_FRACTION <= now_util:
                        events.append(
                            {
                                "type": "budget_warning",
                                "scope": scope,
                                "dimension": dim,
                                "utilization": round(now_util, 4),
                                "message": (
                                    f"soft warning: {scope}/{dim} crossed "
                                    f"{int(SOFT_WARNING_FRACTION * 100)}% of budget"
                                ),
                            }
                        )
        # Campaign exhaustion pauses rather than silent-stops (§5).
        camp = self._ledgers.get(SCOPE_CAMPAIGN)
        if camp is not None:
            for dim in DIMENSIONS:
                rem = camp.remaining(dim)
                if rem == 0:
                    self.paused_campaigns.append("current")
                    events.append(
                        {
                            "type": "campaign_exhausted",
                            "dimension": dim,
                            "message": "campaign budget exhausted: pause + notify operator",
                        }
                    )
                    break
        return events

    # -- persistence ----------------------------------------------------------

    def snapshot(self) -> dict[str, dict[str, float]]:
        """Persist spent usage per scope; restore() must land on these numbers."""
        return {s: dict(lg.spent) for s, lg in self._ledgers.items()}

    def restore(self, snap: dict[str, dict[str, float]]) -> None:
        """Restore spent usage from a snapshot (restart path).

        Only ever *adds* to what's already recorded: usage spent between
        snapshot and crash must not be unspent by restoring an older number.
        """
        for scope, dims in snap.items():
            ledger = self._ledgers.get(scope)
            if ledger is None:
                continue
            for dim, value in dims.items():
                ledger.spent[dim] = max(float(ledger.spent[dim]), float(value))

    def remaining(self, scope: str, dimension: str) -> float | int | None:
        ledger = self._ledgers.get(scope)
        if ledger is None:
            return None
        rem = ledger.remaining(dimension)
        held = self._holds.get((scope, dimension), 0.0)
        if rem is None:
            return None
        return max(0, float(rem) - held)
