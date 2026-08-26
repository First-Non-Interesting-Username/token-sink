"""Per-agent budget enforcement (issue #141, PLAN §6, §14, §21).

PLAN §6 requires *per-agent budgets* — "Per-agent token, request, time,
and tool budgets" — as lifetime/cumulative caps (distinct from rate
windows, which issue #80's limiter already covers). This module is the
single authority for those rules:

- :class:`AgentBudget` — the declared caps: max tokens, max requests,
  wall-clock seconds, max tool calls. Attached at agent creation.
- :class:`BudgetLedger` — cumulative usage per dimension with an
  injectable clock; supports reserving/releasing in-flight calls.
- :class:`BudgetEnforcer` — the two enforcement points from the issue:
  1. **Pre-call check** (:meth:`BudgetEnforcer.pre_call`): deny before a
     call starts if any cap is exhausted.
  2. **Mid-run hard stop**: a call that crosses a boundary is allowed to
     finish (never killed mid-stream) but its overrun is attributed to
     the owning agent (:meth:`record_usage` returns ``overrun=True``),
     and the enforcer flips to exhausted so no further calls are admitted
     — "never exceed by more than one in-flight call".
- Subagent rule: a subagent's budget must be ≤ its parent's *remaining*
  budget (:func:`derive_subagent_budget`).
- Blocked events: denials produce an actionable explanation string naming
  the exhausted dimension and remaining/limit values, suitable for
  surfacing as blocked events (§5) and non-transient retry classification
  (per issue #91's taxonomy).

Tool-budget gating integrates at the same pre-call point: a tool call
denied for budget produces the same blocked-event shape.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "AgentBudget",
    "BudgetDecision",
    "BudgetDimension",
    "BudgetEnforcer",
    "BudgetExhaustedError",
    "BudgetLedger",
    "derive_subagent_budget",
]


class BudgetDimension:
    """The four budget dimensions PLAN §6 names."""

    TOKENS = "tokens"
    REQUESTS = "requests"
    WALL_CLOCK_SECONDS = "wall_clock_seconds"
    TOOL_CALLS = "tool_calls"

    ALL = (TOKENS, REQUESTS, WALL_CLOCK_SECONDS, TOOL_CALLS)


@dataclass(frozen=True)
class AgentBudget:
    """Declared caps for one agent. ``None`` means unlimited."""

    max_tokens: int | None = None
    max_requests: int | None = None
    max_wall_clock_seconds: float | None = None
    max_tool_calls: int | None = None

    def limit_for(self, dimension: str) -> int | float | None:
        return {
            BudgetDimension.TOKENS: self.max_tokens,
            BudgetDimension.REQUESTS: self.max_requests,
            BudgetDimension.WALL_CLOCK_SECONDS: self.max_wall_clock_seconds,
            BudgetDimension.TOOL_CALLS: self.max_tool_calls,
        }[dimension]

    def as_dict(self) -> dict[str, float | int | None]:
        return {
            "max_tokens": self.max_tokens,
            "max_requests": self.max_requests,
            "max_wall_clock_seconds": self.max_wall_clock_seconds,
            "max_tool_calls": self.max_tool_calls,
        }


class BudgetExhaustedError(ValueError):
    """A subagent budget was requested larger than the parent remainder."""


def derive_subagent_budget(parent_budget: AgentBudget, parent_ledger: BudgetLedger) -> AgentBudget:
    """Subagent budget must be ≤ parent's remaining budget on every dimension.

    Unlimited parents pass through unlimited children only when the parent
    itself is unlimited on that dimension.
    """
    remaining = parent_ledger.remaining(parent_budget)
    limits: dict[str, int | float | None] = {}
    for dim in BudgetDimension.ALL:
        rem = remaining[dim]
        limits[dim] = None if rem is None else rem  # None = unlimited inherits unlimited
    return AgentBudget(
        max_tokens=limits[BudgetDimension.TOKENS],  # type: ignore[arg-type]
        max_requests=limits[BudgetDimension.REQUESTS],  # type: ignore[arg-type]
        max_wall_clock_seconds=limits[BudgetDimension.WALL_CLOCK_SECONDS],  # type: ignore[arg-type]
        max_tool_calls=limits[BudgetDimension.TOOL_CALLS],  # type: ignore[arg-type]
    )


@dataclass(frozen=True)
class BudgetDecision:
    """Outcome of a pre-call budget check (blocked-event ready)."""

    allowed: bool
    dimension: str = ""  # which cap refused ("tokens", ...)
    explanation: str = ""

    @classmethod
    def ok(cls) -> BudgetDecision:
        return cls(allowed=True)

    @classmethod
    def blocked(cls, dimension: str, used: float | int, limit: float | int) -> BudgetDecision:
        return cls(
            allowed=False,
            dimension=dimension,
            explanation=(
                f"budget exhausted: {dimension} {used}/{limit} — "
                f"no further calls admitted this run; classify as non-transient"
            ),
        )


@dataclass
class BudgetLedger:
    """Cumulative usage counters plus start time, with injectable clock.

    Wall-clock consumption has two sources that add up: real time since
    ``started_at`` (the run actually running) and explicitly recorded
    ``duration_seconds`` from calls whose time should count even though the
    enforcer's virtual clock may not advance in tests.
    """

    started_at: float | None = None
    now: Callable[[], float] = time.monotonic
    tokens_used: int = 0
    requests_made: int = 0
    wall_clock_seconds_used: float = 0.0
    tool_calls_made: int = 0

    def __post_init__(self) -> None:
        # Anchor to the injected clock, not the real one, so virtual clocks work.
        if self.started_at is None:
            self.started_at = self.now()

    def elapsed(self) -> float:
        assert self.started_at is not None
        return max(0.0, self.now() - self.started_at) + self.wall_clock_seconds_used

    def remaining(self, budget: AgentBudget | None = None) -> dict[str, float | int | None]:
        """Remaining allowance per dimension; ``None`` = unlimited."""
        if budget is None:
            return {dim: None for dim in BudgetDimension.ALL}
        out: dict[str, float | int | None] = {}
        for dim in BudgetDimension.ALL:
            limit = budget.limit_for(dim)
            if limit is None:
                out[dim] = None
            elif dim == BudgetDimension.TOKENS:
                out[dim] = max(0, int(limit) - self.tokens_used)
            elif dim == BudgetDimension.REQUESTS:
                out[dim] = max(0, int(limit) - self.requests_made)
            elif dim == BudgetDimension.TOOL_CALLS:
                out[dim] = max(0, int(limit) - self.tool_calls_made)
            else:
                out[dim] = max(0.0, float(limit) - self.elapsed())
        return out


class BudgetEnforcer:
    """Two-point enforcement: pre-call admission + mid-call overrun accounting."""

    def __init__(self, budget: AgentBudget, ledger: BudgetLedger | None = None) -> None:
        self.budget = budget
        self.ledger = ledger or BudgetLedger()
        self.exhausted_dimension: str | None = None
        self.overrun_events: list[dict[str, float | int | str]] = []

    # -- pre-call gate ---------------------------------------------------------

    def pre_call(self, *, is_tool_call: bool = False) -> BudgetDecision:
        """Deny before dispatch when any lifetime cap is spent.

        Once a dimension is exhausted it stays exhausted (hard stop): no
        further calls are admitted, so the run never exceeds its budget by
        more than the one call that crossed the boundary.
        """
        if self.exhausted_dimension is not None:
            return BudgetDecision(
                allowed=False,
                dimension=self.exhausted_dimension,
                explanation=(
                    f"budget previously exhausted on '{self.exhausted_dimension}'; "
                    f"hard stop remains in effect"
                ),
            )
        remaining = self.ledger.remaining(self.budget)
        for dim in BudgetDimension.ALL:
            rem = remaining[dim]
            if rem is not None and rem <= 0:
                self.exhausted_dimension = dim
                limit = self.budget.limit_for(dim)
                assert limit is not None
                used = self._used_for(dim)
                return BudgetDecision.blocked(dim, used, limit)
        _ = is_tool_call  # tool gating uses the same four dimensions today
        return BudgetDecision.ok()

    # -- usage recording --------------------------------------------------------

    def record_usage(
        self,
        *,
        tokens: int = 0,
        request: bool = False,
        tool_call: bool = False,
        duration_seconds: float = 0.0,
    ) -> dict[str, float | int | str] | None:
        """Attribute usage to the owning agent.

        Returns an overrun event dict when this call crossed one or more
        boundaries — the caller still gets its result, but the overrun is
        attributed here (§21 accurate attribution) and further calls are
        hard-stopped. Returns ``None`` when within budget.
        """
        before = self.ledger.remaining(self.budget)
        self.ledger.tokens_used += tokens
        self.ledger.wall_clock_seconds_used += duration_seconds
        if request:
            self.ledger.requests_made += 1
        if tool_call:
            self.ledger.tool_calls_made += 1

        overruns: list[str] = []
        for dim in BudgetDimension.ALL:
            limit = self.budget.limit_for(dim)
            if limit is None:
                continue
            was_before = before[dim]
            if was_before is not None and was_before > 0:
                after = self._used_for(dim)
                if after > limit:
                    overruns.append(dim)
                    self.exhausted_dimension = self.exhausted_dimension or dim
        if not overruns:
            return None
        event = {
            "overran_dimensions": ",".join(overruns),
            "tokens": tokens,
            "duration_seconds": duration_seconds,
            "attribution": "owning_agent",
            "detail": "call crossed budget boundary; result kept, further calls denied",
        }
        self.overrun_events.append(event)
        return event

    def blocked_event(self, decision: BudgetDecision) -> dict[str, str]:
        """Blocked-event shape for policy-engine integration (§5)."""
        return {
            "blocked_reason": "budget_exhausted",
            "dimension": decision.dimension,
            "explanation": decision.explanation,
        }

    # -- helpers -----------------------------------------------------------------

    def _used_for(self, dim: str) -> float | int:
        if dim == BudgetDimension.TOKENS:
            return self.ledger.tokens_used
        if dim == BudgetDimension.REQUESTS:
            return self.ledger.requests_made
        if dim == BudgetDimension.TOOL_CALLS:
            return self.ledger.tool_calls_made
        return round(self.ledger.elapsed(), 6)
