"""Router pool subsystem (spec §7, §8).

Public surface:

* :class:`RouterPool` — coordinator that owns the routers, the
  breaker store, the dead-letter queue, and the usage accountant.
* :class:`RoutingTask`, :class:`RoutingOutcome` — input and output.
* :class:`mavr.routers.policies.MergePolicy` — pluggable merge policy.
* :class:`mavr.routers.circuit_breaker.CircuitBreakerStore`
* :class:`mavr.routers.usage.UsageAccountant`
* :class:`mavr.routers.dead_letter.DeadLetterQueue`
* :class:`mavr.routers.free_filter.FreeOnlyViolation`
"""
from __future__ import annotations

from mavr.routers.circuit_breaker import BreakerConfig, CircuitBreakerStore
from mavr.routers.dead_letter import DeadLetterQueue
from mavr.routers.free_filter import (
    FreeOnlyViolation,
    eligible_candidates,
    require_paid_override,
)
from mavr.routers.policies import (
    best_score_within_budget,
    consensus,
    diversity,
    fastest_eligible,
)
from mavr.routers.pool import (
    BaseRouter,
    CostAwareRouter,
    DiversityRouter,
    RouterPool,
    RoutingOutcome,
    ScoreRouter,
)
from mavr.routers.usage import UsageAccountant

__all__ = [
    "BaseRouter",
    "BreakerConfig",
    "CircuitBreakerStore",
    "CostAwareRouter",
    "DeadLetterQueue",
    "DiversityRouter",
    "FreeOnlyViolation",
    "RouterPool",
    "RoutingOutcome",
    "ScoreRouter",
    "UsageAccountant",
    "best_score_within_budget",
    "consensus",
    "diversity",
    "eligible_candidates",
    "fastest_eligible",
    "require_paid_override",
]
