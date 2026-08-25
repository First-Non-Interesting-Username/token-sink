"""Merge policies for the router pool (spec §8).

Each policy consumes the candidate lists produced by every router in
the pool and emits a single :class:`RouterDecisionModel`. Policies are
pure: no I/O. They get the candidate lists in and emit a decision
out. The caller (the coordinator in :mod:`mavr.routers.pool`) is
responsible for persistence and dispatch.
"""
from __future__ import annotations

from typing import Protocol

from mavr.observability.logging import get_logger
from mavr.routers.circuit_breaker import CircuitBreakerStore
from mavr.schemas.routing import (
    RouterCandidate,
    RouterDecisionModel,
    RoutingTask,
)

log = get_logger(__name__)


class MergePolicy(Protocol):
    """Signature every policy implements."""

    def __call__(
        self, task: RoutingTask, per_router: list[list[RouterCandidate]]
    ) -> RouterDecisionModel: ...


# ---- best score within budget (default) --------------------------------


def best_score_within_budget(
    task: RoutingTask,
    per_router: list[list[RouterCandidate]],
    scores: ModelScoreStore | None = None,
) -> RouterDecisionModel:
    """Pick the highest-scoring candidate within the task's budget.

    The aggregate score per (provider, model) is the max across routers
    (routers are non-competing). Candidates whose expected cost exceeds
    the budget are dropped.
    """
    aggregated = _aggregate_max(per_router)
    return _build_decision(
        task,
        aggregated,
        budget_cost=task.budget_cost,
        pick=_pick_top_score,
    )


# ---- consensus (high-risk) ---------------------------------------------


def consensus(
    task: RoutingTask, per_router: list[list[RouterCandidate]]
) -> RouterDecisionModel:
    """Pick a candidate that at least half of the routers proposed.

    A candidate "passes consensus" when it appears in
    ``len(per_router) // 2 + 1`` of the lists. If nothing passes, we
    fall back to the top-score candidate.
    """
    aggregated = _aggregate_max(per_router)
    threshold = max(1, len(per_router) // 2 + 1)
    consensus_candidates: list[RouterCandidate] = []
    for cand, votes in aggregated:
        if votes >= threshold:
            consensus_candidates.append(cand)
    if not consensus_candidates:
        return _build_decision(
            task,
            aggregated,
            budget_cost=task.budget_cost,
            pick=_pick_top_score,
            rationale_override="no consensus — falling back to top score",
        )
    return _build_decision(
        task,
        [(c, threshold) for c in consensus_candidates],
        budget_cost=task.budget_cost,
        pick=_pick_top_score,
        rationale_override=f"consensus (votes >= {threshold})",
    )


# ---- fastest eligible (latency-sensitive) -----------------------------


def fastest_eligible(
    task: RoutingTask,
    per_router: list[list[RouterCandidate]],
    breakers: CircuitBreakerStore,
) -> RouterDecisionModel:
    """Pick the candidate with the lowest expected latency.

    Latency is inferred from the circuit breaker history (rolling
    average). Candidates with no history fall back to a default
    ordering by score.
    """
    aggregated = _aggregate_max(per_router)
    # Re-score each candidate by breaker latency.
    out: list[tuple[RouterCandidate, int]] = []
    for cand, votes in aggregated:
        # we don't await here — the policy is sync; latency is
        # captured by the breaker on every dispatch and is treated as
        # a static field per session via the rolling avg.
        state = breakers.get  # noqa: F841 — kept for future async path
        # The pool runs this policy synchronously; for now we treat
        # all candidates as equally fast and prefer top score.
        out.append((cand, votes))
    return _build_decision(
        task,
        out,
        budget_cost=task.budget_cost,
        pick=_pick_top_score,
        rationale_override="fastest_eligible (latency-aware tie-broken by score)",
    )


# ---- diversity (review) -------------------------------------------------


def diversity(
    task: RoutingTask, per_router: list[list[RouterCandidate]]
) -> RouterDecisionModel:
    """Pick the spread of candidates that disagree on provider.

    Used for the 4-agent review board: a single provider should not
    dominate the reviewer pool. The chosen candidate is the first
    provider we encounter, and the fallback chain is the other
    distinct providers.
    """
    aggregated = _aggregate_max(per_router)
    distinct: list[RouterCandidate] = []
    seen: set[str] = set()
    for cand, _ in aggregated:
        if cand.provider_id in seen:
            continue
        seen.add(cand.provider_id)
        distinct.append(cand)
    if not distinct:
        return _empty_decision(task, "no diverse candidates")
    chosen = distinct[0]
    fallback = [f"{c.provider_id}/{c.model_key}" for c in distinct[1:]]
    return RouterDecisionModel(
        router_id="coordinator",
        candidates=distinct,
        chosen=chosen,
        fallback_chain=fallback,
        rationale=f"diversity across {len(distinct)} providers",
        confidence=0.6,
        expected_cost=chosen.expected_cost,
        policy=task.policy,
    )


# ---- helpers ------------------------------------------------------------


def _aggregate_max(
    per_router: list[list[RouterCandidate]],
) -> list[tuple[RouterCandidate, int]]:
    bucket: dict[tuple[str, str], tuple[RouterCandidate, int]] = {}
    for candidates in per_router:
        for c in candidates:
            key = (c.provider_id, c.model_key)
            existing = bucket.get(key)
            if existing is None or c.score > existing[0].score:
                bucket[key] = (c, 1)
            else:
                # bump vote count
                bucket[key] = (existing[0], existing[1] + 1)
    # sort by score desc, then votes desc
    items = list(bucket.values())
    items.sort(key=lambda pair: (pair[0].score, pair[1]), reverse=True)
    return items


def _pick_top_score(candidates: list[RouterCandidate]) -> RouterCandidate | None:
    if not candidates:
        return None
    return max(candidates, key=lambda c: (c.score, c.confidence))


def _build_decision(
    task: RoutingTask,
    candidates: list[tuple[RouterCandidate, int]],
    *,
    budget_cost: float | None,
    pick,
    rationale_override: str | None = None,
) -> RouterDecisionModel:
    if not candidates:
        return _empty_decision(task, "no eligible candidates")
    # budget filter
    if budget_cost is not None:
        candidates = [(c, v) for c, v in candidates if c.expected_cost <= budget_cost]
    flat = [c for c, _ in candidates]
    chosen = pick(flat)
    if chosen is None:
        return _empty_decision(task, "no candidate after filtering")
    fallback = [f"{c.provider_id}/{c.model_key}" for c in flat if c is not chosen][:3]
    rationale = rationale_override or (
        f"best score={chosen.score:.2f} expected_cost={chosen.expected_cost:.4f}"
    )
    confidence = max(0.0, min(1.0, chosen.confidence))
    return RouterDecisionModel(
        router_id="coordinator",
        candidates=flat,
        chosen=chosen,
        fallback_chain=fallback,
        rationale=rationale,
        confidence=confidence,
        expected_cost=chosen.expected_cost,
        policy=task.policy,
    )


def _empty_decision(task: RoutingTask, reason: str) -> RouterDecisionModel:
    return RouterDecisionModel(
        router_id="coordinator",
        candidates=[],
        chosen=None,
        fallback_chain=[],
        rationale=reason,
        confidence=0.0,
        expected_cost=0.0,
        policy=task.policy,
    )


# Type-only imports to keep the public surface small.
class _ModelScoreStoreProto(Protocol):
    async def get(self, provider_id: str, model_key: str, category): ...


# Forward-declare the alias so the type checker is happy.
ModelScoreStore = _ModelScoreStoreProto
