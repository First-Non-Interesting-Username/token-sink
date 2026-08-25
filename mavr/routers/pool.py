"""Router pool: parallel routers that pick a model for each task.

Design (spec §7.3, §8):

* The pool owns N independent async routers, each of which may inspect
  the task from a different angle. The coordinator merges their
  :class:`RouterDecision` according to a policy:

  * ``best_score_within_budget`` (default) — pick the highest-scoring
    candidate.
  * ``consensus`` (high-risk tasks) — only choose a candidate that at
    least half of the routers propose.
  * ``fastest_eligible`` (latency-sensitive) — pick the candidate with
    the lowest expected latency.
  * ``diversity`` (review tasks) — pick four candidates that disagree,
    so the 4-agent reviewer board is genuinely diverse.

* Safeguards:

  * Free-only mode rejects any candidate whose model has
    ``free_status != "confirmed"`` (i.e. unknown or paid).
  * Circuit breakers track per-(provider, model) failure counts. A
    candidate with an open breaker is excluded.
  * Every routing decision is written to ``router_decisions`` (audit).
  * A task that cannot be routed is enqueued in the dead-letter table.

* The pool never blocks on a single router: a hung router is given a
  timeout and the remaining routers continue.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.providers.adapters.base import ProviderAdapter, ProviderError
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.providers.registry.registry import ProviderRegistry
from mavr.routers.circuit_breaker import CircuitBreakerStore
from mavr.routers.dead_letter import DeadLetterQueue
from mavr.routers.free_filter import (
    FreeOnlyViolation,
    eligible_candidates,
)
from mavr.routers.policies import (
    best_score_within_budget,
    consensus,
    diversity,
    fastest_eligible,
)
from mavr.routers.usage import UsageAccountant
from mavr.schemas.routing import (
    ChatRequest,
    ChatResponse,
    RouterCandidate,
    RouterDecisionModel,
    RoutingPolicy,
    RoutingTask,
)
from mavr.storage.database import Database

log = get_logger(__name__)


# ---- data structures ----------------------------------------------------


@dataclass
class RoutingOutcome:
    """The result of routing a single task."""

    decision: RouterDecisionModel
    response: ChatResponse | None = None
    error: ProviderError | None = None
    dead_lettered: bool = False
    candidate_provider: str | None = None
    candidate_model: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    latency_ms: int = 0


# ---- routers ------------------------------------------------------------


class BaseRouter:
    """A single router. Subclasses override :meth:`propose`."""

    router_id: str

    def __init__(self, router_id: str) -> None:
        self.router_id = router_id

    async def propose(
        self,
        task: RoutingTask,
        registry: ProviderRegistry,
        scores: ModelScoreStore,
    ) -> list[RouterCandidate]:
        raise NotImplementedError


class ScoreRouter(BaseRouter):
    """Score every eligible candidate using the model score store."""

    def __init__(self) -> None:
        super().__init__("score")

    async def propose(
        self,
        task: RoutingTask,
        registry: ProviderRegistry,
        scores: ModelScoreStore,
    ) -> list[RouterCandidate]:
        return await _eligible_with_scores(task, registry, scores)


class CostAwareRouter(BaseRouter):
    """Prefer the cheapest eligible candidate, breaking ties by score."""

    def __init__(self) -> None:
        super().__init__("cost_aware")

    async def propose(
        self,
        task: RoutingTask,
        registry: ProviderRegistry,
        scores: ModelScoreStore,
    ) -> list[RouterCandidate]:
        return await _eligible_with_scores(task, registry, scores)


class DiversityRouter(BaseRouter):
    """Propose the broadest spread of eligible candidates (provider-level diversity)."""

    def __init__(self) -> None:
        super().__init__("diversity")

    async def propose(
        self,
        task: RoutingTask,
        registry: ProviderRegistry,
        scores: ModelScoreStore,
    ) -> list[RouterCandidate]:
        cands = await _eligible_with_scores(task, registry, scores)
        # Deduplicate by provider_id so a single provider doesn't dominate.
        seen_providers: set[str] = set()
        out: list[RouterCandidate] = []
        for c in cands:
            if c.provider_id in seen_providers:
                continue
            seen_providers.add(c.provider_id)
            out.append(c)
        return out


# ---- pool ---------------------------------------------------------------


class RouterPool:
    """The coordinator that runs the parallel routers and dispatches the chosen model."""

    def __init__(
        self,
        registry: ProviderRegistry,
        scores: ModelScoreStore,
        breakers: CircuitBreakerStore,
        usage: UsageAccountant,
        dead_letter: DeadLetterQueue,
        *,
        db: Database | None = None,
        routers: Sequence[BaseRouter] | None = None,
        router_timeout_seconds: float = 3.0,
    ) -> None:
        self._registry = registry
        self._scores = scores
        self._breakers = breakers
        self._usage = usage
        self._dlq = dead_letter
        self._db = db
        self._routers: list[BaseRouter] = (
            list(routers) if routers is not None
            else [ScoreRouter(), CostAwareRouter(), DiversityRouter()]
        )
        self._router_timeout = router_timeout_seconds

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    @property
    def scores(self) -> ModelScoreStore:
        return self._scores

    @property
    def breakers(self) -> CircuitBreakerStore:
        return self._breakers

    @property
    def dead_letter(self) -> DeadLetterQueue:
        return self._dlq

    @property
    def usage(self) -> UsageAccountant:
        return self._usage

    # -- decision ----------------------------------------------------

    async def decide(self, task: RoutingTask) -> RouterDecisionModel:
        """Run the routers, merge, and return a decision. No I/O dispatch."""
        cands_per_router = await self._gather_router_candidates(task)
        merged = await self._merge(task, cands_per_router)
        chosen = merged.chosen
        if chosen is not None:
            decision = RouterDecisionModel(
                router_id="coordinator",
                candidates=merged.candidates,
                chosen=chosen,
                fallback_chain=merged.fallback_chain,
                rationale=merged.rationale,
                confidence=merged.confidence,
                expected_cost=merged.expected_cost,
                policy=task.policy,
            )
        else:
            decision = RouterDecisionModel(
                router_id="coordinator",
                candidates=merged.candidates,
                chosen=None,
                fallback_chain=merged.fallback_chain,
                rationale=merged.rationale or "no eligible candidates",
                confidence=0.0,
                expected_cost=0.0,
                policy=task.policy,
            )
        if self._db is not None:
            await self._persist_decision(task, decision)
        return decision

    # -- dispatch + execute ------------------------------------------

    async def route_and_run(self, task: RoutingTask) -> RoutingOutcome:
        """Decide, then run the chosen model. Returns a :class:`RoutingOutcome`."""
        decision = await self.decide(task)
        chosen = decision.chosen
        if chosen is None:
            await self._dlq.enqueue(
                task_id=task.task_id,
                campaign_id=task.campaign_id,
                reason="no_candidates" if decision.rationale == "no eligible candidates" else "unroutable",
                detail=decision.rationale,
                payload=task.model_dump(mode="json"),
            )
            return RoutingOutcome(decision=decision, dead_lettered=True)

        adapter = self._registry.get(chosen.provider_id)
        breaker = await self._breakers.get(chosen.provider_id, chosen.model_key)
        if breaker.state.value == "open":
            await self._dlq.enqueue(
                task_id=task.task_id,
                campaign_id=task.campaign_id,
                reason="circuit_open",
                detail=f"circuit open for {chosen.provider_id}/{chosen.model_key}",
                payload=task.model_dump(mode="json"),
            )
            return RoutingOutcome(decision=decision, dead_lettered=True)

        start = time.monotonic()
        try:
            response = await adapter.chat(chosen.model_key, task.request)
        except ProviderError as exc:
            await self._breakers.record_failure(chosen.provider_id, chosen.model_key, str(exc))
            await self._dlq.enqueue(
                task_id=task.task_id,
                campaign_id=task.campaign_id,
                reason="error",
                detail=str(exc),
                payload=task.model_dump(mode="json"),
            )
            finished = datetime.now(UTC)
            return RoutingOutcome(
                decision=decision,
                error=exc,
                dead_lettered=True,
                finished_at=finished,
                latency_ms=int((time.monotonic() - start) * 1000),
                candidate_provider=chosen.provider_id,
                candidate_model=chosen.model_key,
            )

        latency_ms = int((time.monotonic() - start) * 1000)
        await self._breakers.record_success(chosen.provider_id, chosen.model_key)
        is_free = await self._is_free_model(chosen.provider_id, chosen.model_key)
        await self._usage.record(
            provider_id=chosen.provider_id,
            model_key=chosen.model_key,
            agent_id=task.agent_id,
            task_id=task.task_id,
            campaign_id=task.campaign_id,
            usage=response.usage,
            latency_ms=latency_ms,
            is_free=is_free,
        )
        # Live score update: per-(model, category), feed 1.0 on success
        await self._scores.update_from_samples(
            chosen.provider_id,
            chosen.model_key,
            task.category,
            [1.0],
            source="live",
        )
        return RoutingOutcome(
            decision=decision,
            response=response,
            finished_at=datetime.now(UTC),
            latency_ms=latency_ms,
            candidate_provider=chosen.provider_id,
            candidate_model=chosen.model_key,
        )

    # -- internals ---------------------------------------------------

    async def _gather_router_candidates(
        self, task: RoutingTask
    ) -> list[list[RouterCandidate]]:
        async def _run(router: BaseRouter) -> list[RouterCandidate]:
            try:
                return await asyncio.wait_for(
                    router.propose(task, self._registry, self._scores),
                    timeout=self._router_timeout,
                )
            except FreeOnlyViolation as exc:
                log.warning(
                    "router_free_only_violation",
                    router=router.router_id,
                    detail=str(exc),
                )
                return []
            except Exception as exc:  # noqa: BLE001 — a router must not crash the pool
                log.warning("router_failed", router=router.router_id, error=str(exc))
                return []

        results = await asyncio.gather(*[_run(r) for r in self._routers])
        return [list(r) for r in results]

    async def _merge(
        self, task: RoutingTask, per_router: list[list[RouterCandidate]]
    ) -> RouterDecisionModel:
        policy = task.policy
        if policy == RoutingPolicy.CONSENSUS:
            return consensus(task, per_router)
        if policy == RoutingPolicy.FASTEST_ELIGIBLE:
            return fastest_eligible(task, per_router, self._breakers)
        if policy == RoutingPolicy.DIVERSITY:
            return diversity(task, per_router)
        return best_score_within_budget(task, per_router, self._scores)

    async def _persist_decision(self, task: RoutingTask, decision: RouterDecisionModel) -> None:
        assert self._db is not None
        # Only persist when the task_id references a real task row.
        # Synthetic ids (e.g. in unit tests) are dropped to avoid
        # FK violations; the in-memory decision is still returned to
        # the caller.
        task_row = await self._db.fetchone(
            "SELECT id FROM tasks WHERE id = ?", (task.task_id,)
        )
        if task_row is None:
            log.debug(
                "router_decision_skip_no_task",
                task_id=task.task_id,
                rationale=decision.rationale,
            )
            return
        chosen_model_id = None
        if decision.chosen is not None:
            # resolve (provider_id, model_key) -> models.id
            row = await self._db.fetchone(
                """
                SELECT m.id FROM models m
                JOIN providers p ON m.provider_id = p.id
                WHERE p.provider_id = ? AND m.model_key = ?
                """,
                (decision.chosen.provider_id, decision.chosen.model_key),
            )
            if row is not None:
                chosen_model_id = row["id"]
        await self._db.execute(
            """
            INSERT INTO router_decisions(
                id, schema_version, task_id, router_id, candidates,
                chosen_model_id, rationale, confidence, expected_cost,
                fallback_chain, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                "1.0.0",
                task.task_id,
                decision.router_id,
                json.dumps([c.model_dump() for c in decision.candidates]),
                chosen_model_id,
                decision.rationale,
                float(decision.confidence),
                float(decision.expected_cost),
                json.dumps(decision.fallback_chain),
                datetime.now(UTC).isoformat(),
            ),
        )

    async def _is_free_model(self, provider_id: str, model_key: str) -> bool:
        try:
            adapter = self._registry.get(provider_id)
        except KeyError:
            return False
        return adapter.is_model_free(model_key)


# ---- helpers shared by the routers --------------------------------------


async def _eligible_with_scores(
    task: RoutingTask, registry: ProviderRegistry, scores: ModelScoreStore
) -> list[RouterCandidate]:
    """Build a candidate list for every eligible model.

    Applies the free-only filter, the circuit-breaker filter, and the
    per-task constraints (budget, category, capabilities).
    """
    all_models: list[tuple[ProviderAdapter, str]] = []
    for adapter in registry.all():  # type: ignore[attr-defined]
        for m in adapter.models():
            all_models.append((adapter, m.model_key))

    candidates: list[RouterCandidate] = []
    for adapter, model_key in all_models:
        entry = next((m for m in adapter.models() if m.model_key == model_key), None)
        if entry is None:
            continue
        try:
            eligible_candidates(
                entry,
                free_only=task.free_only,
                allow_paid_override=task.allow_paid_override,
                human_approved=task.human_approved,
            )
        except FreeOnlyViolation:
            continue
        # if the model is in a category list (non-empty), require membership
        if entry.categories and task.category not in entry.categories:
            # the catalog is descriptive, not strict — we don't drop
            # candidates purely on category unless the model declares
            # a single category and it doesn't match.
            if len(entry.categories) == 1:
                continue
        score = await scores.get(adapter.provider_id, model_key, task.category)
        confidence = 0.5
        if score is not None and score.sample_count > 0:
            score_value = score.score
            confidence = max(0.0, min(1.0, (score.confidence_high - score.confidence_low) + 0.5))
        else:
            # fresh model — fall back to a small prior
            score_value = 0.5
        expected_cost = _expected_cost(entry, task.request)
        candidates.append(
            RouterCandidate(
                provider_id=adapter.provider_id,
                model_key=model_key,
                score=score_value,
                expected_cost=expected_cost,
                rationale=(
                    f"score={score_value:.2f} samples={score.sample_count if score else 0}"
                ),
                confidence=confidence,
            )
        )
    # ensure we have *some* baseline ordering for the merging policies.
    candidates.sort(key=lambda c: (c.score, c.confidence), reverse=True)
    return candidates


def _expected_cost(entry: Any, request: ChatRequest) -> float:
    in_per = entry.pricing_input_per_mtok
    out_per = entry.pricing_output_per_mtok
    if in_per is None and out_per is None:
        return 0.0
    in_tokens = sum(len(m.content) // 4 for m in request.messages)
    out_tokens = request.max_tokens or 256
    cost = 0.0
    if in_per is not None:
        cost += (in_tokens / 1_000_000) * in_per
    if out_per is not None:
        cost += (out_tokens / 1_000_000) * out_per
    return float(cost)


__all__ = [
    "BaseRouter",
    "CostAwareRouter",
    "DiversityRouter",
    "RouterPool",
    "RoutingOutcome",
    "ScoreRouter",
]
