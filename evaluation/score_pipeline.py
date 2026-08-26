"""Score update pipeline: benchmark + observed outcomes → routing scores
(PLAN §8.3–§8.4, issue #235).

Wires results into live routing decisions over time:

- **Versioned score records** per model/category with an explicit
  ``source`` (``benchmark:<version>`` vs ``observed``) — :class:`ScoreUpdate`.
- **Benchmark ingestion**: a finished ``BenchmarkRun`` folds into the store
  as a *prior* update tagged with the suite version (:meth:`ScorePipeline.apply_benchmark_run`).
- **Observed outcomes**: router task success/failure and reviewer agreement
  stream in as observations (:meth:`ScorePipeline.record_outcome`).
- **Router consumption**: :meth:`ScorePipeline.rank` wraps
  ``rank_candidates_ucb`` with configurable exploration vs exploitation.
- **Audit**: every change is appended to an immutable, exportable audit log;
  each entry names its inputs so any score value is traceable.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from evaluation.scores import Observation, ScoreStore, rank_candidates_ucb

__all__ = ["ScorePipeline", "ScoreUpdate", "benchmark_prior"]


@dataclass(frozen=True)
class ScoreUpdate:
    """One auditable score-affecting event."""

    update_id: str
    ts: float
    source: str  # "benchmark" | "observed"
    provider: str
    model: str
    category: str
    # Inputs that produced the change — full traceability per issue item 4.
    inputs: dict[str, Any] = field(default_factory=dict)


def benchmark_prior(
    pass_count: int,
    total: int,
    strength: float = 8.0,
) -> tuple[float, float]:
    """Beta prior parameters from a benchmark outcome.

    Maps pass rate onto a Beta distribution with pseudo-count ``strength``,
    so a fresh benchmark seeds routing before any observed traffic exists:
    ``alpha = strength * pass_rate + 1``, ``beta = strength * (1 - pass_rate) + 1``.
    """
    if total <= 0:
        return (1.0, 1.0)
    pass_rate = max(0.0, min(1.0, pass_count / total))
    alpha = 1.0 + strength * pass_rate
    beta = 1.0 + strength * (1.0 - pass_rate)
    return (alpha, beta)


class ScorePipeline:
    """Facade binding the score store to benchmarks, outcomes and routers."""

    def __init__(self, store: ScoreStore | None = None) -> None:
        self.store = store or ScoreStore()
        self._audit: list[ScoreUpdate] = []

    # -- ingestion ----------------------------------------------------------

    def apply_benchmark_run(
        self,
        provider: str,
        model: str,
        category: str,
        passed_items: list[str],
        failed_items: list[str],
        suite_version: int,
        run_id: str = "",
        now: float | None = None,
    ) -> ScoreUpdate:
        """Fold one completed benchmark run in as the key's prior.

        The prior is *replaced* (benchmarks are authoritative re-baselines);
        observed data keeps accumulating on top of it.
        """
        now = time.time() if now is None else now
        total = len(passed_items) + len(failed_items)
        if total == 0:
            raise ValueError("benchmark run has no items")
        alpha, beta_ = benchmark_prior(len(passed_items), total)
        self.store.set_prior(
            provider, model, category, alpha, beta_, benchmark_version=suite_version
        )
        # Materialize the entry so routers can read the seeded prior before
        # any live traffic exists (set_prior alone only stores parameters).
        if self.store.get(provider, model, category) is None:
            entry = self.store.record(
                Observation(
                    provider=provider,
                    model=model,
                    category=category,
                    success=True,
                    recorded_at=now,
                ),
                now=now,
            )
            # The seed observation above added mass; restore exact prior
            # values so the benchmark remains the sole authority at this point.
            entry.alpha = alpha
            entry.beta = beta_
            entry.prior_alpha = alpha
            entry.prior_beta = beta_
            entry.benchmark_version = suite_version
            entry.n_observations = 0
        update = ScoreUpdate(
            update_id=f"scu_{uuid.uuid4().hex[:12]}",
            ts=now,
            source="benchmark",
            provider=provider,
            model=model,
            category=category,
            inputs={
                "run_id": run_id,
                "suite_version": suite_version,
                "passed": sorted(passed_items),
                "failed": sorted(failed_items),
                "alpha": alpha,
                "beta": beta_,
            },
        )
        self._audit.append(update)
        return update

    def record_outcome(
        self,
        provider: str,
        model: str,
        category: str,
        success: bool,
        reviewer_agreement: float | None = None,
        latency_norm: float | None = None,
        now: float | None = None,
    ) -> Any:
        """Record one live routing outcome; returns the updated entry."""
        now = time.time() if now is None else now
        entry = self.store.record(
            Observation(
                provider=provider,
                model=model,
                category=category,
                success=success,
                recorded_at=now,
                reviewer_agreement=reviewer_agreement,
                latency_norm=latency_norm,
            ),
            now=now,
        )
        self._audit.append(
            ScoreUpdate(
                update_id=f"scu_{uuid.uuid4().hex[:12]}",
                ts=now,
                source="observed",
                provider=provider,
                model=model,
                category=category,
                inputs={"success": success},
            )
        )
        return entry

    # -- router consumption ---------------------------------------------------

    def rank(
        self,
        candidates: list[tuple[str, str]],
        category: str,
        exploration: float = 1.0,
    ) -> list[tuple[str, str, float]]:
        """Rank candidates for selection.

        ``exploration`` > 1 favors uncertain models (UCB); 0 is pure exploit
        of current best mean. Missing scores sort last.
        """
        scored = [(p, m, self.store) for p, m in candidates]
        return rank_candidates_ucb(scored, category, exploration=exploration)

    def best(self, candidates: list[tuple[str, str]], category: str) -> tuple[str, str] | None:
        ranked = self.rank(candidates, category, exploration=0.0)
        return (ranked[0][0], ranked[0][1]) if ranked else None

    # -- audit ----------------------------------------------------------------

    def audit_log(self) -> list[ScoreUpdate]:
        return list(self._audit)

    def trace(self, provider: str, model: str, category: str) -> list[ScoreUpdate]:
        """All updates affecting one key, oldest first."""
        return [
            u
            for u in self._audit
            if (u.provider, u.model, u.category) == (provider, model, category)
        ]

    def export_audit(self) -> list[dict[str, Any]]:
        from dataclasses import asdict

        return [asdict(u) for u in self._audit]
