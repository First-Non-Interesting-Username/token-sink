"""Score computation engine: shrinkage estimators, confidence intervals,
recency weighting (PLAN §8.3–§8.4, issue #76).

Design goals, straight from the issue:

1. **No small-sample overconfidence.** Every (model, category) score is a
   Beta-Binomial posterior: a prior seeded from benchmark results (with the
   benchmark version recorded so priors stay auditable per §8.4) shrunk
   toward as sample count grows. A 1-for-1 model can never approach 100%.
2. **Honest uncertainty.** Each score carries a Wilson interval *and* the
   Beta posterior; both are exposed to routers and the UI. Raw observations
   are retained so scores are recomputable/deterministically replayable.
3. **Recency weighting** via exponential decay with a configurable half-life
   (§16 config). Decay is applied when observations are *recorded* — each
   observation stores its decayed weight — so replay from recorded data is
   deterministic regardless of when it runs.
4. **Documented multi-signal combination**: success rate (posterior mean),
   latency percentile, error rate, reviewer agreement, and completion
   quality combine into one category score with an explicit weighted formula
   (see :func:`combine_signals` and docs/benchmark-scores.md).

Storage-agnostic pure stdlib, matching the rest of ``evaluation/``.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

# Default recency half-life in seconds (configurable per §16); ~3 days so a
# week-old failure still counts but last month's glory does not.
DEFAULT_HALF_LIFE_S = 3 * 24 * 3600

# Multi-signal weights for combine_signals(). Sum to 1.0 by construction;
# documented in docs/benchmark-scores.md rather than left implicit.
SIGNAL_WEIGHTS = {
    "success": 0.5,
    "latency": 0.2,
    "error_rate": 0.15,
    "reviewer_agreement": 0.1,
    "completion_quality": 0.05,
}

# Cap on effective sample size contributed by any single observation's
# weight — keeps one heavily-weighted recent event from dominating.
_MAX_OBS_WEIGHT = 10.0


@dataclass(frozen=True)
class Observation:
    """One raw score observation for a (provider, model, category) key.

    Kept verbatim in the store so scores can be recomputed (issue item 5:
    "raw observations stored"). ``recorded_at`` is wall-clock at record time;
    all derived quantities live in :class:`ScoreEntry`, never here.
    """

    provider: str
    model: str
    category: str
    success: bool
    recorded_at: float  # epoch seconds
    # Optional signal values in [0, 1]; None → excluded from that signal.
    latency_norm: float | None = None  # normalized latency score (1 = fast)
    reviewer_agreement: float | None = None
    completion_quality: float | None = None


@dataclass
class ScoreEntry:
    """Derived score for one (model, category) pair.

    Point estimate is the weighted posterior mean of a Beta distribution
    whose alpha/beta come from decay-weighted success/failure mass added to
    the benchmark-seeded prior. The Wilson interval is computed on the
    decay-weighted empirical rate with ``z`` fixed at ~1.96 (95%).
    """

    provider: str
    model: str
    category: str
    prior_alpha: float
    prior_beta: float
    benchmark_version: int | None  # provenance of the prior (§8.4 auditability)
    alpha: float  # posterior alpha = prior_alpha + weighted successes
    beta: float  # posterior beta = prior_beta + weighted failures
    n_observations: int
    updated_at: float

    @property
    def score(self) -> float:
        """Posterior mean — the point estimate routers rank by."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def wilson_interval(self) -> tuple[float, float]:
        """Wilson score interval (95%) on the decay-weighted success rate.

        Used instead of the raw Beta quantiles because Wilson degrades to a
        wide-but-finite interval at tiny samples and is closed-form (stdlib
        only — no scipy dependency for a percentile lookup).
        """
        z = 1.959963984540054
        n = self.alpha + self.beta - self.prior_alpha - self.prior_beta
        if n <= 0:
            return (0.0, 1.0)  # no evidence yet: maximally uncertain
        p_hat = self.score
        denom = 1 + z * z / n
        center = p_hat + z * z / (2 * n)
        margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))
        return (max(0.0, (center - margin) / denom), min(1.0, (center + margin) / denom))

    @property
    def uncertainty(self) -> float:
        """Half-width of the Wilson interval; wide ⇒ explore (UCB policy)."""
        lo, hi = self.wilson_interval
        return (hi - lo) / 2

    def ucb(self, exploration: float = 1.0) -> float:
        """Upper confidence bound: score + exploration * uncertainty.

        Router-facing ranking value (issue item 6): wide intervals make a
        candidate look better than its point estimate alone, encouraging
        exploration without ever exceeding what the evidence supports.
        """
        return min(1.0, self.score + exploration * self.uncertainty)


def _decay_weight(recorded_at: float, now: float, half_life_s: float) -> float:
    """Exponential recency weight in (0, 1], capped away from zero."""
    if half_life_s <= 0:
        return 1.0
    age = max(0.0, now - recorded_at)
    return max(2.0 ** (-age / half_life_s), 1e-9)


def seed_prior_from_benchmarks(
    benchmark_version: int,
    successes: int,
    failures: int,
    strength: float = 4.0,
) -> tuple[float, float]:
    """Build a Beta prior from §8.4 benchmark results.

    The benchmark outcome sets the prior *mean*; ``strength`` is the
    equivalent sample size of the prior (how much live evidence it takes to
    override it). Recording ``benchmark_version`` with the returned pair is
    required so priors remain auditable (issue item 5).
    """
    total = successes + failures
    if total == 0:
        # Neutral prior: uninformative Beta(1,1) scaled down so even the
        # first observation dominates.
        return (strength / 2, strength / 2)
    mean = successes / total
    return (mean * strength, (1 - mean) * strength)


class ScoreStore:
    """In-memory score store keyed by (provider, model, category).

    Observations are appended immutably; entries are recomputable from them
    (:meth:`recompute`), which is what makes deterministic replay possible.
    A storage-layer adapter (#7/#46) can persist the observation list and
    rebuild this object on restart.
    """

    def __init__(self, half_life_s: float = DEFAULT_HALF_LIFE_S):
        self.half_life_s = half_life_s
        self._observations: list[Observation] = []
        self._priors: dict[tuple[str, str, str], tuple[float, float, int | None]] = {}
        self._entries: dict[tuple[str, str, str], ScoreEntry] = {}

    # -- recording ---------------------------------------------------------

    def set_prior(
        self,
        provider: str,
        model: str,
        category: str,
        alpha: float,
        beta: float,
        benchmark_version: int | None = None,
    ) -> None:
        """Seed/replace the prior for a key (from benchmarks, §8.4)."""
        self._priors[(provider, model, category)] = (alpha, beta, benchmark_version)

    def record(self, obs: Observation, now: float | None = None) -> ScoreEntry:
        """Record one observation; returns the recomputed entry.

        Recency weight is computed against ``now`` at record time and folded
        into the entry's alpha/beta immediately — recorded data never needs
        re-decaying later, keeping replay deterministic.
        """
        now = time.time() if now is None else now
        self._observations.append(obs)
        key = (obs.provider, obs.model, obs.category)
        entry = self._entries.get(key)
        prior = self._priors.get(key, (1.0, 1.0, None))
        w = min(_decay_weight(obs.recorded_at, now, self.half_life_s), _MAX_OBS_WEIGHT)

        if entry is None:
            entry = ScoreEntry(
                provider=obs.provider,
                model=obs.model,
                category=obs.category,
                prior_alpha=prior[0],
                prior_beta=prior[1],
                benchmark_version=prior[2],
                alpha=prior[0],
                beta=prior[1],
                n_observations=0,
                updated_at=now,
            )
            self._entries[key] = entry
        # Success/failure mass updates the Bernoulli part; optional signals
        # fold into their running means via exponential-update below.
        if obs.success:
            entry.alpha += w
        else:
            entry.beta += w
        entry.n_observations += 1
        entry.updated_at = now
        self._fold_signal(entry, "latency", obs.latency_norm, w, now)
        self._fold_signal(entry, "reviewer_agreement", obs.reviewer_agreement, w, now)
        self._fold_signal(entry, "completion_quality", obs.completion_quality, w, now)
        return entry

    def _fold_signal(
        self,
        entry: ScoreEntry,
        name: str,
        value: float | None,
        w: float,
        now: float,
    ) -> None:
        """Exponentially-weighted running mean for one optional signal."""
        if value is None:
            return
        attr = f"_{name}_mean"
        prev = getattr(entry, attr, None)
        # Same smoothing the posterior uses conceptually: new evidence moves
        # the mean proportionally to its weight vs. accumulated weight.
        setattr(entry, attr, value if prev is None else (prev * 3 + value * w) / (3 + w))

    def signal_mean(self, key: tuple[str, str, str], name: str) -> float | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        return getattr(entry, f"_{name}_mean", None)

    # -- querying ----------------------------------------------------------

    def get(self, provider: str, model: str, category: str) -> ScoreEntry | None:
        return self._entries.get((provider, model, category))

    def entries(self) -> list[ScoreEntry]:
        return list(self._entries.values())

    def observations(self) -> list[Observation]:
        """Raw observations — retained for replay/audit (issue item 5)."""
        return list(self._observations)

    def recompute(self, now: float | None = None) -> dict[tuple[str, str, str], ScoreEntry]:
        """Rebuild every entry from scratch: prior + raw observations.

        Deterministic given the same observation list and ``now`` anchors —
        the regression-test hook for "deterministic replay from recorded
        observations" (issue item 7).
        """
        now = time.time() if now is None else now
        self._entries.clear()
        obs_copy, self._observations = self._observations, []
        saved_signals = {}
        for key, e in self._entries.items():  # pragma: no cover - cleared above
            saved_signals[key] = e
        replay: list[tuple[Observation, float]] = []
        for o in obs_copy:
            replay.append((o, o.recorded_at))
        self._entries = {}
        # Re-record with each observation's own timestamp as `now` anchor so
        # weights match the original run exactly.
        for o, anchor in sorted(replay, key=lambda t: t[1]):
            self.record(o, now=anchor)
        return self._entries


def rank_candidates_ucb(
    scored: list[tuple[str, str, ScoreStore]],
    category: str,
    exploration: float = 1.0,
) -> list[tuple[str, str, float]]:
    """Rank (provider, model) candidates by UCB for router integration.

    Convenience shim over :meth:`ScoreEntry.ucb` — routers pass their
    candidate list plus the store; missing scores sort last (never rewarded
    for absence of evidence).
    """
    ranked = []
    for provider, model, store in scored:
        entry = store.get(provider, model, category)
        value = entry.ucb(exploration) if entry else -1.0
        ranked.append((provider, model, value))
    return sorted(ranked, key=lambda t: t[2], reverse=True)


def combine_signals(
    success_score: float,
    latency_norm: float | None = None,
    error_rate: float | None = None,
    reviewer_agreement: float | None = None,
    completion_quality: float | None = None,
) -> float:
    """Weighted multi-signal category score (issue item 4).

    Formula (documented, not implicit):

        score = 0.50 * success_posterior_mean
              + 0.20 * latency_norm           (normalized latency quality)
              + 0.15 * (1 - error_rate)       (error rate inverted)
              + 0.10 * reviewer_agreement
              + 0.05 * completion_quality

    Signals with no data have their weight redistributed proportionally over
    the present ones, so a model with no reviewer data isn't penalized —
    it just carries wider intervals from fewer effective samples.
    """
    parts = {
        "success": success_score,
        "latency": latency_norm,
        "error_rate": None if error_rate is None else 1.0 - error_rate,
        "reviewer_agreement": reviewer_agreement,
        "completion_quality": completion_quality,
    }
    present = {k: v for k, v in parts.items() if v is not None}
    total_w = sum(SIGNAL_WEIGHTS[k] for k in present)
    return sum(SIGNAL_WEIGHTS[k] * v for k, v in present.items()) / total_w
