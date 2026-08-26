# Model Scores & Benchmarks

How dynamic model scores are computed, kept honest, and fed to routers
(PLAN §8.3–§8.4; implementation in `evaluation/scores.py`, issue #76).
Benchmark suite definition lives in `evaluation/benchmarks.py`
(see [docs/benchmarks.md](benchmarks.md)).

## Why shrinkage

PLAN §8.3 is explicit: *"Do not let a small number of successful calls
produce an overconfident score."* The engine therefore treats each
(provider, model, category) success/failure history as a Beta-Binomial
posterior:

- A **prior** `Beta(alpha0, beta0)` seeded from §8.4 benchmark results via
  `seed_prior_from_benchmarks()`. The benchmark pass rate sets the prior
  mean; the prior's *strength* (default 4 pseudo-observations) sets how much
  live evidence is needed to override it. The benchmark version is recorded
  with the prior so it stays auditable.
- Each live observation adds decay-weighted mass to `alpha` (success) or
  `beta` (failure).
- The **point estimate** is the posterior mean `alpha / (alpha + beta)`.
  With a neutral prior, a single success scores 2/3 — never ~100%.

## Uncertainty

Every score carries:

- a **Wilson interval** (95%) on the decay-weighted success rate —
  closed-form, no scipy dependency;
- an **uncertainty** half-width derived from it, exposed to routers and the
  UI ("score confidence" per §8.3).

## Recency weighting

Exponential decay with a configurable half-life (`ScoreStore(half_life_s=…)`,
default 3 days; wire to §16 config). Decay is applied at *record* time using
the observation's own timestamp as anchor, so recomputation from stored
observations is deterministic regardless of when replay runs.

## Multi-signal combination

`combine_signals()` produces the final category score with the documented
weighted formula:

```text
score = 0.50 * success_posterior_mean
      + 0.20 * latency_norm           (normalized latency quality)
      + 0.15 * (1 - error_rate)
      + 0.10 * reviewer_agreement
      + 0.05 * completion_quality
```

Signals with no data have their weight redistributed proportionally over the
present ones — absence of reviewer data neither rewards nor penalizes.

## Cold start & auditability

Benchmarks seed priors only (never override live measurements, §8.3/§8.4).
Raw observations are retained verbatim in the store
(`ScoreStore.observations()`), and `ScoreStore.recompute()` rebuilds every
entry from prior + raw observations — the deterministic-replay hook used by
regression tests and by router decision-log audits (#55).

## Router integration

Routers rank candidates with `rank_candidates_ucb(...)`:

```text
ranking_value = score + exploration * uncertainty   (capped at 1.0)
```

Wide intervals make a candidate look better under exploration (> 0),
inviting UCB-style exploration of unproven models; `exploration=0` reduces
to greedy point-estimate ranking. Unscored candidates sort last.
