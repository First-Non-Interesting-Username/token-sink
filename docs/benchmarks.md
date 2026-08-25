# Benchmarks

The benchmark subsystem (PLAN §8.4, issue #86) seeds the model score system
(#17 / §8.3) with initial priors. Benchmarks inform initial routing only —
they never override live performance measurements.

## Components

| Path | Purpose |
|---|---|
| `evaluation/benchmarks.py` | Versioned suite (`SUITE_VERSION`): non-sensitive tasks per §8.3 category, each = prompt + expected schema + automated checks |
| `evaluation/runner.py` | `BenchmarkRun`: executes the suite against a provider/model pair via a pluggable completion callable; records latency, token usage, check results, pass/fail, quality score |
| `evaluation/benchmark_cli.py` | `system model benchmark` CLI (§17) |
| `tests/unit/test_benchmark_runner.py` | Mock-provider tests |

## Semantics

- **Idempotent & resumable.** Each item result is keyed by
  `(run_id, item_id)`; `resume(prior_results)` reloads state from an
  interrupted execution and `execute()` skips completed items, so a crashed
  run continues without double-counting.
- **Free-only by default.** Under free-only mode a model is refused unless
  its catalog entry confirms `free_status == "free"` — paid AND unknown are
  both excluded (#66, §8.2: unknown ⇒ excluded until confirmed).
- **Malformed output fails.** Tasks with an expected schema gate through
  `schemas/validate.classify_result` (§18); truncated or invalid output is
  scored as a failure, never coerced into a pass.
- **Adapter errors fail the item**, not the run.
- **Quality score** = fraction of passed gates (schema gate + automated
  checks); `passed` requires score 1.0.

## CLI

```sh
system model benchmark --model <id> --provider <id> \
  [--category reasoning] [--dry-run] [--concurrency N] [--allow-paid]
```

`--dry-run` lists suite items without calling any model. Exit code is 0 only
when all items pass. `--allow-paid` opts out of the free-only gate explicitly;
the default refuses paid/unknown-status models.

Real provider adapters wire in via
`evaluation.benchmark_cli.make_completion_fn` (placeholder until #14 lands).

## Extending the suite

Add a `BenchTask` to `SUITE`. Bump `SUITE_VERSION` when task content or
checks change incompatibly — recorded results carry the version so priors
from different suites stay distinguishable. Keep tasks non-sensitive:
no live targets, no operational data.
