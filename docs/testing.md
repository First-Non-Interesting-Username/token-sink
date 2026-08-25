# Testing & CI

Layout follows [PLAN.md §19](../PLAN.md):

| Path | Purpose |
|---|---|
| `tests/unit/` | Unit tests (state machines, leases, scope checks, redaction, …) |
| `tests/integration/` | Cross-subsystem tests against mocks (marked `integration`) |
| `tests/safety/` | Security guardrail tests (marked `safety`; never skipped in CI) |
| `evaluation/fixtures/` | Evaluation fixtures (§19.4) |

Load (§19.5) and acceptance (§19.6) suites land later; add them as new top-level
test dirs when they do.

## Run locally

```sh
uv sync --group dev   # or: pip install pytest pytest-timeout ruff
uv run pytest         # everything
uv run pytest -m safety          # only safety guardrails
uv run pytest -m "not integration"
```

## Conventions

- Every test in `tests/integration/` gets `@pytest.mark.integration`;
  every test in `tests/safety/` gets `@pytest.mark.safety`.
- CI (`​.github/workflows/ci.yml`) runs lint + tests on every PR to `main`
  and blocks merge on failure, per AGENTS.md. The safety marker runs as its
  own step so it can't be accidentally deselected by later `-m` filters.
- Per-test timeout is 60s — placeholder or hung tests fail fast instead of
  stalling the pipeline.
