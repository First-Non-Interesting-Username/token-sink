# Contributor Guide

For humans and AI agents contributing to token-sink. Working rules (PR
process, review etiquette, agent session tagging) live in
[AGENTS.md](../AGENTS.md) — read it first; this guide covers structure,
conventions, and how-to recipes.

## Repo layout

See [repo-layout.md](repo-layout.md) for the authoritative layout notes.
Summary: one top-level Python package per subsystem, matching PLAN §4 —
`agents`, `api`, `cli`, `findings`, `observability`, `orchestrator`, `policy`,
`providers`, `routers`, `schemas`, `search`, `storage`, `ui` — plus plain
dirs for `tests/`, `docs/`, `examples/`, `migrations/`, `config/`,
`scripts/`, and `evaluation/fixtures/`.

The boundaries are deliberate: providers, agent roles, storage engines, and
UI components must remain replaceable independently. Do not import across a
subsystem's public surface casually; if you need a new cross-package
dependency, note it in the PR and update docs.

## Core conventions

- **PLAN.md is the source of truth** for behavior; each package's
  `__init__.py` docstring states its responsibility and PLAN section. Keep
  those in sync when responsibilities change.
- **Comment the WHY**, not just the what, on non-trivial logic (AGENTS.md).
- **Schemas are versioned** (PLAN §11): campaign, scope policy, agent, task,
  provider, model, router decision, search result, extracted source,
  evidence item, finding, review, PoC, final report, usage event, audit
  event. When you change a schema, bump its version and add a migration under
  `migrations/`; imports of older bundles must keep working (issue #57's
  versioned bundle format depends on this).
- **No secrets, ever.** Placeholder/fake values (`sk-example-...`,
  `changeme`) are fine and encouraged in docs/examples; real credential
  values never enter the repo. CI greps for secret-shaped strings.
- **No target data in examples.** Fixtures must be non-sensitive and
  self-contained so CI can run them.

## How to add a provider adapter (PLAN §8)

1. Implement the common adapter interface under `providers/adapters/`:
   provider identity/config, auth status *without displaying secrets*, model
   discovery/catalog, capabilities + context limits, pricing/free status,
   rate limits, streaming, tool-calling, structured output, health check,
   usage extraction, error normalization, cancellation/timeout.
2. Register it in the registry (`providers/registry/`) and add catalog
   entries to `providers/model_catalog/`.
3. If it is a partly-free gateway: implement strict free-model filtering.
   Never assume a gateway model is free because the gateway is partly free;
   unknown free-status ⇒ marked unknown and excluded from free-only routing.
4. Tests: unit tests for free-model filtering (§19.1), adapter integration
   tests against mocks (`tests/integration/`, `@pytest.mark.integration`).
5. Document the provider in `docs/` if it introduces conventions or quirks.

## Schema versioning & migrations

- Additive changes bump the minor version; breaking changes bump major and
  require an idempotent migration script in `migrations/` plus a round-trip
  test (write with new version, read with old reader path or migrate).
- Storage stays behind the abstraction in `storage/` so agents never depend
  on the backend engine.

## Test requirements

Layout and commands: [testing.md](testing.md). In short:

- `tests/unit/` — state transitions, leases, scope checks, redaction,
  accounting, URL/artifact validation.
- `tests/integration/` — cross-subsystem against mocks; mark every test
  `@pytest.mark.integration`.
- `tests/safety/` — guardrails (SSRF, scope bypass, redaction, prompt
  injection); mark `@pytest.mark.safety`; never skipped in CI.
- New enforcement rule in `policy/` ⇒ new safety test attempting its bypass,
  same PR.
- Per-test timeout is 60s; CI runs lint + tests on every PR and blocks merge
  on failure.

## Documentation rules

- Docs live under `docs/`, split by topic — no monolith files; split around
  ~1000 lines (AGENTS.md). Link new docs from AGENTS.md and from related
  docs' "Related docs" sections.
- Anything a future contributor would have to reverse-engineer gets written
  down: layout rationale, non-obvious conventions, decisions + reasoning.
- Update docs in the same PR as the change they describe; stale guidance
  costs more than missing guidance.

## PR checklist (summary)

1. Fresh clone, branch off `main`, never commit to `main` directly.
2. CI green; all review conversations answered.
3. Branch deleted after squash-merge (AGENTS.md covers timing/review rules).

## Related docs

- [Architecture overview](architecture.md)
- [Operator guide](operator-guide.md)
- [Safety & scope authoring](safety-and-scope.md)
